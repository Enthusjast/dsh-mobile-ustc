package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

var ErrTicketInvalid = errors.New("store: realtime ticket is invalid")

type RealtimeTicket struct {
	Token        string     `json:"ticket"`
	RuntimeID    string     `json:"runtime_id"`
	GrantVersion int64      `json:"grant_version"`
	Scope        GrantScope `json:"scope"`
	ExpiresAt    time.Time  `json:"expires_at"`
}

type TicketRedemption struct {
	UserID             string     `json:"user_id"`
	DeviceID           string     `json:"device_id"`
	DeviceKeyVersion   int64      `json:"-"`
	ProofKeyThumbprint string     `json:"-"`
	ProofPublicJWK     []byte     `json:"-"`
	RuntimeID          string     `json:"runtime_id"`
	GrantVersion       int64      `json:"grant_version"`
	Scope              GrantScope `json:"scope"`
	ExpiresAt          time.Time  `json:"expires_at"`
	ConsumedAt         time.Time  `json:"consumed_at"`
}

func (postgres *Postgres) IssueRealtimeTicket(ctx context.Context, identity UserIdentity, deviceID, runtimeID string, requestedScope GrantScope) (RealtimeTicket, error) {
	transaction, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return RealtimeTicket{}, ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	userID, err := postgres.userID(ctx, transaction, identity.Issuer, identity.Subject)
	if err != nil {
		return RealtimeTicket{}, err
	}
	var registeredDevice string
	var deviceKeyVersion int64
	var proofKeyThumbprint string
	err = transaction.QueryRowContext(ctx, `
		select id::text, key_version, proof_key_thumbprint from devices
		where id = $1 and user_id = $2 and revoked_at is null
		for share`, deviceID, userID).Scan(&registeredDevice, &deviceKeyVersion, &proofKeyThumbprint)
	if errors.Is(err, sql.ErrNoRows) {
		return RealtimeTicket{}, ErrDeviceNotFound
	}
	if err != nil {
		return RealtimeTicket{}, ErrDatabaseUnavailable
	}
	var orgID string
	err = transaction.QueryRowContext(ctx, `
		select h.org_id::text from runtimes r
		join installations i on i.id = r.installation_id and i.revoked_at is null
		join hosts h on h.id = i.host_id and h.state = 'active'
		where r.id = $1 and r.revoked_at is null
		for share of r, i, h`, runtimeID).Scan(&orgID)
	if errors.Is(err, sql.ErrNoRows) {
		return RealtimeTicket{}, ErrAccessDenied
	}
	if err != nil {
		return RealtimeTicket{}, ErrDatabaseUnavailable
	}
	var membershipRole string
	err = transaction.QueryRowContext(ctx, `
		select role from org_memberships where org_id = $1 and user_id = $2 for share`, orgID, userID).Scan(&membershipRole)
	if errors.Is(err, sql.ErrNoRows) {
		return RealtimeTicket{}, ErrAccessDenied
	}
	if err != nil {
		return RealtimeTicket{}, ErrDatabaseUnavailable
	}
	var role string
	var grantScopeJSON []byte
	var grantVersion int64
	err = transaction.QueryRowContext(ctx, `
		select role, scope, grant_version from runtime_grants
		where runtime_id = $1 and user_id = $2 and revoked_at is null
		  and (expires_at is null or expires_at > now())
		for share`, runtimeID, userID).Scan(&role, &grantScopeJSON, &grantVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return RealtimeTicket{}, ErrAccessDenied
	}
	if err != nil {
		return RealtimeTicket{}, ErrDatabaseUnavailable
	}
	scope, err := NormalizeTicketScope(role, requestedScope)
	if err != nil {
		return RealtimeTicket{}, err
	}
	var grantScope GrantScope
	if err := json.Unmarshal(grantScopeJSON, &grantScope); err != nil {
		return RealtimeTicket{}, ErrDatabaseUnavailable
	}
	if !grantScopeSubset(scope, grantScope) {
		return RealtimeTicket{}, ErrAccessDenied
	}
	if err := validateGrantResources(ctx, transaction, runtimeID, scope); err != nil {
		return RealtimeTicket{}, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return RealtimeTicket{}, ErrDatabaseUnavailable
	}
	token := base64.RawURLEncoding.EncodeToString(secret)
	for index := range secret {
		secret[index] = 0
	}
	digest := sha256.Sum256([]byte(token))
	scopeJSON, err := json.Marshal(scope)
	if err != nil {
		return RealtimeTicket{}, ErrGrantInvalid
	}
	var expiresAt time.Time
	if err := transaction.QueryRowContext(ctx, `
		insert into realtime_tickets (token_sha256, user_id, device_id, device_key_version, proof_key_thumbprint, runtime_id, grant_version, scope, expires_at)
		values ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, clock_timestamp() + interval '30 seconds')
		returning expires_at`, digest[:], userID, deviceID, deviceKeyVersion, proofKeyThumbprint, runtimeID, grantVersion, string(scopeJSON)).Scan(&expiresAt); err != nil {
		return RealtimeTicket{}, ErrDatabaseUnavailable
	}
	metadata, _ := json.Marshal(map[string]any{"device_id": deviceID, "runtime_id": runtimeID, "grant_version": grantVersion, "expires_at": expiresAt})
	if _, err := transaction.ExecContext(ctx, `
		insert into audit_log (org_id, actor_type, actor_id, device_id, runtime_id, action, result, metadata)
		values ($1, 'device', $2::uuid::text, $2, $3, 'realtime.ticket.issue', 'success', $4::jsonb)`, orgID, deviceID, runtimeID, string(metadata)); err != nil {
		return RealtimeTicket{}, ErrDatabaseUnavailable
	}
	if err := transaction.Commit(); err != nil {
		return RealtimeTicket{}, ErrDatabaseUnavailable
	}
	return RealtimeTicket{Token: token, RuntimeID: runtimeID, GrantVersion: grantVersion, Scope: scope, ExpiresAt: expiresAt}, nil
}

func realtimeTicketDigest(token string) ([]byte, error) {
	if len(token) != 43 {
		return nil, ErrTicketInvalid
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != token {
		return nil, ErrTicketInvalid
	}
	for index := range decoded {
		decoded[index] = 0
	}
	digest := sha256.Sum256([]byte(token))
	return digest[:], nil
}

// PrepareRealtimeTicket validates a ticket and returns its registered device
// key without consuming it. The Relay verifies the fresh key proof first, then
// calls ConsumeRealtimeTicket to recheck current access and claim the ticket.
func (postgres *Postgres) PrepareRealtimeTicket(ctx context.Context, token string) (TicketRedemption, error) {
	digest, err := realtimeTicketDigest(token)
	if err != nil {
		return TicketRedemption{}, err
	}
	transaction, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return TicketRedemption{}, ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	redemption, err := loadRealtimeTicket(ctx, transaction, digest, false)
	if err != nil {
		return TicketRedemption{}, err
	}
	if err := transaction.Commit(); err != nil {
		return TicketRedemption{}, ErrDatabaseUnavailable
	}
	return redemption, nil
}

// ConsumeRealtimeTicket atomically claims a ticket after the Relay has verified
// the challenge proof. The active device key and grant are rechecked here.
func (postgres *Postgres) ConsumeRealtimeTicket(ctx context.Context, token string) (TicketRedemption, error) {
	digest, err := realtimeTicketDigest(token)
	if err != nil {
		return TicketRedemption{}, err
	}
	transaction, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return TicketRedemption{}, ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	redemption, err := loadRealtimeTicket(ctx, transaction, digest, true)
	if err != nil {
		return TicketRedemption{}, err
	}
	err = transaction.QueryRowContext(ctx, `
		update realtime_tickets set consumed_at = clock_timestamp()
		where token_sha256 = $1 and consumed_at is null and expires_at > clock_timestamp()
		returning consumed_at`, digest).Scan(&redemption.ConsumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return TicketRedemption{}, ErrTicketInvalid
	}
	if err != nil {
		return TicketRedemption{}, ErrDatabaseUnavailable
	}
	metadata, _ := json.Marshal(map[string]any{"runtime_id": redemption.RuntimeID, "grant_version": redemption.GrantVersion})
	if _, err := transaction.ExecContext(ctx, `
		insert into audit_log (actor_type, actor_id, device_id, runtime_id, action, result, metadata)
		values ('device', $1::uuid::text, $1, $2, 'realtime.ticket.consume', 'success', $3::jsonb)`, redemption.DeviceID, redemption.RuntimeID, string(metadata)); err != nil {
		return TicketRedemption{}, ErrDatabaseUnavailable
	}
	if err := transaction.Commit(); err != nil {
		return TicketRedemption{}, ErrDatabaseUnavailable
	}
	return redemption, nil
}

// ValidateRealtimeLease rechecks the device key and exact grant version for an
// established socket before sending a command receipt or another scoped frame.
func (postgres *Postgres) ValidateRealtimeLease(ctx context.Context, ticket TicketRedemption) error {
	transaction, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	var currentScopeJSON []byte
	err = transaction.QueryRowContext(ctx, `
		select g.scope from users u
		join devices d on d.user_id = u.id and d.id = $2 and d.revoked_at is null
		join org_memberships m on m.user_id = u.id
		join hosts h on h.org_id = m.org_id and h.state = 'active'
		join installations i on i.host_id = h.id and i.revoked_at is null
		join runtimes r on r.installation_id = i.id and r.id = $3 and r.revoked_at is null
		join runtime_grants g on g.runtime_id = r.id and g.user_id = u.id and g.grant_version = $4
		where u.id = $1 and u.status = 'active' and d.key_version = $5 and d.proof_key_thumbprint = $6
		  and g.revoked_at is null and (g.expires_at is null or g.expires_at > clock_timestamp())
		for share of u, d, m, h, i, r, g`,
		ticket.UserID, ticket.DeviceID, ticket.RuntimeID, ticket.GrantVersion,
		ticket.DeviceKeyVersion, ticket.ProofKeyThumbprint).Scan(&currentScopeJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrTicketInvalid
	}
	if err != nil {
		return ErrDatabaseUnavailable
	}
	var currentScope GrantScope
	if json.Unmarshal(currentScopeJSON, &currentScope) != nil || !grantScopeSubset(ticket.Scope, currentScope) {
		return ErrTicketInvalid
	}
	if err := validateGrantResources(ctx, transaction, ticket.RuntimeID, ticket.Scope); err != nil {
		if errors.Is(err, ErrGrantInvalid) || errors.Is(err, ErrAccessDenied) {
			return ErrTicketInvalid
		}
		return err
	}
	if err := transaction.Commit(); err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}

func loadRealtimeTicket(ctx context.Context, transaction *sql.Tx, digest []byte, forUpdate bool) (TicketRedemption, error) {
	var redemption TicketRedemption
	var scopeJSON []byte
	var consumedAt sql.NullTime
	var ticketCurrent bool
	lockClause := " for share"
	if forUpdate {
		lockClause = " for update"
	}
	err := transaction.QueryRowContext(ctx, `
		select t.user_id::text, t.device_id::text, t.device_key_version, t.proof_key_thumbprint,
		       t.runtime_id::text, t.grant_version,
		       t.scope, t.expires_at, t.consumed_at, t.expires_at > clock_timestamp()
		from realtime_tickets t where t.token_sha256 = $1`+lockClause, digest).
		Scan(&redemption.UserID, &redemption.DeviceID, &redemption.DeviceKeyVersion, &redemption.ProofKeyThumbprint,
			&redemption.RuntimeID, &redemption.GrantVersion,
			&scopeJSON, &redemption.ExpiresAt, &consumedAt, &ticketCurrent)
	if errors.Is(err, sql.ErrNoRows) {
		return TicketRedemption{}, ErrTicketInvalid
	}
	if err != nil {
		return TicketRedemption{}, ErrDatabaseUnavailable
	}
	if consumedAt.Valid || !ticketCurrent {
		return TicketRedemption{}, ErrTicketInvalid
	}
	if err := json.Unmarshal(scopeJSON, &redemption.Scope); err != nil {
		return TicketRedemption{}, ErrDatabaseUnavailable
	}
	var currentScopeJSON, proofPublicJWK []byte
	err = transaction.QueryRowContext(ctx, `
		select g.scope, d.proof_public_jwk from users u
		join devices d on d.user_id = u.id and d.id = $2 and d.revoked_at is null
		join org_memberships m on m.user_id = u.id
		join hosts h on h.org_id = m.org_id and h.state = 'active'
		join installations i on i.host_id = h.id and i.revoked_at is null
		join runtimes r on r.installation_id = i.id and r.id = $3 and r.revoked_at is null
		join runtime_grants g on g.runtime_id = r.id and g.user_id = u.id and g.grant_version = $4
		where u.id = $1 and u.status = 'active' and g.revoked_at is null
		  and (g.expires_at is null or g.expires_at > now())
		  and d.key_version = $5 and d.proof_key_thumbprint = $6
		for share of u, d, m, h, i, r, g`,
		redemption.UserID, redemption.DeviceID, redemption.RuntimeID, redemption.GrantVersion,
		redemption.DeviceKeyVersion, redemption.ProofKeyThumbprint).Scan(&currentScopeJSON, &proofPublicJWK)
	if errors.Is(err, sql.ErrNoRows) {
		return TicketRedemption{}, ErrTicketInvalid
	}
	if err != nil {
		return TicketRedemption{}, ErrDatabaseUnavailable
	}
	var currentScope GrantScope
	if err := json.Unmarshal(currentScopeJSON, &currentScope); err != nil || !grantScopeSubset(redemption.Scope, currentScope) {
		return TicketRedemption{}, ErrTicketInvalid
	}
	redemption.ProofPublicJWK = proofPublicJWK
	if err := validateGrantResources(ctx, transaction, redemption.RuntimeID, redemption.Scope); err != nil {
		if errors.Is(err, ErrGrantInvalid) {
			return TicketRedemption{}, ErrTicketInvalid
		}
		return TicketRedemption{}, err
	}
	return redemption, nil
}
