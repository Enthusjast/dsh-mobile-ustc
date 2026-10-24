package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"time"

	"dsh-mobile-ustc/services/remote/internal/approval"
	"dsh-mobile-ustc/services/remote/internal/auth"
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrApprovalInvalid = errors.New("store: invalid approval request")
var ErrApprovalConflict = errors.New("store: approval already bound or decided")
var ErrApprovalExpired = errors.New("store: approval has expired")
var ErrApprovalLimit = errors.New("store: approval limit reached")

const approvalAdmissionTimeout = 1500 * time.Millisecond
const maxActiveApprovals = 64

var approvalAssuranceProfile = regexp.MustCompile(`^[a-z0-9][a-z0-9./_-]{0,127}$`)

// ApprovalPolicy is trusted deployment policy for the high-risk owner path.
// Changing its assurance mapping requires a new policy version.
type ApprovalPolicy struct {
	Version           int64
	AssuranceProfile  string
	MaxAuthAgeSeconds int64
}

type ApprovalControl struct {
	database  *Postgres
	assurance *auth.AssuranceVerifier
	policy    ApprovalPolicy
}

// ApprovalStatus is a durable control-plane fact, not execution permission.
type ApprovalStatus struct {
	ApprovalID    string    `json:"approval_id"`
	RuntimeID     string    `json:"runtime_id"`
	RuntimeEpoch  string    `json:"runtime_epoch"`
	SessionID     string    `json:"session_id"`
	ExecutionID   string    `json:"execution_id"`
	BindingSHA256 string    `json:"binding_sha256"`
	State         string    `json:"state"`
	Decision      string    `json:"decision,omitempty"`
	PayloadSHA256 string    `json:"decision_payload_sha256,omitempty"`
	ExpiresAt     time.Time `json:"expires_at"`
	HostState     string    `json:"host_state,omitempty"`
	Outcome       string    `json:"execution_outcome,omitempty"`
}

func NewApprovalControl(database *Postgres, policy ApprovalPolicy, assurance *auth.AssuranceVerifier) (*ApprovalControl, error) {
	if database == nil || database.DB == nil || assurance == nil || policy.Version < 1 || policy.Version > 9_007_199_254_740_991 ||
		!approvalAssuranceProfile.MatchString(policy.AssuranceProfile) ||
		policy.MaxAuthAgeSeconds < 0 || policy.MaxAuthAgeSeconds > 900 {
		return nil, ErrApprovalInvalid
	}
	return &ApprovalControl{database: database, assurance: assurance, policy: policy}, nil
}

func (control *ApprovalControl) context(raw []byte) (approval.Binding, error) {
	binding, err := approval.ContextBinding(raw)
	if err != nil || binding.Context.PolicyVersion != control.policy.Version ||
		binding.Context.RequiredAssurance.Profile != control.policy.AssuranceProfile ||
		*binding.Context.RequiredAssurance.MaxAuthAgeSeconds != control.policy.MaxAuthAgeSeconds {
		return approval.Binding{}, ErrApprovalInvalid
	}
	return binding, nil
}

// Register authenticates the live host connection and catalog mapping before
// persisting only metadata. Full context, arguments and native call IDs stay
// transient. The binding and nonce/execution tombstones survive retries.
func (control *ApprovalControl) Register(ctx context.Context, connection RuntimeConnection, keyVersion int64, rawContext []byte) (ApprovalStatus, error) {
	binding, err := control.context(rawContext)
	if err != nil {
		return ApprovalStatus{}, err
	}
	request := binding.Context
	if !validApprovalConnection(connection, keyVersion) || connection.InstallationID != request.InstallationID || connection.RuntimeID != request.RuntimeID || connection.RuntimeEpoch != request.RuntimeEpoch {
		return ApprovalStatus{}, ErrRuntimeConnectionStale
	}
	ctx, cancel := context.WithTimeout(ctx, approvalAdmissionTimeout)
	defer cancel()
	transaction, err := control.database.DB.BeginTx(ctx, nil)
	if err != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	// The runtime row serializes registration limits and connection replacement.
	orgID, currentConnection, err := lockApprovalRuntime(ctx, transaction, request, true)
	if err != nil {
		return ApprovalStatus{}, err
	}
	var currentKeyVersion int64
	if err := transaction.QueryRowContext(ctx, `select connection_key_version from runtimes where id = $1`, request.RuntimeID).Scan(&currentKeyVersion); err != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	if currentConnection != connection.ConnectionID || currentKeyVersion != keyVersion {
		return ApprovalStatus{}, ErrRuntimeConnectionStale
	}
	if err := lockApprovalSession(ctx, transaction, request); err != nil {
		return ApprovalStatus{}, err
	}
	now, err := approvalDatabaseTime(ctx, transaction)
	if err != nil {
		return ApprovalStatus{}, err
	}
	if err := approvalRequestTime(request, now); err != nil {
		return ApprovalStatus{}, err
	}
	if err := endRuntimeApprovals(ctx, transaction, orgID, request.RuntimeID, "", true); err != nil {
		return ApprovalStatus{}, err
	}
	var active int
	if err := transaction.QueryRowContext(ctx, `select count(*) from approvals where runtime_id = $1 and (state in ('pending', 'decision_received') or (state = 'allowed' and host_state = 'consumed'))`, request.RuntimeID).Scan(&active); err != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	existing, existingConnection, err := readApproval(ctx, transaction, request.ApprovalID)
	if err == nil {
		if existing.BindingSHA256 != binding.SHA256 {
			return ApprovalStatus{}, ErrApprovalConflict
		}
		if existingConnection != connection.ConnectionID {
			return ApprovalStatus{}, ErrRuntimeConnectionStale
		}
		if err := transaction.Commit(); err != nil {
			return ApprovalStatus{}, ErrDatabaseUnavailable
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	if active >= maxActiveApprovals {
		return ApprovalStatus{}, ErrApprovalLimit
	}
	created, _ := time.Parse(time.RFC3339Nano, request.CreatedAt)
	deadline, _ := time.Parse(time.RFC3339Nano, request.ExpiresAt)
	nonceDigest := sha256.Sum256([]byte(request.Nonce))
	_, err = transaction.ExecContext(ctx, `
		insert into approvals (id, metadata_version, runtime_id, session_id, runtime_epoch, execution_id,
		    binding_sha256, policy_version, state, expires_at, connection_id, workspace_id,
		    nonce_sha256, assurance_profile, max_auth_age_seconds, request_created_at)
		values ($1, 1, $2, $3, $4, $5, $6, $7, 'pending', $8, $9, $10, $11, $12, $13, $14)`,
		request.ApprovalID, request.RuntimeID, request.SessionID, request.RuntimeEpoch, request.ExecutionID,
		binding.SHA256, request.PolicyVersion, deadline, connection.ConnectionID, request.Workspace.WorkspaceID,
		hex.EncodeToString(nonceDigest[:]), request.RequiredAssurance.Profile, *request.RequiredAssurance.MaxAuthAgeSeconds, created)
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return ApprovalStatus{}, ErrApprovalConflict
		}
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	status, _, err := readApproval(ctx, transaction, request.ApprovalID)
	if err != nil || approvalChange(ctx, transaction, orgID, "installation", request.InstallationID, "", "approval.pending", status) != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	if err := transaction.Commit(); err != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	return status, nil
}

// Decide requires both a verified fresh JWT/DPoP principal and the admitted
// socket's exact ticket scope. Neither can be reconstructed from phone JSON.
// A received allow decision is not a claim that the host executed the tool.
func (control *ApprovalControl) Decide(ctx context.Context, principal auth.Principal, ticket TicketRedemption, rawContext []byte, compact string) (ApprovalStatus, error) {
	binding, err := control.context(rawContext)
	if err != nil {
		return ApprovalStatus{}, err
	}
	request := binding.Context
	if ticket.RuntimeID != request.RuntimeID || !grantUUIDPattern.MatchString(ticket.UserID) || !grantUUIDPattern.MatchString(ticket.DeviceID) ||
		ticket.DeviceKeyVersion < 1 || ticket.GrantVersion < 1 || principal.ProofKeyJKT != ticket.ProofKeyThumbprint || principal.ProofJTI == "" ||
		!slices.Contains(ticket.Scope.Actions, "approval.decide") {
		return ApprovalStatus{}, ErrAccessDenied
	}
	if _, err := NormalizeTicketScope("owner", ticket.Scope); err != nil {
		return ApprovalStatus{}, ErrAccessDenied
	}
	ctx, cancel := context.WithTimeout(ctx, approvalAdmissionTimeout)
	defer cancel()
	transaction, err := control.database.DB.BeginTx(ctx, nil)
	if err != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	orgID, connectionID, err := lockApprovalRuntime(ctx, transaction, request, false)
	if err != nil {
		return ApprovalStatus{}, err
	}
	if err := lockApprovalSession(ctx, transaction, request); err != nil {
		return ApprovalStatus{}, err
	}
	key, grantExpires, err := lockApprovalActor(ctx, transaction, principal, ticket, request)
	if err != nil {
		return ApprovalStatus{}, err
	}
	status, registeredConnection, err := readApproval(ctx, transaction, request.ApprovalID)
	if errors.Is(err, sql.ErrNoRows) {
		return ApprovalStatus{}, ErrAccessDenied
	}
	if err != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	if status.BindingSHA256 != binding.SHA256 {
		return ApprovalStatus{}, ErrApprovalConflict
	}
	if connectionID != registeredConnection {
		return ApprovalStatus{}, ErrRuntimeConnectionStale
	}
	// Read the database clock after all potentially blocking locks.
	now, err := approvalDatabaseTime(ctx, transaction)
	if err != nil {
		return ApprovalStatus{}, err
	}
	if err := control.assurance.Verify(principal, control.policy.AssuranceProfile, control.policy.MaxAuthAgeSeconds, now); err != nil {
		return ApprovalStatus{}, err
	}
	if grantExpires.Valid && !grantExpires.Time.After(now) {
		return ApprovalStatus{}, ErrAccessDenied
	}
	verified, err := approval.VerifyDecision(compact, key, rawContext, now)
	if err != nil {
		return ApprovalStatus{}, err
	}
	if status.PayloadSHA256 != "" {
		if status.PayloadSHA256 != verified.PayloadSHA256 {
			return ApprovalStatus{}, ErrApprovalConflict
		}
		if err := transaction.Commit(); err != nil {
			return ApprovalStatus{}, ErrDatabaseUnavailable
		}
		return status, nil
	}
	if status.State != "pending" {
		return ApprovalStatus{}, ErrApprovalConflict
	}
	decisionExpires, _ := time.Parse(time.RFC3339Nano, verified.Claims.ExpiresAt)
	state := "decision_received"
	if verified.Claims.Decision == "reject" {
		state = "denied"
	}
	// Expiry checks use the final write's database clock, so time spent waiting or
	// verifying never buys a later admission window. A failed CAS consumes nothing.
	result, err := transaction.ExecContext(ctx, `
		update approvals set state = $2, decision = $3, decided_by = $4, decided_device_id = $5,
		    decision_jws = $6, decision_payload_sha256 = $7, decision_key_version = $8,
		    decision_approval_key_jkt = $9, decision_proof_key_jkt = $10, decision_grant_version = $11,
		    decision_expires_at = $12, authenticated_at = $13, access_token_expires_at = $14,
		    decided_at = clock_timestamp()
		where id = $1 and state = 'pending' and expires_at > clock_timestamp()
		  and $12::timestamptz > clock_timestamp() and $14::timestamptz > clock_timestamp()
		  and $13::timestamptz + ($15::bigint * interval '1 second') >= clock_timestamp()
		  and ($16::timestamptz is null or $16::timestamptz > clock_timestamp())
		  and exists (select 1 from runtimes r where r.id = approvals.runtime_id
		      and r.last_seen_at > clock_timestamp() - interval '45 seconds')`,
		request.ApprovalID, state, verified.Claims.Decision, ticket.UserID, ticket.DeviceID, compact,
		verified.PayloadSHA256, key.KeyVersion, key.ApprovalKeyJKT, ticket.ProofKeyThumbprint, ticket.GrantVersion,
		decisionExpires, principal.AuthenticatedAt, principal.ExpiresAt, control.policy.MaxAuthAgeSeconds, grantExpires)
	if err != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		if err != nil {
			return ApprovalStatus{}, ErrDatabaseUnavailable
		}
		return ApprovalStatus{}, ErrApprovalExpired
	}
	status, _, err = readApproval(ctx, transaction, request.ApprovalID)
	if err != nil || approvalChange(ctx, transaction, orgID, "device", ticket.DeviceID, ticket.DeviceID, "approval.decided", status) != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	if err := transaction.Commit(); err != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	return status, nil
}

func validApprovalConnection(connection RuntimeConnection, keyVersion int64) bool {
	return keyVersion > 0 && connection.ProtocolVersion == 1 && grantUUIDPattern.MatchString(connection.InstallationID) &&
		grantUUIDPattern.MatchString(connection.RuntimeID) && grantUUIDPattern.MatchString(connection.RuntimeEpoch) && grantUUIDPattern.MatchString(connection.ConnectionID)
}

func lockApprovalRuntime(ctx context.Context, transaction *sql.Tx, request approval.Context, exclusive bool) (string, string, error) {
	locking := "for share of r, i, h"
	if exclusive {
		locking = "for update of r for share of i, h"
	}
	var orgID, connectionID string
	err := transaction.QueryRowContext(ctx, `
		select h.org_id::text, r.connection_id::text from runtimes r
		join installations i on i.id = r.installation_id and i.revoked_at is null
		join hosts h on h.id = i.host_id and h.state = 'active'
		where r.id = $1 and i.id = $2 and h.id = $3 and r.epoch = $4 and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+`
		  and r.connection_id is not null and r.connection_key_version = i.key_version and r.protocol_version = 1
		  and r.last_seen_at > clock_timestamp() - interval '45 seconds'
		`+locking, request.RuntimeID, request.InstallationID, request.HostID, request.RuntimeEpoch).Scan(&orgID, &connectionID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrRuntimeConnectionStale
	}
	if err != nil {
		return "", "", ErrDatabaseUnavailable
	}
	return orgID, connectionID, nil
}

func lockApprovalSession(ctx context.Context, transaction *sql.Tx, request approval.Context) error {
	mapped, err := MobileSessionID(request.RuntimeID, request.DSHSessionID)
	if err != nil || mapped != request.SessionID {
		return ErrAccessDenied
	}
	var sessionID string
	err = transaction.QueryRowContext(ctx, `
		select id::text from sessions where id = $1 and runtime_id = $2 and dsh_session_id = $3
		  and workspace_id = $4 and state in ('available', 'running') for share`,
		request.SessionID, request.RuntimeID, request.DSHSessionID, request.Workspace.WorkspaceID).Scan(&sessionID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAccessDenied
	}
	if err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}

func lockApprovalActor(ctx context.Context, transaction *sql.Tx, principal auth.Principal, ticket TicketRedemption, request approval.Context) (approval.RegisteredKey, sql.NullTime, error) {
	var key approval.RegisteredKey
	var scopeJSON []byte
	var grantExpires sql.NullTime
	err := transaction.QueryRowContext(ctx, `
		select d.user_id::text, d.id::text, d.key_version, d.approval_key_thumbprint, d.approval_public_jwk,
		       g.scope, g.expires_at
		from users u
		join devices d on d.user_id = u.id and d.id = $2 and d.revoked_at is null
		join org_memberships m on m.user_id = u.id
		join hosts h on h.org_id = m.org_id and h.id = $3
		join runtime_grants g on g.user_id = u.id and g.runtime_id = $4
		where u.id = $1 and u.issuer = $5 and u.subject = $6 and u.status = 'active'
		  and d.key_version = $7 and d.proof_key_thumbprint = $8 and g.grant_version = $9
		  and g.role = 'owner' and g.revoked_at is null and (g.expires_at is null or g.expires_at > clock_timestamp())
		for share of u, d, m, g`, ticket.UserID, ticket.DeviceID, request.HostID, request.RuntimeID,
		principal.Issuer, principal.Subject, ticket.DeviceKeyVersion, ticket.ProofKeyThumbprint, ticket.GrantVersion).
		Scan(&key.UserID, &key.DeviceID, &key.KeyVersion, &key.ApprovalKeyJKT, &key.PublicJWK, &scopeJSON, &grantExpires)
	if errors.Is(err, sql.ErrNoRows) {
		return key, grantExpires, ErrAccessDenied
	}
	if err != nil {
		return key, grantExpires, ErrDatabaseUnavailable
	}
	var scope GrantScope
	if json.Unmarshal(scopeJSON, &scope) != nil {
		return key, grantExpires, ErrDatabaseUnavailable
	}
	workspace := sql.NullString{String: request.Workspace.WorkspaceID, Valid: true}
	if !slices.Contains(scope.Actions, "approval.decide") || !grantScopeSubset(ticket.Scope, scope) ||
		!scopeIncludesSession(scope, request.SessionID, workspace) || !scopeIncludesSession(ticket.Scope, request.SessionID, workspace) {
		return key, grantExpires, ErrAccessDenied
	}
	key.Active = true
	return key, grantExpires, nil
}

func readApproval(ctx context.Context, transaction *sql.Tx, id string) (ApprovalStatus, string, error) {
	var status ApprovalStatus
	var connectionID string
	err := transaction.QueryRowContext(ctx, `
		select id::text, runtime_id::text, runtime_epoch::text, session_id::text, execution_id::text,
		       binding_sha256, state, coalesce(decision, ''), coalesce(decision_payload_sha256, ''), expires_at, connection_id::text,
		       coalesce(host_state, ''), coalesce(execution_outcome, '')
		from approvals where id = $1 and metadata_version = 1 for update`, id).
		Scan(&status.ApprovalID, &status.RuntimeID, &status.RuntimeEpoch, &status.SessionID, &status.ExecutionID,
			&status.BindingSHA256, &status.State, &status.Decision, &status.PayloadSHA256, &status.ExpiresAt, &connectionID, &status.HostState, &status.Outcome)
	return status, connectionID, err
}

func approvalDatabaseTime(ctx context.Context, transaction *sql.Tx) (time.Time, error) {
	var now time.Time
	if err := transaction.QueryRowContext(ctx, `select clock_timestamp()`).Scan(&now); err != nil {
		return time.Time{}, ErrDatabaseUnavailable
	}
	return now.UTC(), nil
}

func approvalRequestTime(request approval.Context, now time.Time) error {
	created, _ := time.Parse(time.RFC3339Nano, request.CreatedAt)
	deadline, _ := time.Parse(time.RFC3339Nano, request.ExpiresAt)
	if created.After(now.Add(5 * time.Second)) {
		return ErrApprovalInvalid
	}
	if !deadline.After(now) {
		return ErrApprovalExpired
	}
	return nil
}

func approvalChange(ctx context.Context, transaction *sql.Tx, orgID, actorType, actorID, deviceID, topic string, status ApprovalStatus) error {
	metadata, err := json.Marshal(status)
	if err != nil {
		return ErrDatabaseUnavailable
	}
	if _, err := transaction.ExecContext(ctx, `
		insert into audit_log (org_id, actor_type, actor_id, device_id, runtime_id, session_id, action, result, metadata)
		values ($1, $2, $3, nullif($4, '')::uuid, $5, $6, $7, 'success', $8::jsonb)`,
		orgID, actorType, actorID, deviceID, status.RuntimeID, status.SessionID, topic, string(metadata)); err != nil {
		return ErrDatabaseUnavailable
	}
	if _, err := transaction.ExecContext(ctx, `insert into control_outbox (org_id, topic, payload) values ($1, $2, $3::jsonb)`, orgID, topic, string(metadata)); err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}

// The caller holds the runtime lock. Accepted decisions become unknown when a
// connection disappears: the service cannot assert whether execution occurred.
func endRuntimeApprovals(ctx context.Context, transaction *sql.Tx, orgID, runtimeID, connectionID string, expiredOnly bool) error {
	rows, err := transaction.QueryContext(ctx, `
		update approvals set state = case when state = 'decision_received' or host_state = 'consumed' then 'outcome_unknown'
		    when $3 then 'expired' else 'invalidated' end
		where runtime_id = $1 and metadata_version = 1 and (state in ('pending', 'decision_received') or (state = 'allowed' and host_state = 'consumed'))
		  and ($2 = '' or connection_id = nullif($2, '')::uuid)
		  and (not $3 or least(expires_at, coalesce(decision_expires_at, expires_at)) <= clock_timestamp())
		returning id::text, runtime_epoch::text, session_id::text, execution_id::text,
		    binding_sha256, state, coalesce(decision, ''), coalesce(decision_payload_sha256, ''), expires_at,
		    coalesce(host_state, ''), coalesce(execution_outcome, '')`,
		runtimeID, connectionID, expiredOnly)
	if err != nil {
		return ErrDatabaseUnavailable
	}
	statuses := []ApprovalStatus{}
	for rows.Next() {
		status := ApprovalStatus{RuntimeID: runtimeID}
		if err := rows.Scan(&status.ApprovalID, &status.RuntimeEpoch, &status.SessionID, &status.ExecutionID,
			&status.BindingSHA256, &status.State, &status.Decision, &status.PayloadSHA256, &status.ExpiresAt, &status.HostState, &status.Outcome); err != nil {
			_ = rows.Close()
			return ErrDatabaseUnavailable
		}
		statuses = append(statuses, status)
	}
	readErr := rows.Err()
	closeErr := rows.Close()
	if readErr != nil || closeErr != nil {
		return ErrDatabaseUnavailable
	}
	for _, status := range statuses {
		if err := approvalChange(ctx, transaction, orgID, "system", "approval-lifecycle", "", "approval.ended", status); err != nil {
			return err
		}
	}
	return nil
}
