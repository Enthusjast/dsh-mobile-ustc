package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

var ErrDatabaseConfig = errors.New("store: invalid PostgreSQL configuration")
var ErrDatabaseUnavailable = errors.New("store: PostgreSQL unavailable")
var ErrIdentityNotProvisioned = errors.New("store: user is not provisioned")
var ErrDeviceNotFound = errors.New("store: device not found")

// Postgres owns a bounded database/sql pool over the pinned pgx driver.
type Postgres struct {
	DB *sql.DB
}

type Host struct {
	ID    string `json:"id"`
	Alias string `json:"alias"`
	State string `json:"state"`
}

type Runtime struct {
	ID                 string     `json:"id"`
	HostID             string     `json:"host_id"`
	DSHVersion         string     `json:"dsh_version,omitempty"`
	ApplicationVersion string     `json:"application_version,omitempty"`
	PluginVersion      string     `json:"plugin_version,omitempty"`
	ProtocolVersion    int        `json:"protocol_version"`
	LastSeenAt         *time.Time `json:"last_seen_at,omitempty"`
}

type Session struct {
	RuntimeID        string    `json:"-"`
	WorkspaceID      *string   `json:"-"`
	ID               string    `json:"session_id"`
	State            string    `json:"state"`
	LastPersistedSeq int64     `json:"last_persisted_seq"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type CommandStatus struct {
	RequestID     string    `json:"request_id"`
	SessionID     string    `json:"session_id"`
	State         string    `json:"state"`
	PayloadSHA256 string    `json:"payload_sha256"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type DeviceRegistration struct {
	Issuer                string
	Subject               string
	Name                  string
	ApprovalPublicJWK     []byte
	ApprovalKeyThumbprint string
	ProofPublicJWK        []byte
	ProofKeyThumbprint    string
}

type UserIdentity struct {
	Issuer  string
	Subject string
}

func ValidateDSN(dsn string) error {
	if strings.TrimSpace(dsn) == "" || strings.TrimSpace(dsn) != dsn {
		return ErrDatabaseConfig
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return ErrDatabaseConfig
	}
	if localDatabaseHost(config.Host) {
		return nil
	}
	if config.TLSConfig == nil || config.TLSConfig.InsecureSkipVerify || len(config.Fallbacks) != 0 {
		return ErrDatabaseConfig
	}
	return nil
}

func localDatabaseHost(host string) bool {
	if filepath.IsAbs(host) || strings.HasPrefix(host, "@") || strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func Open(ctx context.Context, dsn string) (*Postgres, error) {
	if err := ValidateDSN(dsn); err != nil {
		return nil, err
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, ErrDatabaseConfig
	}
	database := stdlib.OpenDB(*config)
	database.SetMaxOpenConns(30)
	database.SetMaxIdleConns(10)
	database.SetConnMaxLifetime(30 * time.Minute)
	database.SetConnMaxIdleTime(5 * time.Minute)
	ping, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := database.PingContext(ping); err != nil {
		_ = database.Close()
		return nil, ErrDatabaseUnavailable
	}
	return &Postgres{DB: database}, nil
}

func (postgres *Postgres) Ready(ctx context.Context) error {
	if postgres == nil || postgres.DB == nil {
		return ErrDatabaseUnavailable
	}
	if err := postgres.DB.PingContext(ctx); err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}

func (postgres *Postgres) Close() error {
	if postgres == nil || postgres.DB == nil {
		return nil
	}
	return postgres.DB.Close()
}

func (postgres *Postgres) userID(ctx context.Context, tx *sql.Tx, issuer, subject string) (string, error) {
	var id string
	err := tx.QueryRowContext(ctx, `
		select id::text from users
		where issuer = $1 and subject = $2 and status = 'active'
		for share`, issuer, subject).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrIdentityNotProvisioned
	}
	if err != nil {
		return "", ErrDatabaseUnavailable
	}
	return id, nil
}

func (postgres *Postgres) ActiveUser(ctx context.Context, identity UserIdentity) (string, error) {
	var id string
	err := postgres.DB.QueryRowContext(ctx, `
		select id::text from users where issuer = $1 and subject = $2 and status = 'active'`,
		identity.Issuer, identity.Subject).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrIdentityNotProvisioned
	}
	if err != nil {
		return "", ErrDatabaseUnavailable
	}
	return id, nil
}

func (postgres *Postgres) ActiveDevice(ctx context.Context, identity UserIdentity, proofKeyThumbprint string) (string, error) {
	var id string
	err := postgres.DB.QueryRowContext(ctx, `
		select d.id::text
		from devices d
		join users u on u.id = d.user_id
		where u.issuer = $1 and u.subject = $2 and u.status = 'active'
		  and d.proof_key_thumbprint = $3 and d.revoked_at is null`,
		identity.Issuer, identity.Subject, proofKeyThumbprint).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrDeviceNotFound
	}
	if err != nil {
		return "", ErrDatabaseUnavailable
	}
	return id, nil
}

func (postgres *Postgres) ListHosts(ctx context.Context, identity UserIdentity) ([]Host, error) {
	rows, err := postgres.DB.QueryContext(ctx, `
		select distinct h.id::text, h.alias, h.state
		from users u
		join org_memberships m on m.user_id = u.id
		join hosts h on h.org_id = m.org_id and h.state = 'active'
		join installations i on i.host_id = h.id and i.revoked_at is null
		join runtimes r on r.installation_id = i.id and r.revoked_at is null
		join runtime_grants g on g.runtime_id = r.id and g.user_id = u.id
		where u.issuer = $1 and u.subject = $2 and u.status = 'active'
		  and g.revoked_at is null and (g.expires_at is null or g.expires_at > now())
		  and (
		      g.scope->'actions' ? 'host.list'
		      or (g.scope->'actions' ? 'session.list' and exists (
		          select 1 from sessions s
		          where s.runtime_id = r.id and (
		              coalesce(g.scope->'sessions', '[]'::jsonb) @> jsonb_build_array(s.id::text)
		              or (s.workspace_id is not null and coalesce(g.scope->'workspaces', '[]'::jsonb) @> jsonb_build_array(s.workspace_id::text))
		          )
		      ))
	  )
		order by h.alias, h.id::text`, identity.Issuer, identity.Subject)
	if err != nil {
		return nil, ErrDatabaseUnavailable
	}
	defer rows.Close()
	hosts := make([]Host, 0)
	for rows.Next() {
		var host Host
		if err := rows.Scan(&host.ID, &host.Alias, &host.State); err != nil {
			return nil, ErrDatabaseUnavailable
		}
		hosts = append(hosts, host)
	}
	if err := rows.Err(); err != nil {
		return nil, ErrDatabaseUnavailable
	}
	return hosts, nil
}

func (postgres *Postgres) ListRuntimes(ctx context.Context, identity UserIdentity) ([]Runtime, error) {
	rows, err := postgres.DB.QueryContext(ctx, `
		select distinct r.id::text, h.id::text, coalesce(r.dsh_version, ''),
		       coalesce(r.application_version, ''), coalesce(r.plugin_version, ''),
		       r.protocol_version, r.last_seen_at
		from users u
		join org_memberships m on m.user_id = u.id
		join hosts h on h.org_id = m.org_id and h.state = 'active'
		join installations i on i.host_id = h.id and i.revoked_at is null
		join runtimes r on r.installation_id = i.id and r.revoked_at is null
		join runtime_grants g on g.runtime_id = r.id and g.user_id = u.id
		where u.issuer = $1 and u.subject = $2 and u.status = 'active'
		  and g.revoked_at is null and (g.expires_at is null or g.expires_at > now())
		  and (
		      g.scope->'actions' ? 'host.list'
		      or (g.scope->'actions' ? 'session.list' and exists (
		          select 1 from sessions s
		          where s.runtime_id = r.id and (
		              coalesce(g.scope->'sessions', '[]'::jsonb) @> jsonb_build_array(s.id::text)
		              or (s.workspace_id is not null and coalesce(g.scope->'workspaces', '[]'::jsonb) @> jsonb_build_array(s.workspace_id::text))
		          )
		      ))
	  )
		order by h.id::text, r.id::text`, identity.Issuer, identity.Subject)
	if err != nil {
		return nil, ErrDatabaseUnavailable
	}
	defer rows.Close()
	runtimes := make([]Runtime, 0)
	for rows.Next() {
		var runtime Runtime
		if err := rows.Scan(&runtime.ID, &runtime.HostID, &runtime.DSHVersion, &runtime.ApplicationVersion,
			&runtime.PluginVersion, &runtime.ProtocolVersion, &runtime.LastSeenAt); err != nil {
			return nil, ErrDatabaseUnavailable
		}
		runtimes = append(runtimes, runtime)
	}
	if err := rows.Err(); err != nil {
		return nil, ErrDatabaseUnavailable
	}
	return runtimes, nil
}

func (postgres *Postgres) ListSessions(ctx context.Context, identity UserIdentity, runtimeID string) ([]Session, error) {
	rows, err := postgres.DB.QueryContext(ctx, `
		select s.id::text, s.runtime_id::text, s.workspace_id::text, s.state, s.last_persisted_seq, s.updated_at
		from users u
		join org_memberships m on m.user_id = u.id
		join hosts h on h.org_id = m.org_id and h.state = 'active'
		join installations i on i.host_id = h.id and i.revoked_at is null
		join runtimes r on r.installation_id = i.id and r.id = $3 and r.revoked_at is null
		join runtime_grants g on g.runtime_id = r.id and g.user_id = u.id
		join sessions s on s.runtime_id = r.id
		where u.issuer = $1 and u.subject = $2 and u.status = 'active'
		  and g.revoked_at is null and (g.expires_at is null or g.expires_at > now())
		  and g.scope->'actions' ? 'session.list'
		  and (
		      coalesce(g.scope->'sessions', '[]'::jsonb) @> jsonb_build_array(s.id::text)
		      or (s.workspace_id is not null and coalesce(g.scope->'workspaces', '[]'::jsonb) @> jsonb_build_array(s.workspace_id::text))
		  )
		order by s.updated_at desc, s.id`, identity.Issuer, identity.Subject, runtimeID)
	if err != nil {
		return nil, ErrDatabaseUnavailable
	}
	defer rows.Close()
	sessions := make([]Session, 0)
	for rows.Next() {
		var session Session
		if err := rows.Scan(&session.ID, &session.RuntimeID, &session.WorkspaceID, &session.State, &session.LastPersistedSeq, &session.UpdatedAt); err != nil {
			return nil, ErrDatabaseUnavailable
		}
		sessions = append(sessions, session)
	}
	if err := rows.Err(); err != nil {
		return nil, ErrDatabaseUnavailable
	}
	return sessions, nil
}

func (postgres *Postgres) CommandStatus(ctx context.Context, identity UserIdentity, deviceID, requestID string) (CommandStatus, error) {
	var status CommandStatus
	err := postgres.DB.QueryRowContext(ctx, `
		select c.request_id::text, c.session_id::text, c.state, c.payload_sha256, c.updated_at
		from users u
		join devices d on d.user_id = u.id and d.id = $3 and d.revoked_at is null
		join commands c on c.device_id = d.id and c.user_id = u.id and c.request_id = $4::uuid
		join sessions s on s.id = c.session_id and s.runtime_id = c.runtime_id
		join runtime_grants g on g.runtime_id = c.runtime_id and g.user_id = u.id
		join runtimes r on r.id = c.runtime_id and r.revoked_at is null
		join installations i on i.id = r.installation_id and i.revoked_at is null
		join hosts h on h.id = i.host_id and h.state = 'active'
		join org_memberships m on m.org_id = h.org_id and m.user_id = u.id
		where u.issuer = $1 and u.subject = $2 and u.status = 'active'
		  and g.revoked_at is null and (g.expires_at is null or g.expires_at > now())
		  and g.scope->'actions' ? 'command.status'
		  and (
		      coalesce(g.scope->'sessions', '[]'::jsonb) @> jsonb_build_array(s.id::text)
		      or (s.workspace_id is not null and coalesce(g.scope->'workspaces', '[]'::jsonb) @> jsonb_build_array(s.workspace_id::text))
		  )`,
		identity.Issuer, identity.Subject, deviceID, requestID).
		Scan(&status.RequestID, &status.SessionID, &status.State, &status.PayloadSHA256, &status.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return CommandStatus{}, ErrDeviceNotFound
	}
	if err != nil {
		return CommandStatus{}, ErrDatabaseUnavailable
	}
	return status, nil
}

func (postgres *Postgres) RegisterDevice(ctx context.Context, registration DeviceRegistration) (string, error) {
	if len(registration.Name) == 0 || len(registration.Name) > 160 || registration.Issuer == "" || registration.Subject == "" ||
		len(registration.ApprovalPublicJWK) == 0 || len(registration.ProofPublicJWK) == 0 ||
		registration.ApprovalKeyThumbprint == "" || registration.ProofKeyThumbprint == "" {
		return "", ErrDatabaseConfig
	}
	transaction, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	userID, err := postgres.userID(ctx, transaction, registration.Issuer, registration.Subject)
	if err != nil {
		return "", err
	}
	var deviceID string
	err = transaction.QueryRowContext(ctx, `
		insert into devices (user_id, name, approval_public_jwk, approval_key_thumbprint,
		                     proof_public_jwk, proof_key_thumbprint)
		values ($1, $2, $3::jsonb, $4, $5::jsonb, $6)
		returning id::text`, userID, registration.Name, string(registration.ApprovalPublicJWK),
		registration.ApprovalKeyThumbprint, string(registration.ProofPublicJWK), registration.ProofKeyThumbprint).Scan(&deviceID)
	if err != nil {
		return "", ErrDatabaseUnavailable
	}
	metadata, _ := json.Marshal(map[string]string{"device_id": deviceID, "proof_key_thumbprint": registration.ProofKeyThumbprint})
	if _, err := transaction.ExecContext(ctx, `
		insert into audit_log (actor_type, actor_id, device_id, action, result, metadata)
		values ('user', $1, $2, 'device.register', 'success', $3::jsonb)`, userID, deviceID, string(metadata)); err != nil {
		return "", ErrDatabaseUnavailable
	}
	if err := transaction.Commit(); err != nil {
		return "", ErrDatabaseUnavailable
	}
	return deviceID, nil
}

func (postgres *Postgres) RevokeDevice(ctx context.Context, issuer, subject, deviceID string) error {
	transaction, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	userID, err := postgres.userID(ctx, transaction, issuer, subject)
	if err != nil {
		return err
	}
	var revokedID string
	err = transaction.QueryRowContext(ctx, `
		update devices set revoked_at = now()
		where id = $1 and user_id = $2 and revoked_at is null
		returning id::text`, deviceID, userID).Scan(&revokedID)
	if errors.Is(err, sql.ErrNoRows) {
		var exists bool
		if err := transaction.QueryRowContext(ctx, `select exists (
			select 1 from devices where id = $1 and user_id = $2
		)`, deviceID, userID).Scan(&exists); err != nil {
			return ErrDatabaseUnavailable
		}
		if exists {
			return nil
		}
		return ErrDeviceNotFound
	}
	if err != nil {
		return ErrDatabaseUnavailable
	}
	metadata, _ := json.Marshal(map[string]string{"device_id": revokedID})
	if _, err := transaction.ExecContext(ctx, `
		insert into control_outbox (topic, payload) values ('device.revoked', $1::jsonb)`, string(metadata)); err != nil {
		return ErrDatabaseUnavailable
	}
	if _, err := transaction.ExecContext(ctx, `
		insert into audit_log (actor_type, actor_id, device_id, action, result, metadata)
		values ('user', $1, $2, 'device.revoke', 'success', $3::jsonb)`, userID, revokedID, string(metadata)); err != nil {
		return ErrDatabaseUnavailable
	}
	if err := transaction.Commit(); err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}
