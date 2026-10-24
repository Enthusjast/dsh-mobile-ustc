package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"unicode"
)

var ErrRuntimeConnectionStale = errors.New("store: runtime connection is stale")
var ErrRuntimeProtocolUnsupported = errors.New("store: runtime protocol is unsupported")

type RuntimeConnectionInput struct {
	InstallationID     string
	KeyVersion         int64
	RuntimeID          string
	RuntimeEpoch       string
	ConnectionID       string
	DSHVersion         string
	ApplicationVersion string
	PluginVersion      string
	ProtocolVersion    int
}

type RuntimeConnection struct {
	InstallationID  string `json:"installation_id"`
	RuntimeID       string `json:"runtime_id"`
	RuntimeEpoch    string `json:"runtime_epoch"`
	ConnectionID    string `json:"connection_id"`
	ProtocolVersion int    `json:"protocol_version"`
}

func (postgres *Postgres) AttachRuntimeConnection(ctx context.Context, input RuntimeConnectionInput) (RuntimeConnection, error) {
	input.DSHVersion = strings.TrimSpace(input.DSHVersion)
	input.ApplicationVersion = strings.TrimSpace(input.ApplicationVersion)
	input.PluginVersion = strings.TrimSpace(input.PluginVersion)
	if !grantUUIDPattern.MatchString(input.InstallationID) || !grantUUIDPattern.MatchString(input.RuntimeID) ||
		!grantUUIDPattern.MatchString(input.RuntimeEpoch) || !grantUUIDPattern.MatchString(input.ConnectionID) ||
		input.KeyVersion <= 0 || input.ProtocolVersion < 1 || input.ProtocolVersion > 32 {
		return RuntimeConnection{}, ErrHostCredentialInvalid
	}
	for _, version := range []string{input.DSHVersion, input.ApplicationVersion, input.PluginVersion} {
		if len(version) == 0 || len(version) > 128 || strings.IndexFunc(version, unicode.IsControl) >= 0 {
			return RuntimeConnection{}, ErrHostCredentialInvalid
		}
	}
	transaction, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return RuntimeConnection{}, ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	var protocolVersion int
	var orgID string
	err = transaction.QueryRowContext(ctx, `
		select r.protocol_version, h.org_id::text
		from runtimes r
		join installations i on i.id = r.installation_id and i.revoked_at is null
		join hosts h on h.id = i.host_id and h.state = 'active'
		where r.id = $1 and i.id = $2 and i.key_version = $3 and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+`
		for update of r, i, h`, input.RuntimeID, input.InstallationID, input.KeyVersion).Scan(&protocolVersion, &orgID)
	if errors.Is(err, sql.ErrNoRows) {
		return RuntimeConnection{}, ErrHostCredentialInvalid
	}
	if err != nil {
		return RuntimeConnection{}, ErrDatabaseUnavailable
	}
	if protocolVersion != input.ProtocolVersion {
		return RuntimeConnection{}, ErrRuntimeProtocolUnsupported
	}
	if _, err := transaction.ExecContext(ctx, `
		update runtimes
		set epoch = $1, connection_id = $2, dsh_version = $3, application_version = $4,
		    plugin_version = $5, last_seen_at = clock_timestamp(), connection_key_version = $8
		where id = $6 and installation_id = $7 and revoked_at is null`,
		input.RuntimeEpoch, input.ConnectionID, input.DSHVersion, input.ApplicationVersion,
		input.PluginVersion, input.RuntimeID, input.InstallationID, input.KeyVersion); err != nil {
		return RuntimeConnection{}, ErrDatabaseUnavailable
	}
	if _, err := transaction.ExecContext(ctx, `
		update sessions set state = 'unavailable', updated_at = clock_timestamp()
		where runtime_id = $1`, input.RuntimeID); err != nil {
		return RuntimeConnection{}, ErrDatabaseUnavailable
	}
	if err := endRuntimeApprovals(ctx, transaction, orgID, input.RuntimeID, "", false); err != nil {
		return RuntimeConnection{}, err
	}
	metadata, _ := json.Marshal(map[string]any{
		"runtime_id": input.RuntimeID, "runtime_epoch": input.RuntimeEpoch,
		"connection_id": input.ConnectionID, "protocol_version": input.ProtocolVersion,
	})
	if _, err := transaction.ExecContext(ctx, `
		insert into audit_log (org_id, actor_type, actor_id, runtime_id, action, result, metadata)
		values ($1, 'installation', $2, $3, 'host.runtime.connect', 'success', $4::jsonb)`,
		orgID, input.InstallationID, input.RuntimeID, string(metadata)); err != nil {
		return RuntimeConnection{}, ErrDatabaseUnavailable
	}
	if err := transaction.Commit(); err != nil {
		return RuntimeConnection{}, ErrDatabaseUnavailable
	}
	return RuntimeConnection{
		InstallationID: input.InstallationID, RuntimeID: input.RuntimeID,
		RuntimeEpoch: input.RuntimeEpoch, ConnectionID: input.ConnectionID,
		ProtocolVersion: protocolVersion,
	}, nil
}

func (postgres *Postgres) TouchRuntimeConnection(ctx context.Context, installationID, runtimeID, runtimeEpoch, connectionID string) error {
	result, err := postgres.DB.ExecContext(ctx, `
		update runtimes r set last_seen_at = clock_timestamp()
		from installations i, hosts h
		where r.id = $1 and r.installation_id = $2 and r.epoch = $3 and r.connection_id = $4
		  and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+` and i.id = r.installation_id and i.revoked_at is null
		  and r.connection_key_version = i.key_version and h.id = i.host_id and h.state = 'active'`,
		runtimeID, installationID, runtimeEpoch, connectionID)
	if err != nil {
		return ErrDatabaseUnavailable
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return ErrDatabaseUnavailable
	}
	if rows != 1 {
		return ErrRuntimeConnectionStale
	}
	return nil
}

func (postgres *Postgres) DetachRuntimeConnection(ctx context.Context, installationID, runtimeID, runtimeEpoch, connectionID string) error {
	transaction, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(ctx, `
		update runtimes r set connection_id = null, connection_key_version = null, last_seen_at = null
		where r.id = $1 and r.installation_id = $2 and r.epoch = $3 and r.connection_id = $4`,
		runtimeID, installationID, runtimeEpoch, connectionID)
	if err != nil {
		return ErrDatabaseUnavailable
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return ErrDatabaseUnavailable
	}
	if rows == 1 {
		if _, err := transaction.ExecContext(ctx, `
			update sessions set state = 'unavailable', updated_at = clock_timestamp()
			where runtime_id = $1`, runtimeID); err != nil {
			return ErrDatabaseUnavailable
		}
		var orgID string
		if err := transaction.QueryRowContext(ctx, `
			select h.org_id::text from runtimes r join installations i on i.id = r.installation_id
			join hosts h on h.id = i.host_id where r.id = $1`, runtimeID).Scan(&orgID); err != nil {
			return ErrDatabaseUnavailable
		}
		if err := endRuntimeApprovals(ctx, transaction, orgID, runtimeID, connectionID, false); err != nil {
			return err
		}
	}
	if err := transaction.Commit(); err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}
