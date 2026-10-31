package store

import (
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

var ErrSessionCatalogInvalid = errors.New("store: invalid session catalog")

const maxSessionCatalogItems = 20_000

// SessionCatalogItem contains only identifiers and directory metadata. Session
// bodies and event data never enter the control-plane catalog.
type SessionCatalogItem struct {
	SessionID        string             `json:"session_id"`
	DSHSessionID     string             `json:"dsh_session_id"`
	WorkspaceID      *string            `json:"workspace_id"`
	State            string             `json:"state"`
	LastPersistedSeq int64              `json:"last_persisted_seq"`
	Metadata         *DirectoryMetadata `json:"metadata,omitempty"`
}

func MobileSessionID(runtimeID, dshSessionID string) (string, error) {
	if !grantUUIDPattern.MatchString(runtimeID) || dshSessionID == "" || len(dshSessionID) > 2048 ||
		!utf8.ValidString(dshSessionID) || strings.IndexByte(dshSessionID, 0) >= 0 {
		return "", ErrSessionCatalogInvalid
	}
	namespace, err := hex.DecodeString(strings.ReplaceAll(runtimeID, "-", ""))
	if err != nil || len(namespace) != 16 {
		return "", ErrSessionCatalogInvalid
	}
	hasher := sha1.New()
	_, _ = hasher.Write(namespace)
	_, _ = hasher.Write([]byte(dshSessionID))
	digest := hasher.Sum(nil)[:16]
	digest[6] = (digest[6] & 0x0f) | 0x50
	digest[8] = (digest[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", digest[0:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16]), nil
}

// SyncRealtimeSessionCatalog applies a key-authenticated session metadata
// snapshot or delta. A disconnected runtime cannot publish metadata after a
// newer connection has taken ownership.
func (postgres *Postgres) SyncRealtimeSessionCatalog(
	ctx context.Context,
	connection RuntimeConnection,
	keyVersion int64,
	replace bool,
	items []SessionCatalogItem,
) error {
	_, err := retrySerializable(ctx, func() (struct{}, error) {
		return struct{}{}, postgres.syncRealtimeSessionCatalogOnce(ctx, connection, keyVersion, replace, items)
	}, postgres.admissionGate())
	return err
}

func (postgres *Postgres) syncRealtimeSessionCatalogOnce(ctx context.Context, connection RuntimeConnection, keyVersion int64, replace bool, items []SessionCatalogItem) error {
	if !grantUUIDPattern.MatchString(connection.InstallationID) || !grantUUIDPattern.MatchString(connection.RuntimeID) ||
		!grantUUIDPattern.MatchString(connection.RuntimeEpoch) || !grantUUIDPattern.MatchString(connection.ConnectionID) ||
		keyVersion <= 0 || len(items) > maxSessionCatalogItems {
		return ErrSessionCatalogInvalid
	}
	seenSessions := make(map[string]struct{}, len(items))
	seenNative := make(map[string]struct{}, len(items))
	for index := range items {
		item := &items[index]
		if !grantUUIDPattern.MatchString(item.SessionID) || item.DSHSessionID == "" || len(item.DSHSessionID) > 2048 ||
			!utf8.ValidString(item.DSHSessionID) || strings.IndexByte(item.DSHSessionID, 0) >= 0 || item.LastPersistedSeq < -1 {
			return ErrSessionCatalogInvalid
		}
		if item.State != "available" && item.State != "running" && item.State != "archived" && item.State != "unavailable" {
			return ErrSessionCatalogInvalid
		}
		if item.WorkspaceID != nil && !grantUUIDPattern.MatchString(*item.WorkspaceID) {
			return ErrSessionCatalogInvalid
		}
		if !item.Metadata.Valid() || item.Metadata != nil && (item.WorkspaceID == nil && item.Metadata.WorkspaceTitle != nil || item.State == "unavailable" && (item.Metadata.Title != nil || item.Metadata.WorkspaceTitle != nil)) {
			return ErrSessionCatalogInvalid
		}
		mapped, err := MobileSessionID(connection.RuntimeID, item.DSHSessionID)
		if err != nil || mapped != item.SessionID {
			return ErrSessionCatalogInvalid
		}
		if _, exists := seenSessions[item.SessionID]; exists {
			return ErrSessionCatalogInvalid
		}
		if _, exists := seenNative[item.DSHSessionID]; exists {
			return ErrSessionCatalogInvalid
		}
		seenSessions[item.SessionID] = struct{}{}
		seenNative[item.DSHSessionID] = struct{}{}
	}
	if items == nil {
		items = []SessionCatalogItem{}
	}
	encoded, err := json.Marshal(items)
	if err != nil {
		return ErrSessionCatalogInvalid
	}
	transaction, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return transactionFailure(err)
	}
	defer transaction.Rollback()
	var orgID string
	err = transaction.QueryRowContext(ctx, `
		select h.org_id::text
		from runtimes r
		join installations i on i.id = r.installation_id and i.revoked_at is null
		join hosts h on h.id = i.host_id and h.state = 'active'
		where r.id = $1 and i.id = $2 and i.key_version = $3
		  and r.epoch = $4 and r.connection_id = $5 and r.connection_key_version = $3
		  and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+`
		for share of r, i, h`, connection.RuntimeID, connection.InstallationID, keyVersion,
		connection.RuntimeEpoch, connection.ConnectionID).Scan(&orgID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrRuntimeConnectionStale
	}
	if err != nil {
		return transactionFailure(err)
	}
	if replace {
		if _, err := transaction.ExecContext(ctx, `
			update sessions set state = 'unavailable', workspace_id = null, directory_metadata = null, updated_at = clock_timestamp()
			where runtime_id = $1`, connection.RuntimeID); err != nil {
			return transactionFailure(err)
		}
	}
	result, err := transaction.ExecContext(ctx, `
		insert into sessions (id, runtime_id, workspace_id, dsh_session_id, state, last_persisted_seq, directory_metadata, updated_at)
		select item.session_id, $1, item.workspace_id, item.dsh_session_id, item.state, item.last_persisted_seq, item.metadata, clock_timestamp()
		from jsonb_to_recordset($2::jsonb) as item(
			session_id uuid, workspace_id uuid, dsh_session_id text, state text, last_persisted_seq bigint, metadata jsonb
		)
		left join workspaces w on w.runtime_id = $1 and w.id = item.workspace_id
		where item.workspace_id is null or w.id is not null
		on conflict (runtime_id, dsh_session_id) do update set
			id = excluded.id, workspace_id = excluded.workspace_id, state = excluded.state, directory_metadata = excluded.directory_metadata,
			last_persisted_seq = case
				when excluded.state = 'unavailable' and excluded.workspace_id is null and excluded.last_persisted_seq = -1
				then sessions.last_persisted_seq else excluded.last_persisted_seq end,
			updated_at = excluded.updated_at`,
		connection.RuntimeID, string(encoded))
	if err != nil {
		return transactionFailure(err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != int64(len(items)) {
		return ErrSessionCatalogInvalid
	}
	mode := "delta"
	if replace {
		mode = "snapshot"
	}
	metadata, _ := json.Marshal(map[string]any{"session_count": len(items), "runtime_epoch": connection.RuntimeEpoch, "mode": mode})
	if _, err := transaction.ExecContext(ctx, `
		insert into audit_log (org_id, actor_type, actor_id, runtime_id, action, result, metadata)
		values ($1, 'installation', $2, $3, 'session.catalog.sync', 'success', $4::jsonb)`,
		orgID, connection.InstallationID, connection.RuntimeID, string(metadata)); err != nil {
		return transactionFailure(err)
	}
	if err := transaction.Commit(); err != nil {
		return transactionFailure(err)
	}
	return nil
}
