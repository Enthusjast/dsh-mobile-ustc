package store

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
)

// A socket's literal ticket scope remains narrower than the user's full grant.
// Session-only tickets never become workspace browser authority.
func (postgres *Postgres) AuthorizeRealtimeExport(ctx context.Context, ticket TicketRedemption, session string) (files.ExportAccess, error) {
	if !grantUUIDPattern.MatchString(ticket.UserID) || !slices.Contains(ticket.Scope.Actions, "session.read") || !slices.Contains(ticket.Scope.Actions, "file.download") {
		return files.ExportAccess{}, ErrAccessDenied
	}
	tx, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return files.ExportAccess{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	actor := files.Actor{DeviceID: ticket.DeviceID, ProofKeyJKT: ticket.ProofKeyThumbprint}
	if err := tx.QueryRowContext(ctx, `select issuer,subject from users where id=$1 and status='active' for share`, ticket.UserID).Scan(&actor.Issuer, &actor.Subject); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return files.ExportAccess{}, ErrAccessDenied
		}
		return files.ExportAccess{}, ErrDatabaseUnavailable
	}
	authority, err := authorizeFileAction(ctx, tx, actor, ticket.RuntimeID, session, "file.download", false)
	if err != nil {
		return files.ExportAccess{}, err
	}
	if authority.keyVersion != ticket.DeviceKeyVersion || authority.grantVersion != ticket.GrantVersion || authority.user != ticket.UserID || !grantScopeSubset(ticket.Scope, authority.scope) || !scopeIncludesSession(ticket.Scope, session, authority.workspace) || authority.sessionState == "unavailable" {
		return files.ExportAccess{}, ErrAccessDenied
	}
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return files.ExportAccess{}, err
	}
	until := now.Add(5 * time.Second)
	if authority.grantExpires.Valid {
		until = minTime(until, authority.grantExpires.Time)
	}
	access := files.ExportAccess{Actor: actor, UserID: ticket.UserID, DeviceKeyVersion: authority.keyVersion, GrantVersion: authority.grantVersion, LeaseUntil: until,
		AllowWorkspace: authority.workspace.Valid && slices.Contains(ticket.Scope.Workspaces, authority.workspace.String) && slices.Contains(authority.scope.Workspaces, authority.workspace.String)}
	if err := tx.Commit(); err != nil {
		return files.ExportAccess{}, ErrDatabaseUnavailable
	}
	return access, nil
}

func (postgres *Postgres) LookupRealtimeExport(ctx context.Context, ticket TicketRedemption, selector files.ExportSelector) (files.Status, bool, error) {
	for _, id := range []string{selector.RequestID, selector.RuntimeID, selector.SessionID, selector.RuntimeEpoch, selector.SourceID} {
		if !grantUUIDPattern.MatchString(id) {
			return files.Status{}, false, files.ErrInvalid
		}
	}
	if selector.RuntimeID != ticket.RuntimeID {
		return files.Status{}, false, ErrAccessDenied
	}
	access, err := postgres.AuthorizeRealtimeExport(ctx, ticket, selector.SessionID)
	if err != nil {
		return files.Status{}, false, err
	}
	tx, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return files.Status{}, false, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	record, err := scanFile(tx.QueryRowContext(ctx, `select `+fileColumns+` from files f join file_transfers t on t.file_id=f.id where t.uploader_device_id=$1 and t.request_id=$2`, ticket.DeviceID, selector.RequestID))
	if errors.Is(err, sql.ErrNoRows) {
		return files.Status{}, false, nil
	}
	if err != nil {
		return files.Status{}, false, ErrDatabaseUnavailable
	}
	if record.Direction != "from_host" || record.RuntimeID != selector.RuntimeID || record.SessionID != selector.SessionID {
		return files.Status{}, false, files.ErrConflict
	}
	authority, err := authorizeExportOwner(ctx, tx, access.Actor, record, false)
	if err != nil {
		return files.Status{}, false, err
	}
	if authority.keyVersion != ticket.DeviceKeyVersion || authority.grantVersion != ticket.GrantVersion {
		return files.Status{}, false, ErrAccessDenied
	}
	origin, err := loadExportOrigin(ctx, tx, record)
	if err != nil {
		return files.Status{}, false, err
	}
	if origin.source != selector.SourceID || origin.host.RuntimeEpoch != selector.RuntimeEpoch {
		return files.Status{}, false, files.ErrConflict
	}
	if origin.kind == "workspace_artifact" && !access.AllowWorkspace {
		return files.Status{}, false, ErrAccessDenied
	}
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return files.Status{}, false, err
	}
	if !record.ExpiresAt.After(now) {
		record.State, record.ErrorCode = "expired", "expired"
	}
	if err := tx.Commit(); err != nil {
		return files.Status{}, false, ErrDatabaseUnavailable
	}
	return record.Status(), true, nil
}
