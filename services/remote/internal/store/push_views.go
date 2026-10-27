package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"dsh-mobile-ustc/services/remote/internal/push"
)

func (store *PushStore) Renew(ctx context.Context, actor push.Actor, id string) (push.Binding, error) {
	tx, err := store.database.DB.BeginTx(ctx, nil)
	if err != nil {
		return push.Binding{}, push.ErrUnavailable
	}
	defer tx.Rollback()
	b, err := store.owned(ctx, tx, actor, id, "for update of b")
	if err != nil {
		return push.Binding{}, err
	}
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return push.Binding{}, push.ErrUnavailable
	}
	if b.State != "active" || now.Before(b.Created) || !now.Before(b.Expiry) {
		return push.Binding{}, push.ErrExpired
	}
	b.Expiry = now.Add(7 * 24 * time.Hour)
	if _, err = tx.ExecContext(ctx, `update push_bindings set expires_at=$2 where id=$1`, id, b.Expiry); err != nil || tx.Commit() != nil {
		return push.Binding{}, push.ErrUnavailable
	}
	return b.public(), nil
}

func (store *PushStore) Reference(ctx context.Context, actor push.Actor, id string) (push.Reference, error) {
	if !push.UUID(id) {
		return push.Reference{}, push.ErrAccess
	}
	tx, err := store.database.DB.BeginTx(ctx, nil)
	if err != nil {
		return push.Reference{}, push.ErrUnavailable
	}
	defer tx.Rollback()
	var ref push.Reference
	err = tx.QueryRowContext(ctx, `select id::text,binding_id::text,kind,source_id::text,runtime_id::text,runtime_epoch::text,session_id::text,expires_at from push_deliveries where id=$1 and kind<>'challenge'`, id).Scan(&ref.NotificationID, &ref.BindingID, &ref.Kind, &ref.ReferenceID, &ref.RuntimeID, &ref.RuntimeEpoch, &ref.SessionID, &ref.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ref, push.ErrAccess
	}
	if err != nil {
		return ref, push.ErrUnavailable
	}
	b, err := store.owned(ctx, tx, actor, ref.BindingID, "for share of b")
	if err != nil {
		return ref, err
	}
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return ref, push.ErrUnavailable
	}
	if b.State != "active" || now.Before(b.Created) || !now.Before(b.Expiry) {
		return ref, push.ErrAccess
	}
	if ref.Kind == "question" || ref.Kind == "timed_question" {
		if tx.Commit() != nil {
			return ref, push.ErrUnavailable
		}
		scope, version, err := store.questionGrant(ctx, b, ref.RuntimeID)
		if err != nil {
			return ref, err
		}
		status, err := store.database.AuthorizeQuestionReference(ctx, TicketRedemption{UserID: b.User, DeviceID: b.Device, DeviceKeyVersion: b.KeyVersion, ProofKeyThumbprint: b.JKT, RuntimeID: ref.RuntimeID, GrantVersion: version, Scope: scope}, ref.ReferenceID)
		if errors.Is(err, ErrDatabaseUnavailable) {
			return ref, push.ErrUnavailable
		}
		if err != nil || status.Kind != ref.Kind || status.SessionID != ref.SessionID || status.RuntimeEpoch != ref.RuntimeEpoch {
			return ref, push.ErrAccess
		}
		ref.State = status.State
		ref.Availability = status.Availability
		if status.Availability == "online" {
			ref.ExpiresAt = status.ValidUntil
		}
		return ref, nil
	}
	if store.approvals == nil {
		return ref, push.ErrAccess
	}
	var scopeJSON []byte
	var version int64
	err = tx.QueryRowContext(ctx, `select g.scope,g.grant_version from runtime_grants g join runtimes r on r.id=g.runtime_id join installations i on i.id=r.installation_id join hosts h on h.id=i.host_id where g.runtime_id=$1 and g.user_id=$2 and h.org_id=$3 and g.role='owner' and g.revoked_at is null and (g.expires_at is null or g.expires_at>clock_timestamp())`, ref.RuntimeID, b.User, b.Org).Scan(&scopeJSON, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return ref, push.ErrAccess
	}
	if err != nil {
		return ref, push.ErrUnavailable
	}
	var scope GrantScope
	if json.Unmarshal(scopeJSON, &scope) != nil {
		return ref, push.ErrUnavailable
	}
	if tx.Commit() != nil {
		return ref, push.ErrUnavailable
	}
	if ref.Kind != "approval" {
		return ref, push.ErrAccess
	}
	scope.Actions = []string{"session.read", "approval.decide"}
	status, err := store.approvals.AuthorizeStatus(ctx, TicketRedemption{UserID: b.User, DeviceID: b.Device, DeviceKeyVersion: b.KeyVersion, ProofKeyThumbprint: b.JKT, RuntimeID: ref.RuntimeID, GrantVersion: version, Scope: scope}, ref.ReferenceID)
	if errors.Is(err, ErrDatabaseUnavailable) {
		return ref, push.ErrUnavailable
	}
	if err != nil {
		return ref, push.ErrAccess
	}
	if status.SessionID != ref.SessionID || status.RuntimeEpoch != ref.RuntimeEpoch {
		return ref, push.ErrAccess
	}
	ref.State = status.State
	ref.Availability = "ended"
	if status.State == "pending" && status.ExpiresAt.After(time.Now()) {
		var epoch, connection sql.NullString
		var seen sql.NullTime
		var original string
		err = store.database.DB.QueryRowContext(ctx, `select r.epoch::text,r.connection_id::text,r.last_seen_at,a.connection_id::text from approvals a join runtimes r on r.id=a.runtime_id where a.id=$1`, ref.ReferenceID).Scan(&epoch, &connection, &seen, &original)
		if err != nil {
			return ref, push.ErrUnavailable
		}
		if epoch.String != ref.RuntimeEpoch {
			ref.Availability = "stale_epoch"
		} else if connection.String != original || !seen.Valid || time.Since(seen.Time) > 45*time.Second {
			ref.Availability = "host_offline"
		} else {
			ref.Availability = "online"
		}
	}
	if ref.State == "pending" && !status.ExpiresAt.After(time.Now()) {
		ref.State = "expired"
	}
	return ref, nil
}

func (store *PushStore) questionGrant(ctx context.Context, b pushBinding, runtime string) (GrantScope, int64, error) {
	var scope GrantScope
	var raw []byte
	var version int64
	err := store.database.DB.QueryRowContext(ctx, `select g.scope,g.grant_version from runtime_grants g join runtimes r on r.id=g.runtime_id
	 join installations i on i.id=r.installation_id join hosts h on h.id=i.host_id
	 where g.runtime_id=$1 and g.user_id=$2 and h.org_id=$3 and g.role in ('owner','operator') and g.revoked_at is null
	 and (g.expires_at is null or g.expires_at>clock_timestamp())`, runtime, b.User, b.Org).Scan(&raw, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return scope, 0, push.ErrAccess
	}
	if err != nil || json.Unmarshal(raw, &scope) != nil {
		return scope, 0, push.ErrUnavailable
	}
	scope.Actions = []string{"session.read", "question.answer"}
	return scope, version, nil
}

type PushInbox struct {
	Items  []push.Reference `json:"items"`
	Cursor *string          `json:"cursor"`
}

func (store *PushStore) Inbox(ctx context.Context, actor push.Actor, binding, after string) (PushInbox, error) {
	page := PushInbox{Items: []push.Reference{}}
	if !push.UUID(binding) || (after != "" && !push.UUID(after)) {
		return page, push.ErrInvalid
	}
	tx, err := store.database.DB.BeginTx(ctx, nil)
	if err != nil {
		return page, push.ErrUnavailable
	}
	defer tx.Rollback()
	b, err := store.owned(ctx, tx, actor, binding, "for share of b")
	if err != nil {
		return page, err
	}
	if b.State != "active" {
		return page, push.ErrAccess
	}
	rows, err := tx.QueryContext(ctx, `select id::text from push_deliveries where binding_id=$1 and kind<>'challenge' and ($2='' or id>nullif($2,'')::uuid) and expires_at>clock_timestamp()-interval '1 day' order by id limit 65`, binding, after)
	if err != nil {
		return page, push.ErrUnavailable
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			rows.Close()
			return page, push.ErrUnavailable
		}
		ids = append(ids, id)
	}
	read, closeErr := rows.Err(), rows.Close()
	if read != nil || closeErr != nil {
		return page, push.ErrUnavailable
	}
	if tx.Commit() != nil {
		return page, push.ErrUnavailable
	}
	if len(ids) > 64 {
		cursor := ids[63]
		page.Cursor = &cursor
		ids = ids[:64]
	}
	for _, id := range ids {
		ref, err := store.Reference(ctx, actor, id)
		if errors.Is(err, push.ErrAccess) {
			continue
		}
		if err != nil {
			return PushInbox{}, err
		}
		page.Items = append(page.Items, ref)
	}
	return page, nil
}
func (store *PushStore) Receipt(ctx context.Context, actor push.Actor, id, state string) error {
	started := time.Now()
	err := store.receipt(ctx, actor, id, state)
	store.observePushOperation(ctx, "receipt", started, err)
	return err
}

func (store *PushStore) receipt(ctx context.Context, actor push.Actor, id, state string) error {
	if state != "posted" && state != "opened" && state != "blocked" {
		return push.ErrInvalid
	}
	ref, err := store.Reference(ctx, actor, id)
	if err != nil {
		return err
	}
	// A receipt is client telemetry. It neither authorizes an interaction nor
	// advances the source's state, and is never called 'human saw it'.
	tx, err := store.database.DB.BeginTx(ctx, nil)
	if err != nil {
		return push.ErrUnavailable
	}
	defer tx.Rollback()
	b, err := store.owned(ctx, tx, actor, ref.BindingID, "for share of b")
	if err != nil {
		return err
	}
	if b.State != "active" || !b.Expiry.After(time.Now()) {
		return push.ErrAccess
	}
	var createdAt, receivedAt time.Time
	err = tx.QueryRowContext(ctx, `with inserted as (
	 insert into push_receipts(notification_id,state) values($1,$2) on conflict do nothing returning notification_id,received_at)
	 select d.created_at,i.received_at from inserted i join push_deliveries d on d.id=i.notification_id`, id, state).Scan(&createdAt, &receivedAt)
	inserted := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return push.ErrUnavailable
	}
	if inserted && pushAudit(ctx, tx, b, "push.client_receipt", state, map[string]string{"notification_id": id}) != nil {
		return push.ErrUnavailable
	}
	if tx.Commit() != nil {
		return push.ErrUnavailable
	}
	if inserted {
		store.database.push.metrics.PushReceipt(ref.Kind, state, createdAt, receivedAt)
	}
	return nil
}
