package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"dsh-mobile-ustc/services/remote/internal/push"
)

func (store *PushStore) Plan(ctx context.Context) error {
	tx, err := store.database.DB.BeginTx(ctx, nil)
	if err != nil {
		return push.ErrUnavailable
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `update push_bindings b set state='expired',address_ciphertext=null from devices d
	 where d.id=b.device_id and b.state in ('pending','active') and (b.expires_at<=clock_timestamp() or b.created_at>clock_timestamp()
	 or b.state='pending' and b.challenge_expires_at<=clock_timestamp() or d.revoked_at is not null or d.key_version<>b.device_key_version or d.proof_key_thumbprint<>b.proof_key_jkt)`); err != nil {
		return push.ErrUnavailable
	}
	if _, err = tx.ExecContext(ctx, `update push_deliveries d set state='expired',nonce_ciphertext=null,error_code='expired',updated_at=clock_timestamp()
	 from push_bindings b where b.id=d.binding_id and d.state in ('queued','retry','leased') and (d.expires_at<=clock_timestamp() or b.state not in ('pending','active'))`); err != nil {
		return push.ErrUnavailable
	}
	if _, err = tx.ExecContext(ctx, `update push_deliveries d set nonce_ciphertext=null from push_bindings b where b.id=d.binding_id and d.kind='challenge' and d.nonce_ciphertext is not null and b.state<>'pending'`); err != nil {
		return push.ErrUnavailable
	}
	if _, err = tx.ExecContext(ctx, `update push_deliveries set state='failed',nonce_ciphertext=null,error_code='retry_exhausted',updated_at=clock_timestamp()
	 where attempts>=8 and (state in ('queued','retry') or state='leased' and lease_until<=clock_timestamp())`); err != nil {
		return push.ErrUnavailable
	}
	if store.approvals != nil {
		_, err = tx.ExecContext(ctx, `insert into push_deliveries(binding_id,kind,source_id,runtime_id,runtime_epoch,session_id,grant_version,expires_at)
		 select b.id,'approval',a.id,a.runtime_id,a.runtime_epoch,a.session_id,g.grant_version,a.expires_at
		 from approvals a join sessions s on s.id=a.session_id and s.runtime_id=a.runtime_id and s.state not in ('archived','unavailable')
		 join runtimes r on r.id=a.runtime_id and r.revoked_at is null and r.epoch=a.runtime_epoch and r.connection_id=a.connection_id and `+runtimeEnrollmentApprovedSQL+`
		 join installations i on i.id=r.installation_id and i.revoked_at is null
		 join hosts h on h.id=i.host_id and h.state='active'
		 join runtime_grants g on g.runtime_id=r.id and g.role='owner' and g.revoked_at is null and (g.expires_at is null or g.expires_at>clock_timestamp())
		 join push_bindings b on b.org_id=h.org_id and b.user_id=g.user_id and b.provider_project=$1 and b.state='active' and b.expires_at>clock_timestamp()
		 join devices d on d.id=b.device_id and d.user_id=b.user_id and d.revoked_at is null and d.key_version=b.device_key_version and d.proof_key_thumbprint=b.proof_key_jkt
		 join users u on u.id=b.user_id and u.status='active' and u.issuer=$2
		 join org_memberships m on m.user_id=u.id and m.org_id=h.org_id
		 left join push_deliveries previous on previous.binding_id=b.id and previous.kind='approval' and previous.source_id=a.id
		 where a.metadata_version=1 and a.state='pending' and a.expires_at>clock_timestamp()+interval '1 second'
		 and g.scope->'actions' @> '["session.read","approval.decide"]'::jsonb
		 and (g.scope->'workspaces' ? a.workspace_id::text or g.scope->'sessions' ? a.session_id::text)
		 and (previous.id is null or previous.state='expired' and previous.error_code='authority_changed' and previous.grant_version<>g.grant_version)
		 order by a.created_at,a.id,b.id limit 128
		 on conflict(binding_id,kind,source_id) do update set state='queued',grant_version=excluded.grant_version,next_attempt_at=clock_timestamp(),error_code=null,updated_at=clock_timestamp()
		 where push_deliveries.state='expired' and push_deliveries.error_code='authority_changed' and push_deliveries.grant_version<>excluded.grant_version`, store.project, store.issuer)
		if err != nil {
			return push.ErrUnavailable
		}
	}
	// Fixed retention for transport metadata; interaction/control records keep their own policy.
	_, err = tx.ExecContext(ctx, `insert into push_deliveries(binding_id,kind,source_id,runtime_id,runtime_epoch,session_id,grant_version,expires_at)
	 select b.id,q.kind,q.id,q.runtime_id,q.runtime_epoch,q.session_id,g.grant_version,
	 case when q.kind='question' then least(q.expires_at,clock_timestamp()+interval '10 minutes') else clock_timestamp()+interval '10 minutes' end
	 from question_references q join sessions s on s.id=q.session_id and s.runtime_id=q.runtime_id and s.state not in ('archived','unavailable')
	 join runtimes r on r.id=q.runtime_id and r.revoked_at is null and r.epoch=q.runtime_epoch and r.connection_id=q.connection_id
	 and r.last_seen_at>clock_timestamp()-interval '45 seconds' and `+runtimeEnrollmentApprovedSQL+`
	 join question_reference_feeds f on f.runtime_id=r.id and f.runtime_epoch=q.runtime_epoch and f.connection_id=q.connection_id
	 and f.key_version=r.connection_key_version and f.updated_at<=clock_timestamp() and f.lease_until>clock_timestamp()
	 join installations i on i.id=r.installation_id and i.revoked_at is null
	 join hosts h on h.id=i.host_id and h.state='active'
	 join runtime_grants g on g.runtime_id=r.id and g.role in ('owner','operator') and g.revoked_at is null and (g.expires_at is null or g.expires_at>clock_timestamp())
	 join push_bindings b on b.org_id=h.org_id and b.user_id=g.user_id and b.provider_project=$1 and b.state='active' and b.expires_at>clock_timestamp()
	 join devices d on d.id=b.device_id and d.user_id=b.user_id and d.revoked_at is null and d.key_version=b.device_key_version and d.proof_key_thumbprint=b.proof_key_jkt
	 join users u on u.id=b.user_id and u.status='active' and u.issuer=$2
	 join org_memberships m on m.user_id=u.id and m.org_id=h.org_id
	 left join push_deliveries previous on previous.binding_id=b.id and previous.kind=q.kind and previous.source_id=q.id
	 where q.state in ('pending','continued') and (q.expires_at is null or q.expires_at>clock_timestamp()+interval '1 second')
	 and g.scope->'actions' @> '["session.read","question.answer"]'::jsonb
	 and (g.scope->'workspaces' ? s.workspace_id::text or g.scope->'sessions' ? q.session_id::text)
	 and (previous.id is null or previous.state='expired' and previous.error_code='authority_changed' and previous.expires_at>clock_timestamp())
	 order by q.created_at,q.id,b.id limit 128
	 on conflict(binding_id,kind,source_id) do update set state='queued',grant_version=excluded.grant_version,next_attempt_at=clock_timestamp(),error_code=null,updated_at=clock_timestamp()
	 where push_deliveries.state='expired' and push_deliveries.error_code='authority_changed' and push_deliveries.expires_at>clock_timestamp()`, store.project, store.issuer)
	if err != nil {
		return push.ErrUnavailable
	}
	if _, err = tx.ExecContext(ctx, `delete from push_receipts where notification_id in (select id from push_deliveries where expires_at<clock_timestamp()-interval '7 days')`); err != nil {
		return push.ErrUnavailable
	}
	if _, err = tx.ExecContext(ctx, `delete from push_deliveries where expires_at<clock_timestamp()-interval '7 days'`); err != nil {
		return push.ErrUnavailable
	}
	if _, err = tx.ExecContext(ctx, `delete from push_bindings where state in ('disabled','expired') and expires_at<clock_timestamp()-interval '7 days' and not exists(select 1 from push_deliveries where binding_id=push_bindings.id)`); err != nil {
		return push.ErrUnavailable
	}
	if tx.Commit() != nil {
		return push.ErrUnavailable
	}
	return nil
}
func (store *PushStore) Claim(ctx context.Context) (*push.Claim, error) {
	tx, err := store.database.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, push.ErrUnavailable
	}
	defer tx.Rollback()
	var id string
	err = tx.QueryRowContext(ctx, `select id::text from push_deliveries where expires_at>clock_timestamp() and attempts<8 and
	 ((state in ('queued','retry') and next_attempt_at<=clock_timestamp()) or (state='leased' and lease_until<=clock_timestamp())) order by next_attempt_at,created_at,id for update skip locked limit 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, push.ErrUnavailable
	}
	lease, err := pushUUID()
	if err != nil {
		return nil, err
	}
	var claim push.Claim
	err = tx.QueryRowContext(ctx, `update push_deliveries set state='leased',lease_id=$2,lease_until=least(expires_at,clock_timestamp()+interval '20 seconds'),attempts=attempts+1,updated_at=clock_timestamp()
	 where id=$1 returning id::text,lease_id::text,binding_id::text,kind,expires_at`, id, lease).Scan(&claim.ID, &claim.LeaseID, &claim.BindingID, &claim.Kind, &claim.ExpiresAt)
	if err != nil || tx.Commit() != nil {
		return nil, push.ErrUnavailable
	}
	return &claim, nil
}

type pushWork struct {
	binding                         pushBinding
	source, runtime, epoch, session string
	grant                           int64
	nonce                           []byte
	expiry                          time.Time
}

func (store *PushStore) work(ctx context.Context, claim push.Claim) (pushWork, error) {
	var work pushWork
	if !push.UUID(claim.ID) || !push.UUID(claim.LeaseID) || !push.UUID(claim.BindingID) {
		return work, push.ErrLease
	}
	b, err := scanPushBinding(store.database.DB.QueryRowContext(ctx, `select `+pushBindingColumns+` from push_bindings b
	 join devices d on d.id=b.device_id and d.user_id=b.user_id and d.key_version=b.device_key_version and d.proof_key_thumbprint=b.proof_key_jkt and d.revoked_at is null
	 join users u on u.id=b.user_id and u.status='active' and u.issuer=$2 join org_memberships m on m.user_id=u.id and m.org_id=b.org_id
	 where b.id=$1 and b.provider_project=$3 and b.created_at<=clock_timestamp() and b.expires_at>clock_timestamp()`, claim.BindingID, store.issuer, store.project))
	if errors.Is(err, sql.ErrNoRows) {
		return work, push.ErrAccess
	}
	if err != nil {
		return work, push.ErrUnavailable
	}
	work.binding = b
	var source, runtime, epoch, session sql.NullString
	var grant sql.NullInt64
	err = store.database.DB.QueryRowContext(ctx, `select source_id::text,runtime_id::text,runtime_epoch::text,session_id::text,grant_version,nonce_ciphertext,expires_at from push_deliveries
	 where id=$1 and binding_id=$2 and lease_id=$3 and state='leased' and kind=$4 and lease_until>clock_timestamp() and expires_at>clock_timestamp() and created_at<=clock_timestamp()`, claim.ID, claim.BindingID, claim.LeaseID, claim.Kind).Scan(&source, &runtime, &epoch, &session, &grant, &work.nonce, &work.expiry)
	if errors.Is(err, sql.ErrNoRows) {
		return work, push.ErrLease
	}
	if err != nil {
		return work, push.ErrUnavailable
	}
	work.source, work.runtime, work.epoch, work.session, work.grant = source.String, runtime.String, epoch.String, session.String, grant.Int64
	if claim.Kind == "challenge" {
		if b.State != "pending" || !b.ChallengeExpiry.After(time.Now()) {
			return work, push.ErrExpired
		}
	} else if claim.Kind == "approval" && store.approvals != nil && b.State == "active" {
		var raw []byte
		var version int64
		err = store.database.DB.QueryRowContext(ctx, `select g.scope,g.grant_version from runtime_grants g join runtimes r on r.id=g.runtime_id join installations i on i.id=r.installation_id join hosts h on h.id=i.host_id where g.runtime_id=$1 and g.user_id=$2 and h.org_id=$3 and g.role='owner' and g.revoked_at is null and (g.expires_at is null or g.expires_at>clock_timestamp())`, work.runtime, b.User, b.Org).Scan(&raw, &version)
		if errors.Is(err, sql.ErrNoRows) {
			return work, push.ErrAccess
		}
		if err != nil {
			return work, push.ErrUnavailable
		}
		var scope GrantScope
		if json.Unmarshal(raw, &scope) != nil || version != work.grant {
			return work, push.ErrAccess
		}
		scope.Actions = []string{"session.read", "approval.decide"}
		status, err := store.approvals.AuthorizeView(ctx, TicketRedemption{UserID: b.User, DeviceID: b.Device, DeviceKeyVersion: b.KeyVersion, ProofKeyThumbprint: b.JKT, RuntimeID: work.runtime, GrantVersion: version, Scope: scope}, work.source)
		if errors.Is(err, ErrDatabaseUnavailable) {
			return work, push.ErrUnavailable
		}
		if err != nil || status.State != "pending" || status.RuntimeEpoch != work.epoch || status.SessionID != work.session {
			return work, push.ErrAccess
		}
	} else if (claim.Kind == "question" || claim.Kind == "timed_question") && b.State == "active" {
		scope, version, err := store.questionGrant(ctx, b, work.runtime)
		if err != nil {
			return work, err
		}
		if version != work.grant {
			return work, push.ErrAccess
		}
		status, err := store.database.AuthorizeQuestionReference(ctx, TicketRedemption{UserID: b.User, DeviceID: b.Device, DeviceKeyVersion: b.KeyVersion, ProofKeyThumbprint: b.JKT, RuntimeID: work.runtime, GrantVersion: version, Scope: scope}, work.source)
		if errors.Is(err, ErrDatabaseUnavailable) {
			return work, push.ErrUnavailable
		}
		if err != nil || status.Kind != claim.Kind || status.SessionID != work.session || status.RuntimeEpoch != work.epoch {
			return work, push.ErrAccess
		}
		if status.Availability == "state_unavailable" {
			return work, push.ErrUnavailable
		}
		if status.Availability != "online" || status.State != "pending" && status.State != "continued" {
			return work, push.ErrAccess
		}
	} else {
		return work, push.ErrAccess
	}
	return work, nil
}
func (store *PushStore) Authorize(ctx context.Context, claim push.Claim) (push.Outbound, error) {
	work, err := store.work(ctx, claim)
	if err != nil {
		return push.Outbound{}, err
	}
	address, err := store.cipher.Open(work.binding.Address, work.binding.aad())
	if err != nil {
		return push.Outbound{}, push.ErrUnavailable
	}
	defer clear(address)
	if !push.FID(string(address)) {
		return push.Outbound{}, push.ErrUnavailable
	}
	out := push.Outbound{Provider: "fcm", Address: string(address), BindingID: claim.BindingID, Kind: claim.Kind, ExpiresAt: work.expiry}
	if claim.Kind == "challenge" {
		nonce, err := store.cipher.Open(work.nonce, work.binding.aad()+"\x00challenge\x00"+claim.ID)
		if err != nil {
			return push.Outbound{}, push.ErrUnavailable
		}
		defer clear(nonce)
		if !push.Secret(string(nonce)) || push.SecretHash(string(nonce)) != work.binding.ChallengeHash {
			return push.Outbound{}, push.ErrUnavailable
		}
		out.Challenge = string(nonce)
	} else {
		out.NotificationID = claim.ID
	}
	return out, nil
}
func (store *PushStore) Recheck(ctx context.Context, claim push.Claim) error {
	_, err := store.work(ctx, claim)
	return err
}
func (store *PushStore) Complete(ctx context.Context, claim push.Claim, result push.Result) error {
	started := time.Now()
	err := store.complete(ctx, claim, result)
	store.observePushOperation(ctx, "complete", started, err)
	return err
}

func (store *PushStore) complete(ctx context.Context, claim push.Claim, result push.Result) error {
	if !push.UUID(claim.ID) || !push.UUID(claim.BindingID) || !push.UUID(claim.LeaseID) {
		return push.ErrLease
	}
	if result.State != push.Accepted && result.State != push.Retry && result.State != push.InvalidEndpoint && result.State != push.Failed && result.State != push.Expired {
		return push.ErrInvalid
	}
	if result.ProviderID != "" && !push.Digest(result.ProviderID) {
		return push.ErrInvalid
	}
	tx, err := store.database.DB.BeginTx(ctx, nil)
	if err != nil {
		return push.ErrUnavailable
	}
	defer tx.Rollback()
	b, err := scanPushBinding(tx.QueryRowContext(ctx, `select `+pushBindingColumns+` from push_bindings b where b.id=$1 for update`, claim.BindingID))
	if err != nil {
		return push.ErrUnavailable
	}
	var state, lease, kind string
	var attempts int
	var expires, createdAt time.Time
	err = tx.QueryRowContext(ctx, `select state,coalesce(lease_id::text,''),attempts,expires_at,created_at,kind from push_deliveries where id=$1 and binding_id=$2 for update`, claim.ID, claim.BindingID).Scan(&state, &lease, &attempts, &expires, &createdAt, &kind)
	if err != nil {
		return push.ErrUnavailable
	}
	if state != "leased" || lease != claim.LeaseID {
		return push.ErrLease
	}
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return push.ErrUnavailable
	}
	next := now
	if result.State == push.Retry {
		wait := max(result.RetryAfter, time.Duration(1<<min(attempts, 8))*time.Second)
		next = now.Add(min(wait, time.Hour))
		if !next.Before(expires) || attempts >= 8 {
			result.State = push.Expired
			result.Code = "expired"
		}
	}
	if result.State == push.InvalidEndpoint {
		result.State = push.Failed
		if _, err = tx.ExecContext(ctx, `update push_bindings set state='disabled',address_ciphertext=null where id=$1`, b.ID); err != nil {
			return push.ErrUnavailable
		}
	}
	var updatedAt time.Time
	if err = tx.QueryRowContext(ctx, `update push_deliveries set state=$2,next_attempt_at=$3,provider_message_sha256=nullif($4,''),error_code=nullif($5,''),nonce_ciphertext=case when $2='retry' or (kind='challenge' and $2='provider_accepted') then nonce_ciphertext else null end,updated_at=clock_timestamp() where id=$1 returning updated_at`, claim.ID, result.State, next, result.ProviderID, result.Code).Scan(&updatedAt); err != nil {
		return push.ErrUnavailable
	}
	if pushAudit(ctx, tx, b, "push.delivery", result.State, map[string]any{"notification_id": claim.ID, "kind": claim.Kind, "attempt": attempts, "code": result.Code}) != nil || tx.Commit() != nil {
		return push.ErrUnavailable
	}
	store.database.push.metrics.PushDelivery(kind, result.State, result.Code, createdAt, updatedAt)
	return nil
}
