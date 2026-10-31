package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// ExpireApprovals records negative lifecycle facts without a new Host request.
// It never restores callbacks, issues permission, or guesses execution results.
// Every node may run it: runtime-first SKIP LOCKED claims preserve the admission
// lock order, and the state transition and both event sinks commit together.
func (consumer *ControlConsumer) ExpireApprovals(parent context.Context, limit int) (int, error) {
	if limit < 1 || limit > 128 {
		return 0, ErrGrantInvalid
	}
	ctx, cancel := context.WithTimeout(parent, time.Second)
	defer cancel()
	tx, err := consumer.postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if err := consumer.checkExpiryOwner(ctx, tx, false); err != nil {
		return 0, err
	}
	// Do not lock approvals before runtimes: attach/registration/result paths
	// take the runtime first. A busy runtime is left for a later bounded batch.
	rows, err := tx.QueryContext(ctx, `select r.id::text,h.org_id::text from runtimes r
	 join installations i on i.id=r.installation_id join hosts h on h.id=i.host_id
	 join lateral(select least(a.expires_at,coalesce(a.decision_expires_at,a.expires_at)) as deadline
	  from approvals a where a.runtime_id=r.id and a.metadata_version=1
	  and (a.state in ('pending','decision_received') or (a.state='allowed' and a.host_state='consumed'))
	  and least(a.expires_at,coalesce(a.decision_expires_at,a.expires_at))<=statement_timestamp()
	  order by least(a.expires_at,coalesce(a.decision_expires_at,a.expires_at)),a.id limit 1) expired on true
	 order by expired.deadline,r.id limit $1 for update of r skip locked`, limit)
	if err != nil {
		return 0, ErrDatabaseUnavailable
	}
	runtimes := []string{}
	orgs := map[string]string{}
	for rows.Next() {
		var runtimeID, orgID string
		if err := rows.Scan(&runtimeID, &orgID); err != nil {
			rows.Close()
			return 0, ErrDatabaseUnavailable
		}
		runtimes = append(runtimes, runtimeID)
		orgs[runtimeID] = orgID
	}
	readErr := rows.Err()
	rows.Close()
	if readErr != nil {
		return 0, ErrDatabaseUnavailable
	}
	if len(runtimes) == 0 {
		return 0, nil
	}
	rows, err = tx.QueryContext(ctx, `with previous as materialized (
	 select a.id,a.state as old_state from approvals a where a.runtime_id=any($1::uuid[]) and a.metadata_version=1
	 and (a.state in ('pending','decision_received') or (a.state='allowed' and a.host_state='consumed'))
	 and least(a.expires_at,coalesce(a.decision_expires_at,a.expires_at))<=clock_timestamp()
	 order by least(a.expires_at,coalesce(a.decision_expires_at,a.expires_at)),a.id limit $2 for update skip locked
	) update approvals a set state=case when a.state='decision_received' or a.host_state='consumed' then 'outcome_unknown' else 'expired' end
	 from previous p where a.id=p.id
	 returning a.id::text,a.runtime_id::text,a.runtime_epoch::text,a.session_id::text,a.execution_id::text,
	 a.binding_sha256,a.state,coalesce(a.decision,''),coalesce(a.decision_payload_sha256,''),a.expires_at,
	 coalesce(a.host_state,''),coalesce(a.execution_outcome,''),p.old_state`, runtimes, limit)
	if err != nil {
		return 0, ErrDatabaseUnavailable
	}
	ended := []endedApprovalObservation{}
	type expiryEvent struct {
		OrgID  string         `json:"org_id"`
		Status ApprovalStatus `json:"status"`
	}
	events := []expiryEvent{}
	for rows.Next() {
		var status ApprovalStatus
		var before string
		if err := rows.Scan(&status.ApprovalID, &status.RuntimeID, &status.RuntimeEpoch, &status.SessionID, &status.ExecutionID,
			&status.BindingSHA256, &status.State, &status.Decision, &status.PayloadSHA256, &status.ExpiresAt,
			&status.HostState, &status.Outcome, &before); err != nil {
			rows.Close()
			return 0, ErrDatabaseUnavailable
		}
		org, ok := orgs[status.RuntimeID]
		if !ok {
			rows.Close()
			return 0, ErrDatabaseUnavailable
		}
		ended = append(ended, endedApprovalObservation{before, status})
		events = append(events, expiryEvent{org, status})
	}
	readErr = rows.Err()
	rows.Close()
	if readErr != nil {
		return 0, ErrDatabaseUnavailable
	}
	raw, err := json.Marshal(events)
	if err != nil {
		return 0, ErrDatabaseUnavailable
	}
	for _, query := range []string{
		`insert into audit_log(org_id,actor_type,actor_id,runtime_id,session_id,action,result,metadata)
		 select (e->>'org_id')::uuid,'system','approval-lifecycle',(e->'status'->>'runtime_id')::uuid,
		 (e->'status'->>'session_id')::uuid,'approval.ended','success',e->'status' from jsonb_array_elements($1::jsonb) e`,
		`insert into control_outbox(org_id,topic,payload)
		 select (e->>'org_id')::uuid,'approval.ended',e->'status' from jsonb_array_elements($1::jsonb) e`,
	} {
		result, err := tx.ExecContext(ctx, query, string(raw))
		if err != nil {
			return 0, ErrDatabaseUnavailable
		}
		if count, err := result.RowsAffected(); err != nil || count != int64(len(ended)) {
			return 0, ErrDatabaseUnavailable
		}
	}
	if err := consumer.checkExpiryOwner(ctx, tx, true); err != nil {
		return 0, err
	}
	if tx.Commit() != nil {
		return 0, ErrDatabaseUnavailable
	}
	consumer.postgres.observeEndedApprovals("expiry", ended)
	return len(ended), nil
}

// A slow metadata batch must not pin the renewal/dispatcher row. The initial
// read checks authority; the final SHARE lock pins generation only through
// COMMIT. Admissions take consumer SHARE before runtime locks, so this final
// compatible lock does not invert their runtime/consumer lock order.
func (consumer *ControlConsumer) checkExpiryOwner(ctx context.Context, tx *sql.Tx, final bool) error {
	if _, err := lockRecoveryReady(ctx, tx, consumer.databaseEpoch); err != nil {
		return err
	}
	query := `select generation::text,lease_until from control_consumers where node_id=$1`
	if final {
		query += ` for share`
	}
	var generation string
	var until, now time.Time
	err := tx.QueryRowContext(ctx, query, consumer.node).Scan(&generation, &until)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrControlConsumerFenced
	}
	if err != nil {
		return ErrDatabaseUnavailable
	}
	if err := tx.QueryRowContext(ctx, `select clock_timestamp()`).Scan(&now); err != nil {
		return ErrDatabaseUnavailable
	}
	if generation != consumer.generation || !until.After(now) {
		return ErrControlConsumerFenced
	}
	return nil
}
