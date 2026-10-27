package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestUnknownResultsReadCurrentRowsAndDecreaseAfterReconciliation(t *testing.T) {
	f := newApprovalFixture(t)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := f.database.DB.ExecContext(f.ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	check := func(commands, approvals int64) {
		t.Helper()
		counts, err := f.database.UnknownResults(f.ctx)
		if err != nil || counts.Commands != commands || counts.Approvals != approvals {
			t.Fatal("snapshot differs from current durable rows", counts, err)
		}
	}
	check(0, 0)
	for _, state := range []string{"outcome_unknown", "outcome_unknown", "settled"} {
		exec(`insert into commands(device_id,request_id,user_id,runtime_id,session_id,payload_sha256,state) values($1,$2,$3,$4,$5,$6,$7)`, f.ticket.DeviceID, approvalTestUUID(t), f.ticket.UserID, f.ticket.RuntimeID, f.request.SessionID, strings.Repeat("a", 64), state)
	}
	status := acceptResultFixture(t, f, "allow_once")
	for _, state := range []string{"consumed", "outcome_unknown"} {
		current, err := f.control.RecordResult(f.ctx, f.connection, 1, resultFor(status, state, ""))
		if err != nil {
			t.Fatal(err)
		}
		status = current
	}
	// Retained legacy/recovery rows remain visible even without executable v1 metadata.
	legacy := approvalTestUUID(t)
	exec(`insert into approvals(id,session_id,runtime_epoch,execution_id,binding_sha256,policy_version,state,expires_at) values($1,$2,$3,$4,$5,1,'outcome_unknown',clock_timestamp()+interval '1 hour')`, legacy, f.request.SessionID, approvalTestUUID(t), approvalTestUUID(t), strings.Repeat("b", 64))
	check(2, 2)
	tx, err := f.database.DB.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(f.ctx, `update commands set state='rejected';update approvals set state='invalidated' where metadata_version=0`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	check(2, 2)
	exec(`update commands set state='rejected' where state='outcome_unknown'`)
	if _, err := f.control.RecordResult(f.ctx, f.connection, 1, resultFor(status, "settled", "succeeded")); err != nil {
		t.Fatal(err)
	}
	check(0, 1)
	exec(`delete from approvals where id=$1`, legacy)
	check(0, 0)

	locked, err := f.database.DB.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer locked.Rollback()
	if _, err := locked.ExecContext(f.ctx, `lock table commands in access exclusive mode`); err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(f.ctx, 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := f.database.UnknownResults(bounded); !errors.Is(err, ErrDatabaseUnavailable) || bounded.Err() == nil {
		t.Fatal("blocked database snapshot ignored its deadline", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("blocked read did not release promptly")
	}
}
