package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func waitForGrantLock(t *testing.T, ctx context.Context, db *Postgres, fragment string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := db.DB.QueryRowContext(ctx, `select exists(select 1 from pg_stat_activity
		 where datname=current_database() and pid<>pg_backend_pid() and wait_event_type='Lock' and query like $1)`, "%"+fragment+"%").Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected grant/device lock not observed", fragment)
}

func TestGrantActorProofRecheckedEvenForIdempotentWrites(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	proof := seedGrantFixture(t, ctx, db.DB)
	actor := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	input := RuntimeGrantInput{Role: "viewer", Scope: GrantScope{Actions: []string{"host.list"}, Workspaces: []string{}, Sessions: []string{}}}
	if _, err := db.PutRuntimeGrant(ctx, actor, managingDevice, proof, directoryRuntime, directoryTarget, input); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []struct{ device, key string }{
		{managingDevice, strings.Repeat("A", 43)},
		{"dddddddd-dddd-4ddd-8ddd-dddddddddddd", proof},
		{"88888888-8888-4888-8888-888888888888", proof},
	} {
		if _, err := db.PutRuntimeGrant(ctx, actor, invalid.device, invalid.key, directoryRuntime, directoryTarget, input); !errors.Is(err, ErrAccessDenied) {
			t.Fatal("idempotent PUT bypassed actor proof", err)
		}
		if _, err := db.RevokeRuntimeGrant(ctx, actor, invalid.device, invalid.key, directoryRuntime, directoryTarget); !errors.Is(err, ErrAccessDenied) {
			t.Fatal("DELETE bypassed actor proof", err)
		}
	}
	if _, err := db.RevokeRuntimeGrant(ctx, actor, managingDevice, proof, directoryRuntime, directoryTarget); err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeDevice(ctx, actor.Issuer, actor.Subject, managingDevice); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RevokeRuntimeGrant(ctx, actor, managingDevice, proof, directoryRuntime, directoryTarget); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("idempotent DELETE bypassed current device revocation", err)
	}
	if _, err := db.PutRuntimeGrant(ctx, actor, managingDevice, proof, directoryRuntime, directoryTarget, input); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("revoked device revived a grant", err)
	}
	if err := assertGrantState(ctx, db.DB, directoryRuntime, directoryTarget, 2, "viewer", true); err != nil {
		t.Fatal(err)
	}
}

func TestGrantWriteWaitingForDeviceRevocationRetriesAndDeniesStaleActor(t *testing.T) {
	for _, revokeGrant := range []bool{false, true} {
		name := "put"
		if revokeGrant {
			name = "delete"
		}
		t.Run(name, func(t *testing.T) {
			ctx, db := newPostgresIntegrationDatabase(t)
			proof := seedGrantFixture(t, ctx, db.DB)
			actor := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
			input := RuntimeGrantInput{Role: "viewer", Scope: GrantScope{Actions: []string{"host.list"}, Workspaces: []string{}, Sessions: []string{}}}
			if revokeGrant {
				if _, err := db.PutRuntimeGrant(ctx, actor, managingDevice, proof, directoryRuntime, directoryTarget, input); err != nil {
					t.Fatal(err)
				}
			}
			// Represents the successful HTTP middleware lookup before the race.
			if _, err := db.ActiveDevice(ctx, actor, proof); err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB.ExecContext(ctx, `create function hold_device_revoke_audit() returns trigger language plpgsql as $$ begin
			 if new.action='device.revoke' then perform pg_advisory_xact_lock(426945);end if;return new;end $$;
			 create trigger hold_device_revoke_audit before insert on audit_log for each row execute function hold_device_revoke_audit()`); err != nil {
				t.Fatal(err)
			}
			gate, err := db.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.Rollback()
			if _, err := gate.ExecContext(ctx, `select pg_advisory_xact_lock(426945)`); err != nil {
				t.Fatal(err)
			}
			deviceResult := make(chan error, 1)
			go func() { deviceResult <- db.RevokeDevice(ctx, actor.Issuer, actor.Subject, managingDevice) }()
			waitForGrantLock(t, ctx, db, "insert into audit_log")
			grantResult := make(chan error, 1)
			go func() {
				var err error
				if revokeGrant {
					_, err = db.RevokeRuntimeGrant(ctx, actor, managingDevice, proof, directoryRuntime, directoryTarget)
				} else {
					_, err = db.PutRuntimeGrant(ctx, actor, managingDevice, proof, directoryRuntime, directoryTarget, input)
				}
				grantResult <- err
			}()
			waitForGrantLock(t, ctx, db, "grant_actor_device_fence")
			if err := gate.Commit(); err != nil {
				t.Fatal(err)
			}
			if err := <-deviceResult; err != nil {
				t.Fatal(err)
			}
			if err := <-grantResult; !errors.Is(err, ErrAccessDenied) {
				t.Fatal("stale device snapshot survived confirmed-abort retry", err)
			}
			var audits, events, rows int
			if err := db.DB.QueryRowContext(ctx, `select
			 (select count(*) from audit_log where action like 'runtime_grant.%'),
			 (select count(*) from control_outbox where topic like 'runtime_grant.%'),
			 (select count(*) from runtime_grants where user_id=$1)`, directoryTarget).Scan(&audits, &events, &rows); err != nil {
				t.Fatal(err)
			}
			want := 0
			if revokeGrant {
				want = 1
				if err := assertGrantState(ctx, db.DB, directoryRuntime, directoryTarget, 1, "viewer", false); err != nil {
					t.Fatal(err)
				}
			}
			if audits != want || events != want || rows != want {
				t.Fatal("denied write left grant, audit or outbox changes", audits, events, rows)
			}
		})
	}
}

func TestGrantWriteHoldsActorDeviceUntilCommit(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	proof := seedGrantFixture(t, ctx, db.DB)
	actor := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	if _, err := db.DB.ExecContext(ctx, `create function hold_grant_write() returns trigger language plpgsql as $$ begin
	 perform pg_advisory_xact_lock(426946);return new;end $$;
	 create trigger hold_grant_write before insert on runtime_grants for each row execute function hold_grant_write()`); err != nil {
		t.Fatal(err)
	}
	gate, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback()
	if _, err := gate.ExecContext(ctx, `select pg_advisory_xact_lock(426946)`); err != nil {
		t.Fatal(err)
	}
	granted := make(chan error, 1)
	go func() {
		_, err := db.PutRuntimeGrant(ctx, actor, managingDevice, proof, directoryRuntime, directoryTarget, RuntimeGrantInput{Role: "viewer", Scope: GrantScope{Actions: []string{"host.list"}, Workspaces: []string{}, Sessions: []string{}}})
		granted <- err
	}()
	waitForGrantLock(t, ctx, db, "insert into runtime_grants")
	revoked := make(chan error, 1)
	go func() { revoked <- db.RevokeDevice(ctx, actor.Issuer, actor.Subject, managingDevice) }()
	waitForGrantLock(t, ctx, db, "update devices set revoked_at")
	if err := gate.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-granted; err != nil {
		t.Fatal(err)
	}
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	if _, err := db.RevokeRuntimeGrant(ctx, actor, managingDevice, proof, directoryRuntime, directoryTarget); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("completed device revoke allowed another grant write", err)
	}
	if err := assertGrantState(ctx, db.DB, directoryRuntime, directoryTarget, 1, "viewer", false); err != nil {
		t.Fatal("earlier committed grant was changed by device revocation", err)
	}
}

func TestGrantWriteRetriesOnlyConfirmedAbortsAndRollsBackFailedAudit(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	proof := seedGrantFixture(t, ctx, db.DB)
	actor := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	for _, query := range []string{
		`create sequence grant_audit_attempt`,
		`create function fail_grant_audit() returns trigger language plpgsql as $$ begin
		 if new.action like 'runtime_grant.%' and nextval('grant_audit_attempt')<=2 then
		 raise exception 'PRIVATE_GRANT_AUDIT' using errcode='40001';end if;return new;end $$`,
		`create trigger fail_grant_audit before insert on audit_log for each row execute function fail_grant_audit()`,
	} {
		if _, err := db.DB.ExecContext(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	input := RuntimeGrantInput{Role: "viewer", Scope: GrantScope{Actions: []string{"host.list"}, Workspaces: []string{}, Sessions: []string{}}}
	if version, err := db.PutRuntimeGrant(ctx, actor, managingDevice, proof, directoryRuntime, directoryTarget, input); err != nil || version != 1 {
		t.Fatal("confirmed aborted PUT was not retried as a whole transaction", version, err)
	}
	if err := assertChangeCounts(ctx, db.DB, 1, 1); err != nil {
		t.Fatal("aborted PUT left audit or events", err)
	}
	if _, err := db.DB.ExecContext(ctx, `alter sequence grant_audit_attempt restart with 1`); err != nil {
		t.Fatal(err)
	}
	if version, err := db.RevokeRuntimeGrant(ctx, actor, managingDevice, proof, directoryRuntime, directoryTarget); err != nil || version != 2 {
		t.Fatal("confirmed aborted DELETE repeated a version increment", version, err)
	}
	if err := assertChangeCounts(ctx, db.DB, 2, 2); err != nil {
		t.Fatal("aborted DELETE left audit or events", err)
	}
	// An ordinary audit failure must neither retry nor leave a revived grant.
	if _, err := db.DB.ExecContext(ctx, `alter sequence grant_audit_attempt restart with 1;
	 create or replace function fail_grant_audit() returns trigger language plpgsql as $$ begin
	 perform nextval('grant_audit_attempt');raise exception 'PRIVATE_GRANT_AUDIT';end $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.PutRuntimeGrant(ctx, actor, managingDevice, proof, directoryRuntime, directoryTarget, input); !errors.Is(err, ErrDatabaseUnavailable) || strings.Contains(err.Error(), "PRIVATE_GRANT_AUDIT") {
		t.Fatal("audit failure committed or leaked private details", err)
	}
	var attempts int
	if err := db.DB.QueryRowContext(ctx, `select last_value from grant_audit_attempt`).Scan(&attempts); err != nil || attempts != 1 {
		t.Fatal("ordinary audit failure was replayed", attempts, err)
	}
	if err := assertGrantState(ctx, db.DB, directoryRuntime, directoryTarget, 2, "viewer", true); err != nil {
		t.Fatal(err)
	}
	if err := assertChangeCounts(ctx, db.DB, 2, 2); err != nil {
		t.Fatal(err)
	}
}
