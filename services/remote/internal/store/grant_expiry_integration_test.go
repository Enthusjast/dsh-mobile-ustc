package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestGrantWriteCannotOutliveManagerExpiryDuringTargetLockWait(t *testing.T) {
	for _, operation := range []string{"put", "delete", "same-put", "same-delete"} {
		t.Run(operation, func(t *testing.T) {
			ctx, db := newPostgresIntegrationDatabase(t)
			proof := seedGrantFixture(t, ctx, db.DB)
			actor := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
			input := RuntimeGrantInput{Role: "viewer", Scope: GrantScope{Actions: []string{"host.list"}, Workspaces: []string{}, Sessions: []string{}}}
			if _, err := db.PutRuntimeGrant(ctx, actor, managingDevice, proof, directoryRuntime, directoryTarget, input); err != nil {
				t.Fatal(err)
			}
			if operation == "same-delete" {
				if _, err := db.RevokeRuntimeGrant(ctx, actor, managingDevice, proof, directoryRuntime, directoryTarget); err != nil {
					t.Fatal(err)
				}
			}
			if operation == "put" {
				input.Scope.Actions = []string{"command.status"}
			}
			gate, err := db.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.Rollback()
			if _, err := gate.ExecContext(ctx, `select 1 from runtime_grants where runtime_id=$1 and user_id=$2 for update`, directoryRuntime, directoryTarget); err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB.ExecContext(ctx, `update runtime_grants set expires_at=clock_timestamp()+interval '500 milliseconds' where runtime_id=$1 and user_id=$2`, directoryRuntime, directoryOwner); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				var err error
				if operation == "delete" || operation == "same-delete" {
					_, err = db.RevokeRuntimeGrant(ctx, actor, managingDevice, proof, directoryRuntime, directoryTarget)
				} else {
					_, err = db.PutRuntimeGrant(ctx, actor, managingDevice, proof, directoryRuntime, directoryTarget, input)
				}
				result <- err
			}()
			waitForGrantLock(t, ctx, db, "grant_target_fence")
			var expires time.Time
			if err := db.DB.QueryRowContext(ctx, `select expires_at from runtime_grants where runtime_id=$1 and user_id=$2`, directoryRuntime, directoryOwner).Scan(&expires); err != nil {
				t.Fatal(err)
			}
			waitForGrantDatabaseExpiry(t, ctx, db, expires)
			if err := gate.Commit(); err != nil {
				t.Fatal(err)
			}
			if err := <-result; !errors.Is(err, ErrAccessDenied) {
				t.Fatal("expired management authority survived a target lock wait", err)
			}
			version, revoked, changes := int64(1), false, 1
			if operation == "same-delete" {
				version, revoked, changes = 2, true, 2
			}
			if err := assertGrantState(ctx, db.DB, directoryRuntime, directoryTarget, version, "viewer", revoked); err != nil {
				t.Fatal(err)
			}
			if err := assertChangeCounts(ctx, db.DB, changes, changes); err != nil {
				t.Fatal("expired write changed audit/outbox", err)
			}
		})
	}
}

func waitForGrantDatabaseExpiry(t *testing.T, ctx context.Context, db *Postgres, expires time.Time) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var expired bool
		if err := db.DB.QueryRowContext(ctx, `select clock_timestamp()>=$1`, expires).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if expired {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("grant fixture did not expire")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestGrantWriteRechecksExpiryAfterAuditWait(t *testing.T) {
	for _, kind := range []string{"manager", "candidate", "admin"} {
		t.Run(kind, func(t *testing.T) {
			ctx, db := newPostgresIntegrationDatabase(t)
			proof := seedGrantFixture(t, ctx, db.DB)
			actor := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
			if kind == "admin" {
				if _, err := db.DB.ExecContext(ctx, `update org_memberships set role='admin' where user_id=$1`, directoryOwner); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.DB.ExecContext(ctx, `create function hold_grant_expiry_audit() returns trigger language plpgsql as $$ begin
    if new.action='runtime_grant.update' then perform pg_advisory_xact_lock(426947);end if;return new;end $$;
    create trigger hold_grant_expiry_audit before insert on audit_log for each row execute function hold_grant_expiry_audit()`); err != nil {
				t.Fatal(err)
			}
			gate, err := db.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.Rollback()
			if _, err := gate.ExecContext(ctx, `select pg_advisory_xact_lock(426947)`); err != nil {
				t.Fatal(err)
			}
			var expires time.Time
			if err := db.DB.QueryRowContext(ctx, `select clock_timestamp()+interval '500 milliseconds'`).Scan(&expires); err != nil {
				t.Fatal(err)
			}
			input := RuntimeGrantInput{Role: "viewer", Scope: GrantScope{Actions: []string{"host.list"}, Workspaces: []string{}, Sessions: []string{}}}
			if kind == "candidate" {
				input.ExpiresAt = &expires
			} else {
				if _, err := db.DB.ExecContext(ctx, `update runtime_grants set expires_at=$1 where runtime_id=$2 and user_id=$3`, expires, directoryRuntime, directoryOwner); err != nil {
					t.Fatal(err)
				}
			}
			result := make(chan error, 1)
			go func() {
				_, err := db.PutRuntimeGrant(ctx, actor, managingDevice, proof, directoryRuntime, directoryTarget, input)
				result <- err
			}()
			waitForGrantLock(t, ctx, db, "insert into audit_log")
			waitForGrantDatabaseExpiry(t, ctx, db, expires)
			if err := gate.Commit(); err != nil {
				t.Fatal(err)
			}
			err = <-result
			if kind == "admin" {
				if err != nil {
					t.Fatal("current admin was incorrectly bound to its expired owner grant", err)
				}
				if err := assertGrantState(ctx, db.DB, directoryRuntime, directoryTarget, 1, "viewer", false); err != nil {
					t.Fatal(err)
				}
				if err := assertChangeCounts(ctx, db.DB, 1, 1); err != nil {
					t.Fatal(err)
				}
				return
			}
			want := ErrAccessDenied
			if kind == "candidate" {
				want = ErrGrantInvalid
			}
			if !errors.Is(err, want) {
				t.Fatal("expired authority/candidate committed after audit wait", err)
			}
			var rows int
			if err := db.DB.QueryRowContext(ctx, `select count(*) from runtime_grants where user_id=$1`, directoryTarget).Scan(&rows); err != nil || rows != 0 {
				t.Fatal("failed expiry check left grant data", rows, err)
			}
			if err := assertChangeCounts(ctx, db.DB, 0, 0); err != nil {
				t.Fatal("failed expiry check left audit/outbox", err)
			}
		})
	}
}

func TestGrantWriteExpiryCheckPreservesAuthorizedSelfRemoval(t *testing.T) {
	for _, operation := range []string{"put", "delete"} {
		t.Run(operation, func(t *testing.T) {
			ctx, db := newPostgresIntegrationDatabase(t)
			proof := seedGrantFixture(t, ctx, db.DB)
			actor := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
			if _, err := db.DB.ExecContext(ctx, `insert into runtime_grants(runtime_id,user_id,role,scope,granted_by) values($1,$2,'owner','{"actions":["grant.manage"],"workspaces":[],"sessions":[]}',$3)`, directoryRuntime, directoryTarget, directoryOwner); err != nil {
				t.Fatal(err)
			}
			var err error
			if operation == "delete" {
				_, err = db.RevokeRuntimeGrant(ctx, actor, managingDevice, proof, directoryRuntime, directoryOwner)
			} else {
				_, err = db.PutRuntimeGrant(ctx, actor, managingDevice, proof, directoryRuntime, directoryOwner, RuntimeGrantInput{Role: "viewer", Scope: GrantScope{Actions: []string{"host.list"}, Workspaces: []string{}, Sessions: []string{}}})
			}
			if err != nil {
				t.Fatal("legitimate self-removal lost its original management authority", err)
			}
			role, revoked := "viewer", false
			if operation == "delete" {
				role, revoked = "owner", true
			}
			if err := assertGrantState(ctx, db.DB, directoryRuntime, directoryOwner, 2, role, revoked); err != nil {
				t.Fatal(err)
			}
			if err := assertChangeCounts(ctx, db.DB, 1, 1); err != nil {
				t.Fatal(err)
			}
		})
	}
}
