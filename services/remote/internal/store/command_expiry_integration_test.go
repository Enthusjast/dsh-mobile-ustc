package store

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func commandDeadlineFixture(t *testing.T) (context.Context, *Postgres, TicketRedemption) {
	t.Helper()
	ctx, db := newPostgresIntegrationDatabase(t)
	proof := seedGrantFixture(t, ctx, db.DB)
	if _, err := db.DB.ExecContext(ctx, `update runtime_grants set scope=jsonb_set(scope,'{actions}','["message.submit","session.cancel","session.archive","session.model.select","question.answer","session.create","session.read","grant.manage"]'::jsonb)`); err != nil {
		t.Fatal(err)
	}
	return ctx, db, TicketRedemption{UserID: directoryOwner, DeviceID: managingDevice, DeviceKeyVersion: 1, ProofKeyThumbprint: proof, RuntimeID: directoryRuntime, GrantVersion: 1,
		Scope: GrantScope{Actions: []string{"message.submit", "session.cancel", "session.archive", "session.model.select", "question.answer", "session.create", "session.read"}, Workspaces: []string{"77777777-7777-4777-8777-777777777777"}, Sessions: []string{}}}
}

func TestCommandGrantExpiryCannotSurviveResourceCommandOrAuditWaits(t *testing.T) {
	for _, action := range []string{"message.submit", "session.cancel", "session.archive", "session.model.select", "question.answer", "session.create"} {
		for _, wait := range []string{"resource", "command", "audit"} {
			t.Run(action+"/"+wait, func(t *testing.T) {
				ctx, db, ticket := commandDeadlineFixture(t)
				request, digest := approvalTestUUID(t), strings.Repeat("a", 64)
				admit := func() (CommandStatus, error) {
					if action == "session.create" {
						return db.RecordRealtimeSessionCreate(ctx, ticket, request, ticket.Scope.Workspaces[0], digest)
					}
					return db.RecordRealtimeCommand(ctx, ticket, action, request, "99999999-9999-4999-8999-999999999999", digest)
				}
				if wait == "command" {
					if _, err := admit(); err != nil {
						t.Fatal(err)
					}
				}
				if wait == "audit" {
					if _, err := db.DB.ExecContext(ctx, `create function hold_command_deadline_audit() returns trigger language plpgsql as $$ begin
				 if new.action='command.received' then perform pg_advisory_xact_lock(426963);end if;return new;end $$;
				 create trigger hold_command_deadline_audit before insert on audit_log for each row execute function hold_command_deadline_audit()`); err != nil {
						t.Fatal(err)
					}
				}
				gate, err := db.DB.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer gate.Rollback()
				query, fragment := `select pg_advisory_xact_lock(426963)`, "insert into audit_log"
				if wait == "resource" {
					query = `select 1 from sessions where id='99999999-9999-4999-8999-999999999999' for update`
					fragment = "for share of u, d, m, h, i, r, g, s"
					if action == "session.create" {
						query = `select 1 from workspaces where id='77777777-7777-4777-8777-777777777777' for update`
						fragment = "for share of u, d, m, h, i, r, g, w"
					}
				} else if wait == "command" {
					query = `select 1 from commands where request_id='` + request + `' for update`
					fragment = "from commands where device_id = $1 and request_id = $2 for update"
				}
				if _, err := gate.ExecContext(ctx, query); err != nil {
					t.Fatal(err)
				}
				var expires time.Time
				if err := db.DB.QueryRowContext(ctx, `update runtime_grants set expires_at=clock_timestamp()+interval '600 milliseconds' returning expires_at`).Scan(&expires); err != nil {
					t.Fatal(err)
				}
				result := make(chan error, 1)
				go func() { _, err := admit(); result <- err }()
				waitForGrantLock(t, ctx, db, fragment)
				waitForGrantDatabaseExpiry(t, ctx, db, expires)
				if err := gate.Commit(); err != nil {
					t.Fatal(err)
				}
				if err := <-result; !errors.Is(err, ErrAccessDenied) {
					t.Fatal("expired grant admitted command after wait", err)
				}
				var commands, audits int
				if err := db.DB.QueryRowContext(ctx, `select (select count(*) from commands where request_id=$1),(select count(*) from audit_log where action='command.received' and metadata->>'request_id'=$1::text)`, request).Scan(&commands, &audits); err != nil {
					t.Fatal(err)
				}
				want := 0
				if wait == "command" {
					want = 1
				}
				if commands != want || audits != want {
					t.Fatal("expired admission changed command evidence", commands, audits, want)
				}
			})
		}
	}
}

func TestCommandExpiryAfterFileReadinessWaitRollsBackReferencesAndAudit(t *testing.T) {
	h := newMessageFileFixture(t)
	h.stage(t, h.file)
	var expires time.Time
	if err := h.database.DB.QueryRowContext(h.ctx, `update runtime_grants set expires_at=clock_timestamp()+interval '600 milliseconds' returning expires_at`).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	resume := func() { once.Do(func() { close(release) }) }
	defer resume()
	request := approvalTestUUID(t)
	result := make(chan error, 1)
	go func() {
		calls := 0
		_, err := h.database.RecordRealtimeFileCommand(h.ctx, h.ticket, h.host, request, h.file.SessionID, strings.Repeat("a", 64), fileTestPolicy, []string{h.file.ID}, func() bool {
			calls++
			if calls == 2 {
				close(entered)
				<-release
			}
			return true
		})
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("file readiness recheck was not reached")
	}
	waitForGrantDatabaseExpiry(t, h.ctx, h.database, expires)
	resume()
	if err := <-result; !errors.Is(err, ErrAccessDenied) {
		t.Fatal("expired command retained new file authority", err)
	}
	var commands, refs, audits int
	if err := h.database.DB.QueryRowContext(h.ctx, `select (select count(*) from commands),(select count(*) from file_message_refs),(select count(*) from audit_log where action in('command.received','file.message_bound'))`).Scan(&commands, &refs, &audits); err != nil || commands != 0 || refs != 0 || audits != 0 {
		t.Fatal("late expiry committed file admission", commands, refs, audits, err)
	}
}

func TestCommandAdmissionDoesNotReuseSpentTicketDeadlineOrRejectCurrentHostFacts(t *testing.T) {
	ctx, db, ticket := commandDeadlineFixture(t)
	ticket.ExpiresAt = time.Now().Add(-time.Minute)
	if _, err := db.RecordRealtimeCommand(ctx, ticket, "message.submit", approvalTestUUID(t), "99999999-9999-4999-8999-999999999999", strings.Repeat("a", 64)); err != nil {
		t.Fatal("admission ticket deadline replaced established connection lease", err)
	}
	if _, err := db.RecordRealtimeSessionCreate(ctx, ticket, approvalTestUUID(t), ticket.Scope.Workspaces[0], strings.Repeat("b", 64)); err != nil {
		t.Fatal("spent ticket deadline blocked new session intent", err)
	}
	h := newMessageFileFixture(t)
	request := approvalTestUUID(t)
	if _, err := h.database.RecordRealtimeCommand(h.ctx, h.ticket, "message.submit", request, h.file.SessionID, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.database.DB.ExecContext(h.ctx, `update runtime_grants set expires_at=clock_timestamp()-interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	receipt := fixtureReceipt(h, request)
	for _, state := range []string{"host_accepted", "dispatching", "settled"} {
		receipt.State = state
		if _, err := h.database.RecordRealtimeCommandReceipt(h.ctx, receipt); err != nil {
			t.Fatal("current Host could not record an existing command fact", state, err)
		}
	}
}
