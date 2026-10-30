package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func ticketTimeFixture(t *testing.T) (context.Context, *Postgres, UserIdentity, GrantScope) {
	t.Helper()
	ctx, db := newPostgresIntegrationDatabase(t)
	seedGrantFixture(t, ctx, db.DB)
	return ctx, db, UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"},
		GrantScope{Actions: []string{"session.list"}, Workspaces: []string{"77777777-7777-4777-8777-777777777777"}, Sessions: []string{}}
}

func TestTicketGrantExpiryCannotSurviveAuthorityLockWait(t *testing.T) {
	for _, operation := range []string{"issue", "prepare", "consume", "lease"} {
		t.Run(operation, func(t *testing.T) {
			ctx, db, actor, scope := ticketTimeFixture(t)
			var ticket RealtimeTicket
			var lease TicketRedemption
			var err error
			if operation != "issue" {
				ticket, err = db.IssueRealtimeTicket(ctx, actor, managingDevice, directoryRuntime, scope)
				if err != nil {
					t.Fatal(err)
				}
			}
			if operation == "lease" {
				lease, err = db.ConsumeRealtimeTicket(ctx, ticket.Token)
				if err != nil {
					t.Fatal(err)
				}
			}
			gate, err := db.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.Rollback()
			if _, err := gate.ExecContext(ctx, `select 1 from runtimes where id=$1 for update`, directoryRuntime); err != nil {
				t.Fatal(err)
			}
			var expires time.Time
			if err := db.DB.QueryRowContext(ctx, `update runtime_grants set expires_at=clock_timestamp()+interval '500 milliseconds' where runtime_id=$1 returning expires_at`, directoryRuntime).Scan(&expires); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				var err error
				switch operation {
				case "issue":
					_, err = db.IssueRealtimeTicket(ctx, actor, managingDevice, directoryRuntime, scope)
				case "prepare":
					_, err = db.PrepareRealtimeTicket(ctx, ticket.Token)
				case "consume":
					_, err = db.ConsumeRealtimeTicket(ctx, ticket.Token)
				case "lease":
					err = db.ValidateRealtimeLease(ctx, lease)
				}
				result <- err
			}()
			fragment := "select g.scope"
			if operation == "issue" {
				fragment = "select h.org_id::text from runtimes r"
			}
			waitForGrantLock(t, ctx, db, fragment)
			waitForGrantDatabaseExpiry(t, ctx, db, expires)
			if err := gate.Commit(); err != nil {
				t.Fatal(err)
			}
			want := ErrTicketInvalid
			if operation == "issue" {
				want = ErrAccessDenied
			}
			if err := <-result; !errors.Is(err, want) {
				t.Fatal("expired grant survived the authority lock wait", err)
			}
			var rows, consumed int
			if err := db.DB.QueryRowContext(ctx, `select count(*),count(consumed_at) from realtime_tickets`).Scan(&rows, &consumed); err != nil {
				t.Fatal(err)
			}
			expectedRows, expectedConsumed := 1, 0
			if operation == "issue" {
				expectedRows = 0
			}
			if operation == "lease" {
				expectedConsumed = 1
			}
			if rows != expectedRows || consumed != expectedConsumed {
				t.Fatal("denied operation changed ticket state", rows, consumed)
			}
		})
	}
}

func TestTicketExpiryDuringPrepareWaitDoesNotExpireAnEstablishedLease(t *testing.T) {
	ctx, db, actor, scope := ticketTimeFixture(t)
	ticket, err := db.IssueRealtimeTicket(ctx, actor, managingDevice, directoryRuntime, scope)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback()
	if _, err := gate.ExecContext(ctx, `select 1 from runtimes where id=$1 for update`, directoryRuntime); err != nil {
		t.Fatal(err)
	}
	var expires time.Time
	if err := db.DB.QueryRowContext(ctx, `update realtime_tickets set expires_at=clock_timestamp()+interval '500 milliseconds' returning expires_at`).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := db.PrepareRealtimeTicket(ctx, ticket.Token); result <- err }()
	waitForGrantLock(t, ctx, db, "select g.scope")
	waitForGrantDatabaseExpiry(t, ctx, db, expires)
	if err := gate.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrTicketInvalid) {
		t.Fatal("prepare returned an expired ticket after waiting", err)
	}
	ticket, err = db.IssueRealtimeTicket(ctx, actor, managingDevice, directoryRuntime, scope)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := db.ConsumeRealtimeTicket(ctx, ticket.Token)
	if err != nil {
		t.Fatal(err)
	}
	lease.ExpiresAt = expires
	if err := db.ValidateRealtimeLease(ctx, lease); err != nil {
		t.Fatal("spent admission ticket expiry was reused as socket lifetime", err)
	}
}

func TestTicketExpiryAfterAuditWaitRollsBackIssuanceOrConsumption(t *testing.T) {
	for _, operation := range []string{"issue", "consume-grant", "consume-ticket"} {
		t.Run(operation, func(t *testing.T) {
			ctx, db, actor, scope := ticketTimeFixture(t)
			var ticket RealtimeTicket
			var err error
			if operation != "issue" {
				ticket, err = db.IssueRealtimeTicket(ctx, actor, managingDevice, directoryRuntime, scope)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.DB.ExecContext(ctx, `create function hold_ticket_audit() returns trigger language plpgsql as $$ begin
			 if new.action in('realtime.ticket.issue','realtime.ticket.consume') then perform pg_advisory_xact_lock(426961);end if;return new;end $$;
			 create trigger hold_ticket_audit before insert on audit_log for each row execute function hold_ticket_audit()`); err != nil {
				t.Fatal(err)
			}
			gate, err := db.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.Rollback()
			if _, err := gate.ExecContext(ctx, `select pg_advisory_xact_lock(426961)`); err != nil {
				t.Fatal(err)
			}
			var expires time.Time
			query := `update runtime_grants set expires_at=clock_timestamp()+interval '500 milliseconds' returning expires_at`
			if operation == "consume-ticket" {
				query = `update realtime_tickets set expires_at=clock_timestamp()+interval '500 milliseconds' returning expires_at`
			}
			if err := db.DB.QueryRowContext(ctx, query).Scan(&expires); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				var err error
				if operation == "issue" {
					_, err = db.IssueRealtimeTicket(ctx, actor, managingDevice, directoryRuntime, scope)
				} else {
					_, err = db.ConsumeRealtimeTicket(ctx, ticket.Token)
				}
				result <- err
			}()
			waitForGrantLock(t, ctx, db, "insert into audit_log")
			waitForGrantDatabaseExpiry(t, ctx, db, expires)
			if err := gate.Commit(); err != nil {
				t.Fatal(err)
			}
			want := ErrTicketInvalid
			if operation == "issue" {
				want = ErrAccessDenied
			}
			if err := <-result; !errors.Is(err, want) {
				t.Fatal("expiry after audit wait still committed ticket authority", err)
			}
			if operation == "issue" {
				var rows int
				if err := db.DB.QueryRowContext(ctx, `select count(*) from realtime_tickets`).Scan(&rows); err != nil || rows != 0 {
					t.Fatal("expired issuance left a ticket", rows, err)
				}
			} else {
				digest := sha256.Sum256([]byte(ticket.Token))
				var unused bool
				if err := db.DB.QueryRowContext(ctx, `select consumed_at is null from realtime_tickets where token_sha256=$1`, digest[:]).Scan(&unused); err != nil || !unused {
					t.Fatal("expired consumption left ticket spent", err)
				}
			}
			auditAction := "realtime.ticket.consume"
			if operation == "issue" {
				auditAction = "realtime.ticket.issue"
			}
			var audits int
			if err := db.DB.QueryRowContext(ctx, `select count(*) from audit_log where action=$1`, auditAction).Scan(&audits); err != nil || audits != 0 {
				t.Fatal("failed expiry check left a success audit", audits, err)
			}
		})
	}
}
