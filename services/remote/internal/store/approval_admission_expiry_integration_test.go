package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/approval"
	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/canonical"
	jose "github.com/go-jose/go-jose/v4"
)

func holdApprovalExpiryWrite(t *testing.T, f *approvalFixture, target, topic string) (*sql.Tx, string) {
	t.Helper()
	var table, event, condition, fragment string
	switch target {
	case "audit":
		table, event, condition, fragment = "audit_log", "insert", "new.action='"+topic+"'", "insert into audit_log"
	case "outbox":
		table, event, condition, fragment = "control_outbox", "insert", "new.topic='"+topic+"'", "insert into control_outbox"
	case "evidence":
		table, event, condition, fragment = "approval_decision_evidence", "insert", "true", "update approvals set state"
	case "material":
		table, event, condition, fragment = "approval_decision_evidence_material", "insert", "true", "update approvals set state"
	case "update":
		table, event, condition, fragment = "approvals", "update", "old.decision is null and new.decision is not null", "update approvals set state"
	default:
		t.Fatal("invalid private approval wait target")
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `create function hold_approval_expiry() returns trigger language plpgsql as $$ begin
	 if `+condition+` then perform pg_advisory_xact_lock(426964);end if;return new;end $$;
	 create trigger hold_approval_expiry before `+event+` on `+table+` for each row execute function hold_approval_expiry()`); err != nil {
		t.Fatal(err)
	}
	gate, err := f.database.DB.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gate.Rollback() })
	if _, err := gate.ExecContext(f.ctx, `select pg_advisory_xact_lock(426964)`); err != nil {
		t.Fatal(err)
	}
	return gate, fragment
}

func approvalExpiryDeadline(t *testing.T, f *approvalFixture) time.Time {
	t.Helper()
	var deadline time.Time
	if err := f.database.DB.QueryRowContext(f.ctx, `select clock_timestamp()+interval '600 milliseconds'`).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	return deadline.UTC().Truncate(time.Millisecond)
}

func signApprovalExpiryDecision(t *testing.T, f *approvalFixture, choice string, issued, expires time.Time) string {
	t.Helper()
	binding, err := approval.ContextBinding(approvalRaw(t, f.request))
	if err != nil {
		t.Fatal(err)
	}
	decision := approval.Decision{Domain: approval.DecisionDomain, ProtocolVersion: 1, Identity: f.request.Identity, BindingSHA256: binding.SHA256,
		Decision: choice, UserID: f.ticket.UserID, DeviceID: f.ticket.DeviceID, KeyVersion: f.ticket.DeviceKeyVersion,
		PolicyVersion: f.request.PolicyVersion, Nonce: f.request.Nonce, IssuedAt: issued.Format("2006-01-02T15:04:05.000Z"), ExpiresAt: expires.Format("2006-01-02T15:04:05.000Z")}
	raw, _ := json.Marshal(decision)
	payload, err := canonical.Object(raw)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: f.key, KeyID: approval.KeyID(decision.DeviceID, decision.KeyVersion)}}, (&jose.SignerOptions{}).WithType(approval.JWSType))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func assertNoApprovalDecisionEvidence(t *testing.T, f *approvalFixture) {
	t.Helper()
	var evidence, material, fingerprints int
	if err := f.database.DB.QueryRowContext(f.ctx, `select
	 (select count(*) from approval_decision_evidence),
	 (select count(*) from approval_decision_evidence_material),
	 (select count(*) from approval_evidence_fingerprints)`).Scan(&evidence, &material, &fingerprints); err != nil {
		t.Fatal(err)
	}
	if evidence != 0 || material != 0 || fingerprints != 0 {
		t.Fatal("expired decision left immutable evidence", evidence, material, fingerprints)
	}
}

func TestApprovalRegistrationExpiryAfterDurableWriteWait(t *testing.T) {
	for _, target := range []string{"audit", "outbox"} {
		for _, expiry := range []string{"request", "heartbeat"} {
			t.Run(target+"/"+expiry, func(t *testing.T) {
				f := newApprovalFixture(t)
				gate, fragment := holdApprovalExpiryWrite(t, f, target, "approval.pending")
				deadline := approvalExpiryDeadline(t, f)
				want := ErrApprovalExpired
				if expiry == "request" {
					f.request.ExpiresAt = deadline.Format("2006-01-02T15:04:05.000Z")
				} else {
					want = ErrRuntimeConnectionStale
					if _, err := f.database.DB.ExecContext(f.ctx, `update runtimes set last_seen_at=$1 where id=$2`, deadline.Add(-45*time.Second), f.request.RuntimeID); err != nil {
						t.Fatal(err)
					}
				}
				raw := approvalRaw(t, f.request)
				result := make(chan error, 1)
				go func() { _, err := f.control.Register(f.ctx, f.connection, 1, raw); result <- err }()
				waitForGrantLock(t, f.ctx, f.database, fragment)
				waitForGrantDatabaseExpiry(t, f.ctx, f.database, deadline)
				if err := gate.Commit(); err != nil {
					t.Fatal(err)
				}
				if err := <-result; !errors.Is(err, want) {
					t.Fatal("registration admitted expired authority after a durable write wait", err)
				}
				assertApprovalCounts(t, f, 0, 0, 0, 0)
				assertNoApprovalDecisionEvidence(t, f)
			})
		}
	}
}

func TestApprovalDecisionExpiryAfterDurableWriteWait(t *testing.T) {
	for _, target := range []string{"audit", "outbox", "evidence", "material", "update"} {
		for _, expiry := range []string{"request", "decision", "token", "authentication", "grant", "heartbeat", "freshness"} {
			// The two late writes cover every clock. Other trigger waits prove
			// the CAS/evidence chain cannot bypass the final admission check.
			if target != "audit" && target != "outbox" && expiry != "token" {
				continue
			}
			t.Run(target+"/"+expiry, func(t *testing.T) {
				f := newApprovalFixture(t)
				// An old but valid decision exercises the independent 30-second
				// freshness window without making the request itself expire.
				f.request.CreatedAt = time.Now().Add(-time.Minute).UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
				gate, fragment := holdApprovalExpiryWrite(t, f, target, "approval.decided")
				deadline := approvalExpiryDeadline(t, f)
				issued := time.Now().UTC().Truncate(time.Millisecond)
				decisionExpires, _ := time.Parse(time.RFC3339Nano, f.request.ExpiresAt)
				want := approval.ErrDecision
				switch expiry {
				case "request":
					f.request.ExpiresAt = deadline.Format("2006-01-02T15:04:05.000Z")
					decisionExpires = deadline
				case "decision":
					decisionExpires = deadline
				case "token":
					f.principal.ExpiresAt = deadline
					want = auth.ErrAssurance
				case "authentication":
					f.principal.AuthenticatedAt = deadline.Add(-60 * time.Second)
					f.principal.IssuedAt = f.principal.AuthenticatedAt.Add(time.Millisecond)
					want = auth.ErrAssurance
				case "grant":
					want = ErrAccessDenied
					if _, err := f.database.DB.ExecContext(f.ctx, `update runtime_grants set expires_at=$1`, deadline); err != nil {
						t.Fatal(err)
					}
				case "heartbeat":
					want = ErrRuntimeConnectionStale
					if _, err := f.database.DB.ExecContext(f.ctx, `update runtimes set last_seen_at=$1`, deadline.Add(-45*time.Second)); err != nil {
						t.Fatal(err)
					}
				case "freshness":
					issued = deadline.Add(-30 * time.Second)
				}
				f.register(t, f.request)
				choice := "allow_once"
				if target == "outbox" {
					choice = "reject"
				}
				compact := signApprovalExpiryDecision(t, f, choice, issued, decisionExpires)
				raw := approvalRaw(t, f.request)
				result := make(chan error, 1)
				go func() { _, err := f.control.Decide(f.ctx, f.principal, f.ticket, raw, compact); result <- err }()
				waitForGrantLock(t, f.ctx, f.database, fragment)
				// Freshness accepts equality; advance one millisecond beyond it.
				waitForGrantDatabaseExpiry(t, f.ctx, f.database, deadline.Add(time.Millisecond))
				if err := gate.Commit(); err != nil {
					t.Fatal(err)
				}
				if err := <-result; !errors.Is(err, want) {
					t.Fatal("decision admitted expired authority after a durable write wait", err)
				}
				assertApprovalPending(t, f, f.request)
				assertApprovalCounts(t, f, 1, 1, 0, 0)
				assertNoApprovalDecisionEvidence(t, f)
			})
		}
	}
}

func TestApprovalRegistrationRetryCannotOutliveRequestOrHeartbeat(t *testing.T) {
	for _, expiry := range []string{"request", "heartbeat"} {
		t.Run(expiry, func(t *testing.T) {
			f := newApprovalFixture(t)
			deadline := approvalExpiryDeadline(t, f)
			want := ErrApprovalExpired
			if expiry == "request" {
				f.request.ExpiresAt = deadline.Format("2006-01-02T15:04:05.000Z")
			} else {
				want = ErrRuntimeConnectionStale
				if _, err := f.database.DB.ExecContext(f.ctx, `update runtimes set last_seen_at=$1`, deadline.Add(-45*time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			f.register(t, f.request)
			gate, err := f.database.DB.BeginTx(f.ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.Rollback()
			if _, err := gate.ExecContext(f.ctx, `select 1 from approvals where id=$1 for update`, f.request.ApprovalID); err != nil {
				t.Fatal(err)
			}
			raw := approvalRaw(t, f.request)
			result := make(chan error, 1)
			go func() { _, err := f.control.Register(f.ctx, f.connection, 1, raw); result <- err }()
			waitForGrantLock(t, f.ctx, f.database, "select id::text, runtime_id::text")
			waitForGrantDatabaseExpiry(t, f.ctx, f.database, deadline)
			if err := gate.Commit(); err != nil {
				t.Fatal(err)
			}
			if err := <-result; !errors.Is(err, want) {
				t.Fatal("registration retry bypassed current time checks", err)
			}
			assertApprovalPending(t, f, f.request)
			assertApprovalCounts(t, f, 1, 1, 0, 0)
			assertNoApprovalDecisionEvidence(t, f)
		})
	}
}

func TestApprovalLiveAuthoritySurvivesDurableWriteWaitAndExactRetry(t *testing.T) {
	for _, target := range []string{"audit", "outbox"} {
		for _, operation := range []string{"register", "decide"} {
			t.Run(target+"/"+operation, func(t *testing.T) {
				f := newApprovalFixture(t)
				topic := "approval.pending"
				if operation == "decide" {
					f.register(t, f.request)
					topic = "approval.decided"
				}
				gate, fragment := holdApprovalExpiryWrite(t, f, target, topic)
				raw := approvalRaw(t, f.request)
				compact := f.signed(t, f.request, "allow_once")
				run := func() (ApprovalStatus, error) {
					if operation == "register" {
						return f.control.Register(f.ctx, f.connection, 1, raw)
					}
					return f.control.Decide(f.ctx, f.principal, f.ticket, raw, compact)
				}
				result := make(chan error, 1)
				go func() { _, err := run(); result <- err }()
				waitForGrantLock(t, f.ctx, f.database, fragment)
				if err := gate.Commit(); err != nil {
					t.Fatal(err)
				}
				if err := <-result; err != nil {
					t.Fatal("live authority failed after a bounded wait", err)
				}
				status, err := run()
				if err != nil || status.ApprovalID != f.request.ApprovalID {
					t.Fatal("exact retry failed", err)
				}
				decisions := 0
				state := "pending"
				if operation == "decide" {
					decisions, state = 1, "decision_received"
				}
				if status.State != state {
					t.Fatal("exact retry changed the approval state", status.State)
				}
				assertApprovalCounts(t, f, 1, 1, decisions, 0)
			})
		}
	}
}

func TestApprovalHeartbeatExpiryCannotSurviveRuntimeLockWait(t *testing.T) {
	for _, operation := range []string{"register", "decided-retry"} {
		t.Run(operation, func(t *testing.T) {
			f := newApprovalFixture(t)
			raw := approvalRaw(t, f.request)
			compact := f.signed(t, f.request, "allow_once")
			if operation == "decided-retry" {
				f.register(t, f.request)
				if _, err := f.control.Decide(f.ctx, f.principal, f.ticket, raw, compact); err != nil {
					t.Fatal(err)
				}
			}
			deadline := approvalExpiryDeadline(t, f)
			if _, err := f.database.DB.ExecContext(f.ctx, `update runtimes set last_seen_at=$1`, deadline.Add(-45*time.Second)); err != nil {
				t.Fatal(err)
			}
			gate, err := f.database.DB.BeginTx(f.ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.Rollback()
			if _, err := gate.ExecContext(f.ctx, `select 1 from runtimes where id=$1 for update`, f.request.RuntimeID); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				var err error
				if operation == "register" {
					_, err = f.control.Register(f.ctx, f.connection, 1, raw)
				} else {
					_, err = f.control.Decide(f.ctx, f.principal, f.ticket, raw, compact)
				}
				result <- err
			}()
			waitForGrantLock(t, f.ctx, f.database, "select h.org_id::text, r.connection_id::text")
			waitForGrantDatabaseExpiry(t, f.ctx, f.database, deadline)
			if err := gate.Commit(); err != nil {
				t.Fatal(err)
			}
			if err := <-result; !errors.Is(err, ErrRuntimeConnectionStale) {
				t.Fatal("runtime lock predicate admitted an expired heartbeat", err)
			}
			if operation == "register" {
				assertApprovalCounts(t, f, 0, 0, 0, 0)
			} else {
				assertApprovalCounts(t, f, 1, 1, 1, 0)
				var state string
				if err := f.database.DB.QueryRowContext(f.ctx, `select state from approvals where id=$1`, f.request.ApprovalID).Scan(&state); err != nil || state != "decision_received" {
					t.Fatal("denied retry changed the historical decision", state, err)
				}
			}
		})
	}
}
