package store

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/approval"
)

func approvalTestSigner(t *testing.T, until time.Time) *approval.AuthorizationSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := approval.NewAuthorizationSigner("https://remote.example.edu", "dsh-approval-authority/postgres-test", key, time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond), until.UTC().Truncate(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func newTestLeaseProvider(t *testing.T, fixture *approvalFixture, until time.Time) (*ApprovalLeaseProvider, *approval.AuthorizationSigner) {
	t.Helper()
	signer := approvalTestSigner(t, until)
	provider, err := NewApprovalLeaseProvider(fixture.control, signer)
	if err != nil {
		t.Fatal(err)
	}
	return provider, signer
}

func assertPreparedLeaseCount(t *testing.T, fixture *approvalFixture, expected int) {
	t.Helper()
	var audits, outbox int
	if err := fixture.database.DB.QueryRowContext(fixture.ctx, `select count(*) from audit_log where action = 'approval.authorization.prepare'`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.DB.QueryRowContext(fixture.ctx, `select count(*) from control_outbox where topic = 'approval.authorization.prepared'`).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if audits != expected || outbox != expected {
		t.Fatalf("prepared lease audit/outbox=%d/%d want %d", audits, outbox, expected)
	}
}

func TestPostgresApprovalLeasesRequireAcceptedDecisionAndCurrentOriginalAuthority(t *testing.T) {
	fixture := newApprovalFixture(t)
	provider, signer := newTestLeaseProvider(t, fixture, time.Now().Add(time.Hour))
	fixture.register(t, fixture.request)
	raw := approvalRaw(t, fixture.request)
	if compact, err := provider.Issue(fixture.ctx, fixture.connection, 1, raw); err == nil || compact != "" {
		t.Fatal("pending request acquired authority lease")
	}
	decision := fixture.signed(t, fixture.request, "allow_once")
	if _, err := fixture.control.Decide(fixture.ctx, fixture.principal, fixture.ticket, raw, decision); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		compact, err := provider.Issue(fixture.ctx, fixture.connection, 1, raw)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := approval.VerifyAuthorization(compact, signer.Authority(), raw, decision, fixture.connection.ConnectionID, time.Now())
		if err != nil || verified.Lease.GrantVersion != fixture.ticket.GrantVersion || verified.Key.DeviceID != fixture.ticket.DeviceID {
			t.Fatalf("current authority lease failed independent verification: %v", err)
		}
		issued, _ := time.Parse(time.RFC3339Nano, verified.Lease.IssuedAt)
		expires, _ := time.Parse(time.RFC3339Nano, verified.Lease.ExpiresAt)
		if expires.Sub(issued) > 3*time.Second {
			t.Fatal("unbounded lease")
		}
	}
	assertPreparedLeaseCount(t, fixture, 2)
	for _, test := range []struct{ name, mutate, restore string }{
		{"revoked device", `update devices set revoked_at = now()`, `update devices set revoked_at = null`},
		{"rotated device", `update devices set key_version = 2`, `update devices set key_version = 1`},
		{"regranted owner", `update runtime_grants set grant_version = 2`, `update runtime_grants set grant_version = 1`},
		{"operator role", `update runtime_grants set role = 'operator'`, `update runtime_grants set role = 'owner'`},
		{"revoked grant", `update runtime_grants set revoked_at = now()`, `update runtime_grants set revoked_at = null`},
		{"expired grant", `update runtime_grants set expires_at = now() - interval '1 second'`, `update runtime_grants set expires_at = null`},
		{"missing action", `update runtime_grants set scope = jsonb_set(scope, '{actions}', '["grant.manage"]')`, `update runtime_grants set scope = jsonb_set(scope, '{actions}', '["approval.decide","grant.manage"]')`},
		{"lost workspace scope", `update runtime_grants set scope = jsonb_set(scope, '{workspaces}', '[]')`, `update runtime_grants set scope = jsonb_set(scope, '{workspaces}', '["77777777-7777-4777-8777-777777777777"]')`},
		{"suspended user", `update users set status = 'suspended'`, `update users set status = 'active'`},
		{"rotated installation", `update installations set key_version = 2`, `update installations set key_version = 1`},
		{"archived session", `update sessions set state = 'archived'`, `update sessions set state = 'running'`},
		{"stale connection", `update runtimes set last_seen_at = now() - interval '46 seconds'`, `update runtimes set last_seen_at = clock_timestamp()`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := fixture.database.DB.ExecContext(fixture.ctx, test.mutate); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if _, err := fixture.database.DB.ExecContext(fixture.ctx, test.restore); err != nil {
					t.Fatal(err)
				}
			})
			if compact, err := provider.Issue(fixture.ctx, fixture.connection, 1, raw); err == nil || compact != "" {
				t.Fatal("stale authority acquired another lease")
			}
			assertPreparedLeaseCount(t, fixture, 2)
		})
	}
	wrongConnection := fixture.connection
	wrongConnection.ConnectionID = approvalTestUUID(t)
	for _, input := range []struct {
		connection RuntimeConnection
		key        int64
	}{{wrongConnection, 1}, {fixture.connection, 2}} {
		if _, err := provider.Issue(fixture.ctx, input.connection, input.key, raw); !errors.Is(err, ErrRuntimeConnectionStale) {
			t.Fatalf("wrong connection/key acquired lease: %v", err)
		}
	}
	changed := fixture.request
	changed.Arguments = json.RawMessage(`{"command":"changed"}`)
	if compact, err := provider.Issue(fixture.ctx, fixture.connection, 1, approvalRaw(t, changed)); err == nil || compact != "" {
		t.Fatal("changed actual execution acquired lease")
	}
	var metadata string
	if err := fixture.database.DB.QueryRowContext(fixture.ctx, `select string_agg(metadata::text, '') from audit_log where action = 'approval.authorization.prepare'`).Scan(&metadata); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{fixture.request.Nonce, "private-tool-argument", fixture.request.CallID, decision} {
		if strings.Contains(metadata, secret) {
			t.Fatal("lease audit stored execution body or proof")
		}
	}
}

func TestPostgresApprovalLeaseExpiryIsClippedToEveryOriginalDeadline(t *testing.T) {
	for _, bound := range []string{"token", "grant", "authentication", "authority-key"} {
		t.Run(bound, func(t *testing.T) {
			fixture := newApprovalFixture(t)
			deadline := time.Now().Add(2 * time.Second).UTC().Truncate(time.Millisecond)
			keyUntil := time.Now().Add(time.Hour)
			switch bound {
			case "token":
				fixture.principal.ExpiresAt = deadline
			case "authentication":
				fixture.principal.AuthenticatedAt = deadline.Add(-60 * time.Second)
			case "grant":
				if _, err := fixture.database.DB.ExecContext(fixture.ctx, `update runtime_grants set expires_at = $1`, deadline); err != nil {
					t.Fatal(err)
				}
			case "authority-key":
				keyUntil = deadline
			}
			provider, signer := newTestLeaseProvider(t, fixture, keyUntil)
			fixture.register(t, fixture.request)
			raw := approvalRaw(t, fixture.request)
			decision := fixture.signed(t, fixture.request, "allow_once")
			if _, err := fixture.control.Decide(fixture.ctx, fixture.principal, fixture.ticket, raw, decision); err != nil {
				t.Fatal(err)
			}
			compact, err := provider.Issue(fixture.ctx, fixture.connection, 1, raw)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := approval.VerifyAuthorization(compact, signer.Authority(), raw, decision, fixture.connection.ConnectionID, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			expires, _ := time.Parse(time.RFC3339Nano, verified.Lease.ExpiresAt)
			if !expires.Equal(deadline) {
				t.Fatalf("lease escaped %s deadline: %s want %s", bound, expires, deadline)
			}
			assertPreparedLeaseCount(t, fixture, 1)
		})
	}
}

func TestPostgresApprovalLeaseAuditOrOutboxFailureNeverReturnsSignedPermission(t *testing.T) {
	fixture := newApprovalFixture(t)
	provider, _ := newTestLeaseProvider(t, fixture, time.Now().Add(time.Hour))
	fixture.register(t, fixture.request)
	raw := approvalRaw(t, fixture.request)
	if _, err := fixture.control.Decide(fixture.ctx, fixture.principal, fixture.ticket, raw, fixture.signed(t, fixture.request, "allow_once")); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"audit_log", "control_outbox"} {
		t.Run(target, func(t *testing.T) {
			if _, err := fixture.database.DB.ExecContext(fixture.ctx, `create function reject_lease_write() returns trigger language plpgsql as $$ begin raise exception 'test unavailable'; end $$; create trigger reject_lease_write before insert on `+target+` for each row execute function reject_lease_write()`); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if _, err := fixture.database.DB.ExecContext(fixture.ctx, `drop trigger reject_lease_write on `+target+`; drop function reject_lease_write()`); err != nil {
					t.Fatal(err)
				}
			})
			if compact, err := provider.Issue(fixture.ctx, fixture.connection, 1, raw); !errors.Is(err, ErrDatabaseUnavailable) || compact != "" {
				t.Fatalf("failed durable issuance returned permission: %v", err)
			}
			assertPreparedLeaseCount(t, fixture, 0)
		})
	}
	if _, err := provider.Issue(fixture.ctx, fixture.connection, 1, raw); err != nil {
		t.Fatal(err)
	}
	assertPreparedLeaseCount(t, fixture, 1)
}

func TestPostgresApprovalLeaseKeepsExpiredAuthenticationAndUnknownExecutionClosed(t *testing.T) {
	fixture := newApprovalFixture(t)
	provider, _ := newTestLeaseProvider(t, fixture, time.Now().Add(time.Hour))
	fixture.principal.ExpiresAt = time.Now().Add(400 * time.Millisecond)
	fixture.register(t, fixture.request)
	raw := approvalRaw(t, fixture.request)
	if _, err := fixture.control.Decide(fixture.ctx, fixture.principal, fixture.ticket, raw, fixture.signed(t, fixture.request, "allow_once")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(fixture.principal.ExpiresAt) + 5*time.Millisecond)
	fixture.principal.ExpiresAt = time.Now().Add(time.Hour) // A new token cannot alter recorded decision evidence.
	if compact, err := provider.Issue(fixture.ctx, fixture.connection, 1, raw); err == nil || compact != "" {
		t.Fatal("new token refreshed an old approval")
	}
	if err := fixture.database.DetachRuntimeConnection(fixture.ctx, fixture.connection.InstallationID, fixture.connection.RuntimeID, fixture.connection.RuntimeEpoch, fixture.connection.ConnectionID); err != nil {
		t.Fatal(err)
	}
	if compact, err := provider.Issue(fixture.ctx, fixture.connection, 1, raw); err == nil || compact != "" {
		t.Fatal("disconnected/unknown execution acquired authority")
	}
	assertPreparedLeaseCount(t, fixture, 0)
}
