package store

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func newPhoneApprovalFixture(t *testing.T) *approvalFixture {
	t.Helper()
	f := newApprovalFixture(t)
	f.register(t, f.request)
	if _, err := f.database.DB.ExecContext(f.ctx, `update runtime_grants set scope=jsonb_set(scope,'{actions}','["approval.decide","grant.manage","session.read"]')`); err != nil {
		t.Fatal(err)
	}
	f.ticket.Scope.Actions = []string{"approval.decide", "session.read"}
	return f
}

func TestPhoneApprovalStatusSharesWSSPolicyWithoutTicketOrHost(t *testing.T) {
	f := newPhoneApprovalFixture(t)
	actor := UserIdentity{Issuer: f.principal.Issuer, Subject: f.principal.Subject}
	status, err := f.database.PhoneApprovalStatus(f.ctx, actor, f.ticket.DeviceID, f.principal.ProofKeyJKT, f.request.ApprovalID)
	if err != nil || status.State != "pending" || status.ApprovalID != f.request.ApprovalID {
		t.Fatal("registered phone could not read a known approval", status, err)
	}
	if err := f.database.DetachRuntimeConnection(f.ctx, f.connection.InstallationID, f.connection.RuntimeID, f.connection.RuntimeEpoch, f.connection.ConnectionID); err != nil {
		t.Fatal(err)
	}
	var before string
	counts := `select json_build_array((select count(*) from realtime_tickets),(select count(*) from audit_log),(select count(*) from control_outbox))::text`
	if err := f.database.DB.QueryRowContext(f.ctx, counts).Scan(&before); err != nil {
		t.Fatal(err)
	}
	status, err = f.database.PhoneApprovalStatus(f.ctx, actor, f.ticket.DeviceID, f.principal.ProofKeyJKT, f.request.ApprovalID)
	if err != nil || status.State != "invalidated" {
		t.Fatal("offline metadata required a live Host or socket", status, err)
	}
	wire, err := f.control.AuthorizeStatus(f.ctx, f.ticket, f.request.ApprovalID)
	if err != nil || !reflect.DeepEqual(status, wire) {
		t.Fatal("HTTP and WSS status policies/results diverged", err)
	}
	var after string
	if err := f.database.DB.QueryRowContext(f.ctx, counts).Scan(&after); err != nil || before != after {
		t.Fatal("status read issued authority or mutated audit/events", before, after, err)
	}
	raw, _ := json.Marshal(status)
	for _, private := range []string{"private-tool-argument", "private-native-call-id", "native-approval-session", "arguments", "nonce", "public_jwk", "decision_jws"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("status read disclosed full context or credentials")
		}
	}
	// Each HTTP read uses current resources/version, independent of an old ticket.
	if _, err := f.database.DB.ExecContext(f.ctx, `update runtime_grants set scope=jsonb_set(jsonb_set(scope,'{workspaces}','[]'),'{sessions}',jsonb_build_array($1::text)),grant_version=grant_version+1`, f.request.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.PhoneApprovalStatus(f.ctx, actor, f.ticket.DeviceID, f.principal.ProofKeyJKT, f.request.ApprovalID); err != nil {
		t.Fatal("current explicit session scope required stale workspace authority", err)
	}
	if _, err := f.control.AuthorizeStatus(f.ctx, f.ticket, f.request.ApprovalID); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("old admitted ticket gained the refreshed HTTP scope", err)
	}
}

func TestPhoneApprovalStatusRechecksProofRoleAndCurrentResourceChain(t *testing.T) {
	f := newPhoneApprovalFixture(t)
	actor := UserIdentity{Issuer: f.principal.Issuer, Subject: f.principal.Subject}
	read := func(identity UserIdentity, device, proof, id string) error {
		_, err := f.database.PhoneApprovalStatus(f.ctx, identity, device, proof, id)
		return err
	}
	for _, request := range []struct {
		actor             UserIdentity
		device, proof, id string
	}{
		{actor, f.ticket.DeviceID, strings.Repeat("A", 43), f.request.ApprovalID},
		{actor, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", f.principal.ProofKeyJKT, f.request.ApprovalID},
		{UserIdentity{Issuer: actor.Issuer, Subject: "target-subject"}, f.ticket.DeviceID, f.principal.ProofKeyJKT, f.request.ApprovalID},
		{actor, f.ticket.DeviceID, f.principal.ProofKeyJKT, approvalTestUUID(t)},
	} {
		if err := read(request.actor, request.device, request.proof, request.id); !errors.Is(err, ErrAccessDenied) {
			t.Fatal("phone/identity/approval selector bypassed current authority", err)
		}
	}
	for _, change := range []struct{ name, mutate, restore string }{
		{"operator", `update runtime_grants set role='operator'`, `update runtime_grants set role='owner'`},
		{"admin without owner", `update org_memberships set role='admin';update runtime_grants set role='operator'`, `update org_memberships set role='member';update runtime_grants set role='owner'`},
		{"read only", `update runtime_grants set scope=jsonb_set(scope,'{actions}','["session.read"]')`, `update runtime_grants set scope=jsonb_set(scope,'{actions}','["session.read","approval.decide","grant.manage"]')`},
		{"approval only", `update runtime_grants set scope=jsonb_set(scope,'{actions}','["approval.decide"]')`, `update runtime_grants set scope=jsonb_set(scope,'{actions}','["session.read","approval.decide","grant.manage"]')`},
		{"resource", `update runtime_grants set scope=jsonb_set(scope,'{workspaces}','[]')`, `update runtime_grants set scope=jsonb_set(scope,'{workspaces}','["77777777-7777-4777-8777-777777777777"]')`},
		{"grant", `update runtime_grants set revoked_at=clock_timestamp()`, `update runtime_grants set revoked_at=null`},
		{"expired grant", `update runtime_grants set expires_at=clock_timestamp()-interval '1 second'`, `update runtime_grants set expires_at=null`},
		{"device", `update devices set revoked_at=clock_timestamp()`, `update devices set revoked_at=null`},
		{"account", `update users set status='suspended'`, `update users set status='active'`},
		{"runtime", `update runtimes set revoked_at=clock_timestamp()`, `update runtimes set revoked_at=null`},
		{"installation", `update installations set revoked_at=clock_timestamp()`, `update installations set revoked_at=null`},
		{"host", `update hosts set state='revoked'`, `update hosts set state='active'`},
		{"membership", `delete from org_memberships where user_id='22222222-2222-4222-8222-222222222222'`, `insert into org_memberships(org_id,user_id,role) values('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','22222222-2222-4222-8222-222222222222','member')`},
	} {
		t.Run(change.name, func(t *testing.T) {
			if _, err := f.database.DB.ExecContext(f.ctx, change.mutate); err != nil {
				t.Fatal(err)
			}
			if err := read(actor, f.ticket.DeviceID, f.principal.ProofKeyJKT, f.request.ApprovalID); !errors.Is(err, ErrAccessDenied) {
				t.Fatal("earlier successful read preserved lost authority", err)
			}
			if _, err := f.database.DB.ExecContext(f.ctx, change.restore); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPhoneApprovalStatusRetainsCompletedResultAndHonorsExpiryAfterWaiting(t *testing.T) {
	f := newPhoneApprovalFixture(t)
	actor := UserIdentity{Issuer: f.principal.Issuer, Subject: f.principal.Subject}
	status := acceptResultFixture(t, f, "allow_once")
	for _, state := range []string{"approved", "consumed", "settled"} {
		outcome := ""
		if state == "settled" {
			outcome = "succeeded"
		}
		var err error
		status, err = f.control.RecordResult(f.ctx, f.connection, 1, resultFor(status, state, outcome))
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := f.database.PhoneApprovalStatus(f.ctx, actor, f.ticket.DeviceID, f.principal.ProofKeyJKT, f.request.ApprovalID)
	if err != nil || got.HostState != "settled" || got.Outcome != "succeeded" || got.Decision != "allow_once" {
		t.Fatal("status read relabeled a known signed result", got, err)
	}
	gate, err := f.database.DB.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback()
	if _, err := gate.ExecContext(f.ctx, `select 1 from approvals where id=$1 for update`, f.request.ApprovalID); err != nil {
		t.Fatal(err)
	}
	var expires time.Time
	if err := f.database.DB.QueryRowContext(f.ctx, `update runtime_grants set expires_at=clock_timestamp()+interval '500 milliseconds' returning expires_at`).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := f.database.PhoneApprovalStatus(f.ctx, actor, f.ticket.DeviceID, f.principal.ProofKeyJKT, f.request.ApprovalID)
		result <- err
	}()
	waitForGrantLock(t, f.ctx, f.database, "where id = $1 and metadata_version = 1 for update")
	waitForGrantDatabaseExpiry(t, f.ctx, f.database, expires)
	if err := gate.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrAccessDenied) {
		t.Fatal("expired read authority survived the approval row wait", err)
	}
}
