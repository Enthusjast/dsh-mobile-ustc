package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/approval"
	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/canonical"
	jose "github.com/go-jose/go-jose/v4"
)

type approvalFixture struct {
	ctx        context.Context
	database   *Postgres
	control    *ApprovalControl
	connection RuntimeConnection
	key        *ecdsa.PrivateKey
	principal  auth.Principal
	ticket     TicketRedemption
	request    approval.Context
}

func newApprovalFixture(t *testing.T) *approvalFixture {
	t.Helper()
	ctx, database := newPostgresIntegrationDatabase(t)
	proofJKT := seedGrantFixture(t, ctx, database.DB)
	const (
		runtimeID      = "55555555-5555-4555-8555-555555555555"
		installationID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
		workspaceID    = "77777777-7777-4777-8777-777777777777"
		userID         = "22222222-2222-4222-8222-222222222222"
		deviceID       = "44444444-4444-4444-8444-444444444444"
	)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicJWK, _ := integrationP256JWK(key)
	jkt, _ := auth.PublicP256JWKThumbprintJSON(publicJWK)
	if _, err := database.DB.ExecContext(ctx, `update devices set approval_public_jwk = $1, approval_key_thumbprint = $2 where id = $3`, publicJWK, jkt, deviceID); err != nil {
		t.Fatal(err)
	}
	connection, err := database.AttachRuntimeConnection(ctx, RuntimeConnectionInput{InstallationID: installationID, KeyVersion: 1, RuntimeID: runtimeID,
		RuntimeEpoch: approvalTestUUID(t), ConnectionID: approvalTestUUID(t), DSHVersion: "0.2.1-rc.2", ApplicationVersion: "npm-dsh", PluginVersion: "test", ProtocolVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	sessionID, _ := MobileSessionID(runtimeID, "native-approval-session")
	if err := database.SyncRealtimeSessionCatalog(ctx, connection, 1, true, []SessionCatalogItem{{SessionID: sessionID, DSHSessionID: "native-approval-session", WorkspaceID: ptr(workspaceID), State: "running", LastPersistedSeq: -1}}); err != nil {
		t.Fatal(err)
	}
	scope := GrantScope{Actions: []string{"approval.decide"}, Workspaces: []string{workspaceID}, Sessions: []string{}}
	grant := GrantScope{Actions: []string{"approval.decide", "grant.manage"}, Workspaces: []string{workspaceID}, Sessions: []string{}}
	encoded, _ := json.Marshal(grant)
	if _, err := database.DB.ExecContext(ctx, `update runtime_grants set scope = $1 where runtime_id = $2 and user_id = $3`, encoded, runtimeID, userID); err != nil {
		t.Fatal(err)
	}
	verifier, err := auth.NewAssuranceVerifier([]auth.AssuranceMapping{{Profile: "school/step-up", Issuer: "https://id.example.edu", ClientID: "android",
		ACR: "urn:test:step-up", RequiredAMR: []string{"otp"}}})
	if err != nil {
		t.Fatal(err)
	}
	control, err := NewApprovalControl(database, ApprovalPolicy{Version: 7, AssuranceProfile: "school/step-up", MaxAuthAgeSeconds: 60}, verifier)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	fixture := &approvalFixture{ctx: ctx, database: database, control: control, connection: connection, key: key,
		principal: auth.Principal{Issuer: "https://id.example.edu", Subject: "owner-subject", ClientID: "android", ProofKeyJKT: proofJKT, ProofJTI: "verified-proof",
			IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(5 * time.Minute), AuthenticatedAt: now.Add(-2 * time.Second), ACR: "urn:test:step-up", AMR: []string{"otp"}},
		ticket: TicketRedemption{UserID: userID, DeviceID: deviceID, RuntimeID: runtimeID, DeviceKeyVersion: 1, ProofKeyThumbprint: proofJKT, GrantVersion: 1, Scope: scope},
		request: approval.Context{Domain: approval.ContextDomain, ProtocolVersion: 1,
			Identity: approval.Identity{HostID: "11111111-1111-4111-8111-111111111111", InstallationID: installationID, RuntimeID: runtimeID,
				RuntimeEpoch: connection.RuntimeEpoch, SessionID: sessionID},
			DSHSessionID: "native-approval-session", CallID: "private-native-call-id", Tool: "bash", Arguments: json.RawMessage(`{"command":"private-tool-argument"}`),
			Workspace: approval.Workspace{WorkspaceID: workspaceID, RootSHA256: strings.Repeat("a", 64)}, Resources: []approval.Resource{},
			PolicyVersion: 7, RequiredAssurance: approval.Assurance{Profile: "school/step-up", MaxAuthAgeSeconds: ptr(int64(60))},
			CreatedAt: now.Add(-time.Second).Format("2006-01-02T15:04:05.000Z"), ExpiresAt: now.Add(2 * time.Minute).Format("2006-01-02T15:04:05.000Z")}}
	fixture.request = fixture.freshRequest(t)
	return fixture
}

func ptr[T any](value T) *T { return &value }

func approvalTestUUID(t *testing.T) string {
	t.Helper()
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	value[6], value[8] = (value[6]&15)|64, (value[8]&63)|128
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[:4], value[4:6], value[6:8], value[8:10], value[10:])
}

func (fixture *approvalFixture) freshRequest(t *testing.T) approval.Context {
	t.Helper()
	request := fixture.request
	request.ApprovalID, request.ExecutionID = approvalTestUUID(t), approvalTestUUID(t)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	request.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
	return request
}

func approvalRaw(t *testing.T, request approval.Context) []byte {
	t.Helper()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (fixture *approvalFixture) signed(t *testing.T, request approval.Context, choice string) string {
	t.Helper()
	binding, err := approval.ContextBinding(approvalRaw(t, request))
	if err != nil {
		t.Fatal(err)
	}
	decision := approval.Decision{Domain: approval.DecisionDomain, ProtocolVersion: 1, Identity: request.Identity, BindingSHA256: binding.SHA256, Decision: choice,
		UserID: fixture.ticket.UserID, DeviceID: fixture.ticket.DeviceID, KeyVersion: fixture.ticket.DeviceKeyVersion, PolicyVersion: request.PolicyVersion,
		Nonce: request.Nonce, IssuedAt: time.Now().UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z"), ExpiresAt: request.ExpiresAt}
	raw, _ := json.Marshal(decision)
	encoded, err := canonical.Object(raw)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: fixture.key, KeyID: approval.KeyID(decision.DeviceID, decision.KeyVersion)}}, (&jose.SignerOptions{}).WithType(approval.JWSType))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(encoded)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func (fixture *approvalFixture) register(t *testing.T, request approval.Context) ApprovalStatus {
	t.Helper()
	status, err := fixture.control.Register(fixture.ctx, fixture.connection, 1, approvalRaw(t, request))
	if err != nil {
		t.Fatalf("register pending approval: %v", err)
	}
	return status
}

func assertApprovalCounts(t *testing.T, fixture *approvalFixture, requests, pendingEvents, decisions, endings int) {
	t.Helper()
	var rows, registrations, decided, ended, outbox int
	if err := fixture.database.DB.QueryRowContext(fixture.ctx, `select count(*) from approvals`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.DB.QueryRowContext(fixture.ctx, `select count(*) filter (where action = 'approval.pending'), count(*) filter (where action = 'approval.decided'), count(*) filter (where action = 'approval.ended') from audit_log`).Scan(&registrations, &decided, &ended); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.DB.QueryRowContext(fixture.ctx, `select count(*) from control_outbox where topic like 'approval.%'`).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if rows != requests || registrations != pendingEvents || decided != decisions || ended != endings || outbox != pendingEvents+decisions+endings {
		t.Fatalf("approval rows/audit/outbox = %d/%d/%d/%d/%d, want %d/%d/%d/%d/%d", rows, registrations, decided, ended, outbox, requests, pendingEvents, decisions, endings, pendingEvents+decisions+endings)
	}
}

func assertApprovalPending(t *testing.T, fixture *approvalFixture, request approval.Context) {
	t.Helper()
	var state string
	var decision sql.NullString
	if err := fixture.database.DB.QueryRowContext(fixture.ctx, `select state, decision_jws from approvals where id = $1`, request.ApprovalID).Scan(&state, &decision); err != nil || state != "pending" || decision.Valid {
		t.Fatalf("failed attempt consumed approval: state=%s decision=%t error=%v", state, decision.Valid, err)
	}
}

func TestPostgresApprovalRegistrationBindsCurrentConnectionAndPersistsOnlyMetadata(t *testing.T) {
	fixture := newApprovalFixture(t)
	for _, test := range []struct {
		name   string
		mutate func(*approval.Context)
	}{
		{"host", func(c *approval.Context) { c.HostID = approvalTestUUID(t) }},
		{"epoch", func(c *approval.Context) { c.RuntimeEpoch = approvalTestUUID(t) }},
		{"session", func(c *approval.Context) { c.SessionID = approvalTestUUID(t) }},
		{"native session", func(c *approval.Context) { c.DSHSessionID = "different-native-session" }},
		{"workspace", func(c *approval.Context) { c.Workspace.WorkspaceID = approvalTestUUID(t) }},
		{"policy", func(c *approval.Context) { c.PolicyVersion++ }},
		{"assurance", func(c *approval.Context) { c.RequiredAssurance.Profile = "weaker" }},
		{"age", func(c *approval.Context) { c.RequiredAssurance.MaxAuthAgeSeconds = ptr(int64(900)) }},
		{"future request", func(c *approval.Context) {
			c.CreatedAt = time.Now().Add(10 * time.Second).UTC().Format("2006-01-02T15:04:05.000Z")
		}},
		{"expired request", func(c *approval.Context) { c.ExpiresAt = c.CreatedAt }},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := fixture.request
			test.mutate(&request)
			if _, err := fixture.control.Register(fixture.ctx, fixture.connection, 1, approvalRaw(t, request)); err == nil {
				t.Fatal("unbound request was registered")
			}
		})
	}
	badConnection := fixture.connection
	badConnection.ConnectionID = approvalTestUUID(t)
	for _, variant := range []struct {
		connection RuntimeConnection
		key        int64
	}{{badConnection, 1}, {fixture.connection, 2}} {
		if _, err := fixture.control.Register(fixture.ctx, variant.connection, variant.key, approvalRaw(t, fixture.request)); !errors.Is(err, ErrRuntimeConnectionStale) {
			t.Fatalf("untrusted host connection: %v", err)
		}
	}
	assertApprovalCounts(t, fixture, 0, 0, 0, 0)
	for range 2 {
		if status := fixture.register(t, fixture.request); status.State != "pending" {
			t.Fatal("new request was not pending")
		}
	}
	changed := fixture.request
	changed.Arguments = json.RawMessage(`{"command":"different command"}`)
	if _, err := fixture.control.Register(fixture.ctx, fixture.connection, 1, approvalRaw(t, changed)); !errors.Is(err, ErrApprovalConflict) {
		t.Fatalf("approval ID rebound to new arguments: %v", err)
	}
	for _, field := range []string{"nonce", "execution"} {
		request := fixture.freshRequest(t)
		if field == "nonce" {
			request.Nonce = fixture.request.Nonce
		} else {
			request.ExecutionID = fixture.request.ExecutionID
		}
		if _, err := fixture.control.Register(fixture.ctx, fixture.connection, 1, approvalRaw(t, request)); !errors.Is(err, ErrApprovalConflict) {
			t.Fatalf("%s reused for another request: %v", field, err)
		}
	}
	assertApprovalCounts(t, fixture, 1, 1, 0, 0)
	var persisted string
	if err := fixture.database.DB.QueryRowContext(fixture.ctx, `select row_to_json(a)::text from approvals a`).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-tool-argument", fixture.request.CallID, fixture.request.Nonce, "root_sha256", "resources", "arguments"} {
		if strings.Contains(persisted, secret) {
			t.Fatalf("pending metadata persisted private context field %s", secret)
		}
	}
}

func TestPostgresApprovalDecisionRequiresLiveOwnerDeviceScopeAndAssurance(t *testing.T) {
	fixture := newApprovalFixture(t)
	fixture.register(t, fixture.request)
	compact := fixture.signed(t, fixture.request, "allow_once")
	for _, test := range []struct {
		name   string
		mutate func(*auth.Principal, *TicketRedemption)
	}{
		{"issuer", func(p *auth.Principal, _ *TicketRedemption) { p.Issuer = "https://attacker.example" }},
		{"subject", func(p *auth.Principal, _ *TicketRedemption) { p.Subject = "target-subject" }},
		{"proof key", func(p *auth.Principal, _ *TicketRedemption) { p.ProofKeyJKT = "other" }},
		{"missing proof", func(p *auth.Principal, _ *TicketRedemption) { p.ProofJTI = "" }},
		{"missing auth time", func(p *auth.Principal, _ *TicketRedemption) { p.AuthenticatedAt = time.Time{} }},
		{"stale auth", func(p *auth.Principal, _ *TicketRedemption) {
			p.AuthenticatedAt = time.Now().Add(-time.Minute - time.Second)
		}},
		{"expired token", func(p *auth.Principal, _ *TicketRedemption) { p.ExpiresAt = time.Now().Add(-time.Second) }},
		{"wrong client", func(p *auth.Principal, _ *TicketRedemption) { p.ClientID = "desktop" }},
		{"wrong acr", func(p *auth.Principal, _ *TicketRedemption) { p.ACR = "urn:test:step-up-higher" }},
		{"missing amr", func(p *auth.Principal, _ *TicketRedemption) { p.AMR = nil }},
		{"user", func(_ *auth.Principal, k *TicketRedemption) { k.UserID = approvalTestUUID(t) }},
		{"device", func(_ *auth.Principal, k *TicketRedemption) { k.DeviceID = approvalTestUUID(t) }},
		{"runtime", func(_ *auth.Principal, k *TicketRedemption) { k.RuntimeID = approvalTestUUID(t) }},
		{"key version", func(_ *auth.Principal, k *TicketRedemption) { k.DeviceKeyVersion++ }},
		{"grant version", func(_ *auth.Principal, k *TicketRedemption) { k.GrantVersion++ }},
		{"action", func(_ *auth.Principal, k *TicketRedemption) { k.Scope.Actions = []string{"session.read"} }},
		{"workspace", func(_ *auth.Principal, k *TicketRedemption) { k.Scope.Workspaces = nil }},
		{"session scope", func(_ *auth.Principal, k *TicketRedemption) {
			k.Scope.Workspaces = nil
			k.Scope.Sessions = []string{approvalTestUUID(t)}
		}},
		{"ticket widened", func(_ *auth.Principal, k *TicketRedemption) {
			k.Scope.Actions = []string{"approval.decide", "session.read"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			principal, ticket := fixture.principal, fixture.ticket
			test.mutate(&principal, &ticket)
			if _, err := fixture.control.Decide(fixture.ctx, principal, ticket, approvalRaw(t, fixture.request), compact); err == nil {
				t.Fatal("untrusted decision authority accepted")
			}
			assertApprovalPending(t, fixture, fixture.request)
		})
	}
	for _, test := range []struct {
		name, mutate, restore string
		args                  []any
	}{
		{"operator", `update runtime_grants set role = 'operator'`, `update runtime_grants set role = 'owner'`, nil},
		{"revoked grant", `update runtime_grants set revoked_at = now()`, `update runtime_grants set revoked_at = null`, nil},
		{"expired grant", `update runtime_grants set expires_at = now() - interval '1 second'`, `update runtime_grants set expires_at = null`, nil},
		{"grant changed", `update runtime_grants set grant_version = 2`, `update runtime_grants set grant_version = 1`, nil},
		{"action removed", `update runtime_grants set scope = jsonb_set(scope, '{actions}', '["grant.manage"]')`, `update runtime_grants set scope = jsonb_set(scope, '{actions}', '["approval.decide","grant.manage"]')`, nil},
		{"device revoked", `update devices set revoked_at = now()`, `update devices set revoked_at = null`, nil},
		{"device rotated", `update devices set key_version = 2`, `update devices set key_version = 1`, nil},
		{"wrong approval key", `update devices set approval_key_thumbprint = 'wrong' where id = $1`, `update devices set approval_key_thumbprint = $2 where id = $1`, []any{fixture.ticket.DeviceID, approvalFixtureKeyJKT(t, fixture)}},
		{"user suspended", `update users set status = 'suspended'`, `update users set status = 'active'`, nil},
		{"host revoked", `update hosts set state = 'revoked'`, `update hosts set state = 'active'`, nil},
		{"installation revoked", `update installations set revoked_at = now()`, `update installations set revoked_at = null`, nil},
		{"installation rotated", `update installations set key_version = 2`, `update installations set key_version = 1`, nil},
		{"runtime revoked", `update runtimes set revoked_at = now()`, `update runtimes set revoked_at = null`, nil},
		{"stale host heartbeat", `update runtimes set last_seen_at = now() - interval '46 seconds'`, `update runtimes set last_seen_at = clock_timestamp()`, nil},
		{"host disconnected", `update runtimes set connection_id = null, connection_key_version = null`, `update runtimes set connection_id = $1, connection_key_version = 1`, []any{fixture.connection.ConnectionID}},
		{"session unavailable", `update sessions set state = 'unavailable' where id = $1`, `update sessions set state = 'running' where id = $1`, []any{fixture.request.SessionID}},
		{"session archived", `update sessions set state = 'archived' where id = $1`, `update sessions set state = 'running' where id = $1`, []any{fixture.request.SessionID}},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Different statements use the same argument tuple only where needed.
			args := test.args
			if test.name == "host disconnected" {
				args = nil
			}
			if test.name == "wrong approval key" {
				args = args[:1]
			}
			if _, err := fixture.database.DB.ExecContext(fixture.ctx, test.mutate, args...); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if _, err := fixture.database.DB.ExecContext(fixture.ctx, test.restore, test.args...); err != nil {
					t.Fatal(err)
				}
			})
			if _, err := fixture.control.Decide(fixture.ctx, fixture.principal, fixture.ticket, approvalRaw(t, fixture.request), compact); err == nil {
				t.Fatal("revoked or unavailable authority accepted")
			}
			assertApprovalPending(t, fixture, fixture.request)
		})
	}
	// Changing arguments or signature must not spend the pending nonce.
	changed := fixture.request
	changed.Arguments = json.RawMessage(`{"command":"changed"}`)
	for _, input := range []struct {
		raw     []byte
		compact string
	}{{approvalRaw(t, changed), compact}, {approvalRaw(t, fixture.request), compact[:len(compact)-2] + "!!"}} {
		if _, err := fixture.control.Decide(fixture.ctx, fixture.principal, fixture.ticket, input.raw, input.compact); err == nil {
			t.Fatal("changed signed content accepted")
		}
		assertApprovalPending(t, fixture, fixture.request)
	}
	assertApprovalCounts(t, fixture, 1, 1, 0, 0)
	status, err := fixture.control.Decide(fixture.ctx, fixture.principal, fixture.ticket, approvalRaw(t, fixture.request), compact)
	if err != nil || status.State != "decision_received" || status.Decision != "allow_once" {
		t.Fatalf("valid owner approval: status=%+v error=%v", status, err)
	}
	for _, retry := range []string{compact, equivalentApprovalSignature(t, compact)} {
		if got, err := fixture.control.Decide(fixture.ctx, fixture.principal, fixture.ticket, approvalRaw(t, fixture.request), retry); err != nil || got.PayloadSHA256 != status.PayloadSHA256 {
			t.Fatalf("canonical decision retry: %+v %v", got, err)
		}
	}
	if _, err := fixture.control.Decide(fixture.ctx, fixture.principal, fixture.ticket, approvalRaw(t, fixture.request), fixture.signed(t, fixture.request, "reject")); !errors.Is(err, ErrApprovalConflict) {
		t.Fatalf("second conflicting choice replaced decision: %v", err)
	}
	assertApprovalCounts(t, fixture, 1, 1, 1, 0)
}

func approvalFixtureKeyJKT(t *testing.T, fixture *approvalFixture) string {
	t.Helper()
	raw, _ := integrationP256JWK(fixture.key)
	jkt, err := auth.PublicP256JWKThumbprintJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return jkt
}

func equivalentApprovalSignature(t *testing.T, compact string) string {
	t.Helper()
	parts := strings.Split(compact, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	s := new(big.Int).SetBytes(signature[32:])
	new(big.Int).Sub(elliptic.P256().Params().N, s).FillBytes(signature[32:])
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	return strings.Join(parts, ".")
}

func TestPostgresApprovalCompetingDevicesProduceOneDurableDecision(t *testing.T) {
	fixture := newApprovalFixture(t)
	fixture.register(t, fixture.request)
	other := *fixture
	other.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other.ticket.DeviceID = approvalTestUUID(t)
	other.ticket.ProofKeyThumbprint = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	other.principal.ProofKeyJKT = other.ticket.ProofKeyThumbprint
	publicJWK, _ := integrationP256JWK(other.key)
	if _, err := fixture.database.DB.ExecContext(fixture.ctx, `
		insert into devices (id, user_id, name, approval_public_jwk, approval_key_thumbprint, proof_public_jwk, proof_key_thumbprint)
		values ($1, $2, 'second phone', $3, $4, '{}'::jsonb, $5)`, other.ticket.DeviceID, other.ticket.UserID, publicJWK, approvalFixtureKeyJKT(t, &other), other.ticket.ProofKeyThumbprint); err != nil {
		t.Fatal(err)
	}
	compacts := []string{fixture.signed(t, fixture.request, "allow_once"), other.signed(t, fixture.request, "reject")}
	results := make(chan error, 2)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for index, actor := range []*approvalFixture{fixture, &other} {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, err := actor.control.Decide(actor.ctx, actor.principal, actor.ticket, approvalRaw(t, actor.request), compacts[index])
			results <- err
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	succeeded, conflicts := 0, 0
	for err := range results {
		if err == nil {
			succeeded++
		} else if errors.Is(err, ErrApprovalConflict) {
			conflicts++
		} else {
			t.Fatalf("competing decision failed unexpectedly: %v", err)
		}
	}
	if succeeded != 1 || conflicts != 1 {
		t.Fatalf("race produced success=%d conflict=%d", succeeded, conflicts)
	}
	assertApprovalCounts(t, fixture, 1, 1, 1, 0)
}

func TestPostgresApprovalAuditOutboxAndCASFailuresConsumeNothing(t *testing.T) {
	fixture := newApprovalFixture(t)
	fixture.register(t, fixture.request)
	compact := fixture.signed(t, fixture.request, "allow_once")
	for _, target := range []string{"audit_log", "control_outbox", "approvals"} {
		t.Run(target, func(t *testing.T) {
			body, event := `raise exception 'test unavailable';`, "insert"
			if target == "approvals" {
				body, event = "return null;", "update"
			}
			if _, err := fixture.database.DB.ExecContext(fixture.ctx, `create function reject_approval_write() returns trigger language plpgsql as $$ begin `+body+` end $$; create trigger reject_approval_write before `+event+` on `+target+` for each row execute function reject_approval_write()`); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if _, err := fixture.database.DB.ExecContext(fixture.ctx, `drop trigger reject_approval_write on `+target+`; drop function reject_approval_write()`); err != nil {
					t.Fatal(err)
				}
			})
			if _, err := fixture.control.Decide(fixture.ctx, fixture.principal, fixture.ticket, approvalRaw(t, fixture.request), compact); err == nil {
				t.Fatal("decision survived failed durable admission")
			}
			assertApprovalPending(t, fixture, fixture.request)
			assertApprovalCounts(t, fixture, 1, 1, 0, 0)
		})
	}
	if _, err := fixture.control.Decide(fixture.ctx, fixture.principal, fixture.ticket, approvalRaw(t, fixture.request), compact); err != nil {
		t.Fatal(err)
	}
	assertApprovalCounts(t, fixture, 1, 1, 1, 0)
}

func TestPostgresApprovalReconnectFencesPendingAndRetainsUnknownExecution(t *testing.T) {
	fixture := newApprovalFixture(t)
	fixture.register(t, fixture.request)
	accepted := fixture.freshRequest(t)
	fixture.register(t, accepted)
	if _, err := fixture.control.Decide(fixture.ctx, fixture.principal, fixture.ticket, approvalRaw(t, accepted), fixture.signed(t, accepted, "allow_once")); err != nil {
		t.Fatal(err)
	}
	replacement, err := fixture.database.AttachRuntimeConnection(fixture.ctx, RuntimeConnectionInput{InstallationID: fixture.connection.InstallationID, KeyVersion: 1,
		RuntimeID: fixture.connection.RuntimeID, RuntimeEpoch: fixture.connection.RuntimeEpoch, ConnectionID: approvalTestUUID(t), DSHVersion: "0.2.1-rc.2", ApplicationVersion: "npm-dsh", PluginVersion: "test", ProtocolVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ id, state string }{{fixture.request.ApprovalID, "invalidated"}, {accepted.ApprovalID, "outcome_unknown"}} {
		var state string
		if err := fixture.database.DB.QueryRowContext(fixture.ctx, `select state from approvals where id = $1`, test.id).Scan(&state); err != nil || state != test.state {
			t.Fatalf("reconnect state=%s want=%s error=%v", state, test.state, err)
		}
	}
	assertApprovalCounts(t, fixture, 2, 2, 1, 2)
	if err := fixture.database.DetachRuntimeConnection(fixture.ctx, fixture.connection.InstallationID, fixture.connection.RuntimeID, fixture.connection.RuntimeEpoch, fixture.connection.ConnectionID); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.SyncRealtimeSessionCatalog(fixture.ctx, replacement, 1, true, []SessionCatalogItem{{SessionID: fixture.request.SessionID, DSHSessionID: fixture.request.DSHSessionID, WorkspaceID: ptr(fixture.request.Workspace.WorkspaceID), State: "running", LastPersistedSeq: -1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.control.Register(fixture.ctx, replacement, 1, approvalRaw(t, fixture.request)); !errors.Is(err, ErrRuntimeConnectionStale) {
		t.Fatalf("old request revived on replacement connection: %v", err)
	}
	fixture.connection = replacement
	fresh := fixture.freshRequest(t)
	fixture.register(t, fresh)
	if err := fixture.database.DetachRuntimeConnection(fixture.ctx, replacement.InstallationID, replacement.RuntimeID, replacement.RuntimeEpoch, replacement.ConnectionID); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := fixture.database.DB.QueryRowContext(fixture.ctx, `select state from approvals where id = $1`, fresh.ApprovalID).Scan(&state); err != nil || state != "invalidated" {
		t.Fatalf("detach state=%s error=%v", state, err)
	}
	assertApprovalCounts(t, fixture, 3, 3, 1, 3)
}

func TestPostgresApprovalRegistrationLimitIsAtomic(t *testing.T) {
	fixture := newApprovalFixture(t)
	for range maxActiveApprovals - 1 {
		fixture.register(t, fixture.freshRequest(t))
	}
	requests := []approval.Context{fixture.freshRequest(t), fixture.freshRequest(t)}
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for _, request := range requests {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_, err := fixture.control.Register(fixture.ctx, fixture.connection, 1, approvalRaw(t, request))
			results <- err
		}()
	}
	workers.Wait()
	close(results)
	succeeded, limited := 0, 0
	for err := range results {
		if err == nil {
			succeeded++
		} else if errors.Is(err, ErrApprovalLimit) {
			limited++
		} else {
			t.Fatal(err)
		}
	}
	if succeeded != 1 || limited != 1 {
		t.Fatalf("concurrent limit: succeeded=%d limited=%d", succeeded, limited)
	}
	assertApprovalCounts(t, fixture, maxActiveApprovals, maxActiveApprovals, 0, 0)
}

func TestPostgresApprovalRechecksExpiryAfterWaitingForPendingRow(t *testing.T) {
	fixture := newApprovalFixture(t)
	fixture.register(t, fixture.request)
	compact := fixture.signed(t, fixture.request, "allow_once")
	for _, expiry := range []string{"token", "grant"} {
		t.Run(expiry, func(t *testing.T) {
			principal := fixture.principal
			deadline := time.Now().UTC().Add(100 * time.Millisecond)
			if expiry == "token" {
				principal.ExpiresAt = deadline
			} else {
				if _, err := fixture.database.DB.ExecContext(fixture.ctx, `update runtime_grants set expires_at = $1`, deadline); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					_, _ = fixture.database.DB.ExecContext(fixture.ctx, `update runtime_grants set expires_at = null`)
				})
			}
			lock, err := fixture.database.DB.BeginTx(fixture.ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Rollback()
			if _, err := lock.ExecContext(fixture.ctx, `select id from approvals where id = $1 for update`, fixture.request.ApprovalID); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				_, err := fixture.control.Decide(fixture.ctx, principal, fixture.ticket, approvalRaw(t, fixture.request), compact)
				result <- err
			}()
			time.Sleep(time.Until(deadline) + 30*time.Millisecond)
			if err := lock.Commit(); err != nil {
				t.Fatal(err)
			}
			if err := <-result; err == nil {
				t.Fatal("expired authority survived waiting for a row lock")
			}
			assertApprovalPending(t, fixture, fixture.request)
		})
	}
	assertApprovalCounts(t, fixture, 1, 1, 0, 0)
}

func TestPostgresApprovalRegistrationStorageFailureLeavesNoTombstone(t *testing.T) {
	fixture := newApprovalFixture(t)
	if _, err := fixture.database.DB.ExecContext(fixture.ctx, `
		create function reject_pending_audit() returns trigger language plpgsql as $$ begin raise exception 'test unavailable'; end $$;
		create trigger reject_pending_audit before insert on audit_log for each row execute function reject_pending_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.control.Register(fixture.ctx, fixture.connection, 1, approvalRaw(t, fixture.request)); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatalf("registration survived failed audit: %v", err)
	}
	assertApprovalCounts(t, fixture, 0, 0, 0, 0)
	if _, err := fixture.database.DB.ExecContext(fixture.ctx, `drop trigger reject_pending_audit on audit_log; drop function reject_pending_audit()`); err != nil {
		t.Fatal(err)
	}
	fixture.register(t, fixture.request)
	assertApprovalCounts(t, fixture, 1, 1, 0, 0)
}

func TestPostgresApprovalExpiredRequestsFreeCapacityWithoutRevivingDecisions(t *testing.T) {
	fixture := newApprovalFixture(t)
	fixture.request.CreatedAt = time.Now().Add(-time.Minute).UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
	fixture.request.ExpiresAt = time.Now().Add(300 * time.Millisecond).UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
	fixture.register(t, fixture.request)
	accepted := fixture.freshRequest(t)
	fixture.register(t, accepted)
	if _, err := fixture.control.Decide(fixture.ctx, fixture.principal, fixture.ticket, approvalRaw(t, accepted), fixture.signed(t, accepted, "allow_once")); err != nil {
		t.Fatal(err)
	}
	deadline, _ := time.Parse(time.RFC3339Nano, accepted.ExpiresAt)
	time.Sleep(time.Until(deadline) + 10*time.Millisecond)
	fresh := fixture.freshRequest(t)
	fresh.CreatedAt = time.Now().Add(-time.Second).UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
	fresh.ExpiresAt = time.Now().Add(time.Minute).UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
	fixture.register(t, fresh)
	for _, test := range []struct{ id, state string }{{fixture.request.ApprovalID, "expired"}, {accepted.ApprovalID, "outcome_unknown"}, {fresh.ApprovalID, "pending"}} {
		var state string
		if err := fixture.database.DB.QueryRowContext(fixture.ctx, `select state from approvals where id = $1`, test.id).Scan(&state); err != nil || state != test.state {
			t.Fatalf("expiry state=%s want=%s error=%v", state, test.state, err)
		}
	}
	assertApprovalCounts(t, fixture, 3, 3, 1, 2)
}

func TestPostgresApprovalRejectIsDurableAndCannotBecomeAllow(t *testing.T) {
	fixture := newApprovalFixture(t)
	fixture.register(t, fixture.request)
	compact := fixture.signed(t, fixture.request, "reject")
	for range 2 {
		status, err := fixture.control.Decide(fixture.ctx, fixture.principal, fixture.ticket, approvalRaw(t, fixture.request), compact)
		if err != nil || status.State != "denied" || status.Decision != "reject" {
			t.Fatalf("rejected approval: %+v %v", status, err)
		}
	}
	if _, err := fixture.control.Decide(fixture.ctx, fixture.principal, fixture.ticket, approvalRaw(t, fixture.request), fixture.signed(t, fixture.request, "allow_once")); !errors.Is(err, ErrApprovalConflict) {
		t.Fatalf("denied approval became allowed: %v", err)
	}
	assertApprovalCounts(t, fixture, 1, 1, 1, 0)
}

func TestPostgresApprovalMissingMembershipAndUnregisteredRequestFailClosed(t *testing.T) {
	fixture := newApprovalFixture(t)
	compact := fixture.signed(t, fixture.request, "allow_once")
	if _, err := fixture.control.Decide(fixture.ctx, fixture.principal, fixture.ticket, approvalRaw(t, fixture.request), compact); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("unregistered context acquired approval: %v", err)
	}
	fixture.register(t, fixture.request)
	if _, err := fixture.database.DB.ExecContext(fixture.ctx, `delete from org_memberships where user_id = $1`, fixture.ticket.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.control.Decide(fixture.ctx, fixture.principal, fixture.ticket, approvalRaw(t, fixture.request), compact); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("missing current organization membership accepted: %v", err)
	}
	assertApprovalPending(t, fixture, fixture.request)
	assertApprovalCounts(t, fixture, 1, 1, 0, 0)
}

func TestPostgresApprovalAdmissionTimeoutDoesNotConsumePendingRow(t *testing.T) {
	fixture := newApprovalFixture(t)
	fixture.register(t, fixture.request)
	compact := fixture.signed(t, fixture.request, "allow_once")
	lock, err := fixture.database.DB.BeginTx(fixture.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err := lock.ExecContext(fixture.ctx, `select id from approvals where id = $1 for update`, fixture.request.ApprovalID); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := fixture.control.Decide(fixture.ctx, fixture.principal, fixture.ticket, approvalRaw(t, fixture.request), compact); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatalf("blocked admission failed to time out: %v", err)
	}
	if time.Since(started) > 3*time.Second {
		t.Fatal("admission exceeded its bounded database wait")
	}
	if err := lock.Rollback(); err != nil {
		t.Fatal(err)
	}
	assertApprovalPending(t, fixture, fixture.request)
	assertApprovalCounts(t, fixture, 1, 1, 0, 0)
}

func TestPostgresApprovalMigrationInvalidatesLegacyPendingAndPreservesAudit(t *testing.T) {
	fixture := newApprovalFixture(t)
	_, file, _, _ := runtime.Caller(0)
	apply := func(name, direction string) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../../../deploy/sql/"+name+"."+direction+".sql"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.database.DB.ExecContext(fixture.ctx, string(raw)); err != nil {
			t.Fatalf("approval migration %s: %v", direction, err)
		}
	}
	// Exercise the historical migration with newer dependencies removed first.
	apply("045_approval_evidence_retention", "down")
	apply("030_cold_history_imports", "down")
	apply("028_approval_evidence_exports", "down")
	apply("027_approval_evidence_fingerprints", "down")
	apply("025_approval_decision_evidence", "down")
	fixture.register(t, fixture.request)
	if _, err := fixture.control.Decide(fixture.ctx, fixture.principal, fixture.ticket, approvalRaw(t, fixture.request), fixture.signed(t, fixture.request, "allow_once")); err != nil {
		t.Fatal(err)
	}
	apply("007_approval_host_results", "down")
	apply("006_approval_control", "down")
	legacyID := approvalTestUUID(t)
	if _, err := fixture.database.DB.ExecContext(fixture.ctx, `
		insert into approvals (id, session_id, runtime_epoch, execution_id, call_id, binding_sha256, policy_version, state, expires_at)
		values ($1, $2, $3, $4, 'legacy-call', $5, 1, 'pending', clock_timestamp() + interval '1 minute')`,
		legacyID, fixture.request.SessionID, fixture.request.RuntimeEpoch, approvalTestUUID(t), strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.DB.ExecContext(fixture.ctx, `
		insert into approvals (id, session_id, runtime_epoch, execution_id, binding_sha256, policy_version, state, expires_at)
		values ($1, $2, $3, $4, $5, 1, 'decision_received', clock_timestamp() + interval '1 minute')`,
		approvalTestUUID(t), fixture.request.SessionID, fixture.request.RuntimeEpoch, approvalTestUUID(t), strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	apply("006_approval_control", "up")
	apply("007_approval_host_results", "up")
	apply("025_approval_decision_evidence", "up")
	apply("027_approval_evidence_fingerprints", "up")
	apply("028_approval_evidence_exports", "up")
	apply("030_cold_history_imports", "up")
	apply("045_approval_evidence_retention", "up")
	var invalidated int
	if err := fixture.database.DB.QueryRowContext(fixture.ctx, `select count(*) from approvals where metadata_version = 0 and state = 'invalidated'`).Scan(&invalidated); err != nil || invalidated != 2 {
		t.Fatalf("migration revived legacy approvals: count=%d error=%v", invalidated, err)
	}
	var uncertain int
	if err := fixture.database.DB.QueryRowContext(fixture.ctx, `select count(*) from approvals where metadata_version = 0 and state = 'outcome_unknown'`).Scan(&uncertain); err != nil || uncertain != 1 {
		t.Fatalf("migration lost uncertain legacy execution: count=%d error=%v", uncertain, err)
	}
	if _, err := fixture.control.Decide(fixture.ctx, fixture.principal, fixture.ticket, approvalRaw(t, fixture.request), fixture.signed(t, fixture.request, "allow_once")); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("legacy decision was reused after re-upgrade: %v", err)
	}
	assertApprovalCounts(t, fixture, 3, 1, 1, 0)
}
