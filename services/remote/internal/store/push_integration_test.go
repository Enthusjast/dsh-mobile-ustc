package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/push"
)

type pushFixture struct {
	*approvalFixture
	push   *PushStore
	actor  push.Actor
	cipher *push.Cipher
	lookup []byte
}

func newPushFixture(t *testing.T) *pushFixture {
	t.Helper()
	h := newApprovalFixture(t)
	key, lookup := make([]byte, 32), make([]byte, 32)
	_, _ = rand.Read(key)
	_, _ = rand.Read(lookup)
	cipher, err := push.NewCipher("one", map[string][]byte{"one": key}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(lookup)
	store, err := NewPushStore(h.ctx, h.database, cipher, h.principal.Issuer, "fixture-project", "cn.edu.ustc.dsh.mobile", hex.EncodeToString(fingerprint[:]), h.control)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.database.DB.ExecContext(h.ctx, `update runtime_grants set scope=jsonb_set(scope,'{actions}','["session.read","approval.decide","grant.manage"]')`); err != nil {
		t.Fatal(err)
	}
	return &pushFixture{approvalFixture: h, push: store, cipher: cipher, lookup: lookup, actor: push.Actor{Issuer: h.principal.Issuer, Subject: h.principal.Subject, DeviceID: h.ticket.DeviceID, ProofKeyJKT: h.ticket.ProofKeyThumbprint}}
}
func pushTestSecret(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
func (h *pushFixture) register(t *testing.T, address string) (push.Registration, string, push.Claim, push.Outbound) {
	t.Helper()
	secret := pushTestSecret(t)
	input := push.Registration{BindingID: approvalTestUUID(t), OrganizationID: h.request.Workspace.WorkspaceID, Provider: "fcm", Address: address, RevokeSHA256: push.SecretHash(secret)}
	if err := h.database.DB.QueryRowContext(h.ctx, `select id::text from orgs limit 1`).Scan(&input.OrganizationID); err != nil {
		t.Fatal(err)
	}
	state, err := h.push.Register(h.ctx, h.actor, input)
	if err != nil || state.State != "pending" {
		t.Fatalf("register: %v", err)
	}
	claim, err := h.push.Claim(h.ctx)
	if err != nil || claim == nil {
		t.Fatal("ownership challenge was not queued")
	}
	out, err := h.push.Authorize(h.ctx, *claim)
	if err != nil || out.Kind != "challenge" || out.Address != address || !push.Secret(out.Challenge) {
		t.Fatalf("challenge: %v", err)
	}
	return input, secret, *claim, out
}
func (h *pushFixture) active(t *testing.T) (push.Registration, string) {
	t.Helper()
	input, secret, claim, out := h.register(t, "c"+strings.Repeat("A", 21))
	if err := h.push.Complete(h.ctx, claim, push.Result{State: push.Accepted, ProviderID: strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	state, err := h.push.Confirm(h.ctx, h.actor, input.BindingID, out.Challenge)
	if err != nil || state.State != "active" {
		t.Fatalf("confirm: %v", err)
	}
	return input, secret
}
func TestPushRegistrationRequiresPossessionAndEncryptedOriginalOwnership(t *testing.T) {
	h := newPushFixture(t)
	input, secret, claim, out := h.register(t, "c"+strings.Repeat("B", 21))
	state, err := h.push.Register(h.ctx, h.actor, input)
	if err != nil || state.ID != input.BindingID {
		t.Fatal("original registration was not recovered")
	}
	changed := input
	changed.Address = "d" + strings.Repeat("C", 21)
	if _, err = h.push.Register(h.ctx, h.actor, changed); !errors.Is(err, push.ErrConflict) {
		t.Fatal("original endpoint changed")
	}
	if _, err = h.push.Confirm(h.ctx, h.actor, input.BindingID, pushTestSecret(t)); !errors.Is(err, push.ErrAccess) {
		t.Fatal("unknown nonce proved ownership")
	}
	other := h.actor
	other.ProofKeyJKT = strings.Repeat("Z", 43)
	if _, err = h.push.Confirm(h.ctx, other, input.BindingID, out.Challenge); !errors.Is(err, push.ErrAccess) {
		t.Fatal("challenge crossed device keys")
	}
	if err = h.push.Plan(h.ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if h.database.DB.QueryRowContext(h.ctx, `select count(*) from push_deliveries where kind<>'challenge'`).Scan(&count) != nil || count != 0 {
		t.Fatal("unverified channel received an interaction")
	}
	if _, err = h.push.Confirm(h.ctx, h.actor, input.BindingID, out.Challenge); err != nil {
		t.Fatal(err)
	}
	// A phone may confirm before the provider's HTTP response reaches the worker.
	if err = h.push.Complete(h.ctx, claim, push.Result{State: push.Accepted}); !errors.Is(err, push.ErrLease) {
		t.Fatal("late provider result replaced confirmed channel")
	}
	if state, err = h.push.Renew(h.ctx, h.actor, input.BindingID); err != nil || state.State != "active" {
		t.Fatal("confirmed channel did not renew")
	}
	var ciphertext []byte
	var meta string
	if h.database.DB.QueryRowContext(h.ctx, `select address_ciphertext,request_sha256 from push_bindings where id=$1`, input.BindingID).Scan(&ciphertext, &meta) != nil || strings.Contains(string(ciphertext), input.Address) || !push.Digest(meta) {
		t.Fatal("clear endpoint persisted")
	}
	if err = h.push.Revoke(h.ctx, input.BindingID, pushTestSecret(t)); err != nil {
		t.Fatal(err)
	}
	if state, err = h.push.Status(h.ctx, h.actor, input.BindingID); err != nil || state.State != "active" {
		t.Fatal("unknown deletion secret disabled channel")
	}
	if err = h.push.Revoke(h.ctx, input.BindingID, secret); err != nil {
		t.Fatal(err)
	}
	if state, err = h.push.Status(h.ctx, h.actor, input.BindingID); err != nil || state.State != "disabled" {
		t.Fatal("logout deletion capability did not disable channel")
	}
	if h.database.DB.QueryRowContext(h.ctx, `select count(*) from push_bindings where address_ciphertext is not null`).Scan(&count) != nil || count != 0 {
		t.Fatal("revocation kept provider endpoint")
	}
}
func TestPushSameSessionReferencesRemainIndependentAndAuthorizationIsCurrent(t *testing.T) {
	h := newPushFixture(t)
	input, _ := h.active(t)
	for range 2 {
		request := h.freshRequest(t)
		if _, err := h.control.Register(h.ctx, h.connection, 1, approvalRaw(t, request)); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := h.push.Plan(h.ctx); err != nil {
			t.Fatal(err)
		}
	}
	claims := []push.Claim{}
	for range 2 {
		claim, err := h.push.Claim(h.ctx)
		if err != nil || claim == nil {
			t.Fatal("same-session approval was collapsed")
		}
		claims = append(claims, *claim)
	}
	if claims[0].ID == claims[1].ID {
		t.Fatal("independent approvals shared a notification")
	}
	for _, claim := range claims {
		out, err := h.push.Authorize(h.ctx, claim)
		if err != nil || out.Kind != "approval" || out.Challenge != "" || out.NotificationID != claim.ID {
			t.Fatalf("authorized alert: %v", err)
		}
	}
	if err := h.push.Complete(h.ctx, claims[0], push.Result{State: push.Accepted, ProviderID: strings.Repeat("b", 64)}); err != nil {
		t.Fatal(err)
	}
	if err := h.push.Receipt(h.ctx, h.actor, claims[0].ID, "opened"); err != nil {
		t.Fatal(err)
	}
	if err := h.push.Receipt(h.ctx, h.actor, claims[0].ID, "opened"); err != nil {
		t.Fatal(err)
	}
	page, err := h.push.Inbox(h.ctx, h.actor, input.BindingID, "")
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("inbox lost references: %v", err)
	}
	var pending int
	if h.database.DB.QueryRowContext(h.ctx, `select count(*) from approvals where state='pending'`).Scan(&pending) != nil || pending != 2 {
		t.Fatal("client telemetry changed execution authority")
	}
	if _, err = h.database.DB.ExecContext(h.ctx, `update runtimes set last_seen_at=clock_timestamp()-interval '46 seconds'`); err != nil {
		t.Fatal(err)
	}
	offline, err := h.push.Reference(h.ctx, h.actor, claims[0].ID)
	if err != nil || offline.Availability != "host_offline" {
		t.Fatal("offline host was presented as actionable")
	}
	if h.push.Recheck(h.ctx, claims[1]) == nil {
		t.Fatal("offline host alert was sent as current")
	}
	if _, err = h.database.DB.ExecContext(h.ctx, `update runtimes set last_seen_at=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	var receipts int
	if h.database.DB.QueryRowContext(h.ctx, `select count(*) from push_receipts`).Scan(&receipts) != nil || receipts != 1 {
		t.Fatal("client receipt was not deduplicated")
	}
	if _, err = h.database.DB.ExecContext(h.ctx, `update runtime_grants set revoked_at=clock_timestamp(),grant_version=grant_version+1`); err != nil {
		t.Fatal(err)
	}
	if h.push.Recheck(h.ctx, claims[1]) == nil {
		t.Fatal("revoked grant reached provider")
	}
	if _, err = h.push.Reference(h.ctx, h.actor, claims[0].ID); !errors.Is(err, push.ErrAccess) {
		t.Fatal("old notification exposed revoked context")
	}
}
func TestPushEndpointCannotBeTakenOverAndRetiredLeasesCannotComplete(t *testing.T) {
	h := newPushFixture(t)
	first, firstSecret := h.active(t)
	other := h.actor
	other.DeviceID = approvalTestUUID(t)
	other.ProofKeyJKT = pushTestSecret(t)
	if _, err := h.database.DB.ExecContext(h.ctx, `insert into devices(id,user_id,name,approval_public_jwk,approval_key_thumbprint,proof_public_jwk,proof_key_thumbprint)
        select $1,user_id,'other endpoint holder',approval_public_jwk,$2,proof_public_jwk,$3 from devices where id=$4`, other.DeviceID, pushTestSecret(t), other.ProofKeyJKT, h.actor.DeviceID); err != nil {
		t.Fatal(err)
	}
	h.actor = other
	input, _, _, out := h.register(t, first.Address)
	if _, err := h.push.Confirm(h.ctx, h.actor, input.BindingID, out.Challenge); !errors.Is(err, push.ErrConflict) {
		t.Fatal("existing active endpoint was silently replaced")
	}
	var count int
	if h.database.DB.QueryRowContext(h.ctx, `select count(*) from push_bindings where state='active'`).Scan(&count) != nil || count != 1 {
		t.Fatal("channel collision changed original authority")
	}
	// Retire an actual dispatch lease and ensure another worker owns the retry.
	if _, err := h.database.DB.ExecContext(h.ctx, `update push_deliveries set lease_until=clock_timestamp()-interval '1 second' where binding_id=$1`, input.BindingID); err != nil {
		t.Fatal(err)
	}
	claim, err := h.push.Claim(h.ctx)
	if err != nil || claim == nil {
		t.Fatal("expired lease did not recover")
	}
	old := *claim
	old.LeaseID = approvalTestUUID(t)
	if err = h.push.Complete(h.ctx, old, push.Result{State: push.Accepted}); !errors.Is(err, push.ErrLease) {
		t.Fatal("retired lease changed delivery")
	}
	if err = h.push.Complete(h.ctx, *claim, push.Result{State: push.Retry, Code: "provider_throttled", RetryAfter: time.Minute}); err != nil {
		t.Fatal(err)
	}
	if next, err := h.push.Claim(h.ctx); err != nil || next != nil {
		t.Fatal("provider Retry-After was ignored")
	}
	if err := h.push.Revoke(h.ctx, first.BindingID, firstSecret); err != nil {
		t.Fatal(err)
	}
	if state, err := h.push.Confirm(h.ctx, h.actor, input.BindingID, out.Challenge); err != nil || state.State != "active" {
		t.Fatal("explicitly retired endpoint could not transfer after proof")
	}
}
func TestPushLookupKeyCannotSilentlyRotateAndCiphertextCannotMove(t *testing.T) {
	h := newPushFixture(t)
	input, _ := h.active(t)
	wrongKey := make([]byte, 32)
	_, _ = rand.Read(wrongKey)
	wrongCipher, err := push.NewCipher("one", map[string][]byte{"one": wrongKey}, h.lookup)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(h.lookup)
	if _, err := NewPushStore(h.ctx, h.database, wrongCipher, h.principal.Issuer, "fixture-project", "cn.edu.ustc.dsh.mobile", hex.EncodeToString(fingerprint[:]), h.control); !errors.Is(err, push.ErrInvalid) {
		t.Fatal("replaced live encryption key was silently accepted")
	}
	_, err = NewPushStore(h.ctx, h.database, h.cipher, h.principal.Issuer, "fixture-project", "cn.edu.ustc.dsh.mobile", strings.Repeat("f", 64), h.control)
	if !errors.Is(err, push.ErrInvalid) {
		t.Fatal("lookup key rotation defeated address uniqueness")
	}
	if _, err = h.database.DB.ExecContext(h.ctx, `update push_bindings set proof_key_jkt=$2 where id=$1`, input.BindingID, strings.Repeat("Q", 43)); err != nil {
		t.Fatal(err)
	}
	if err = h.push.Plan(h.ctx); err != nil {
		t.Fatal(err)
	}
	var state string
	var cipher []byte
	if h.database.DB.QueryRowContext(h.ctx, `select state,address_ciphertext from push_bindings where id=$1`, input.BindingID).Scan(&state, &cipher) != nil || state != "expired" || len(cipher) != 0 {
		t.Fatal("changed device binding retained live channel")
	}
}

func TestPushConcurrentExtraDevicesCannotBypassUserChallengeBudget(t *testing.T) {
	h := newPushFixture(t)
	actors := []push.Actor{h.actor}
	for range 2 {
		actor := h.actor
		actor.DeviceID = approvalTestUUID(t)
		actor.ProofKeyJKT = pushTestSecret(t)
		if _, err := h.database.DB.ExecContext(h.ctx, `insert into devices(id,user_id,name,approval_public_jwk,approval_key_thumbprint,proof_public_jwk,proof_key_thumbprint)
		 select $1,user_id,'budget device',approval_public_jwk,$2,proof_public_jwk,$3 from devices where id=$4`, actor.DeviceID, pushTestSecret(t), actor.ProofKeyJKT, h.actor.DeviceID); err != nil {
			t.Fatal(err)
		}
		actors = append(actors, actor)
	}
	var org string
	if h.database.DB.QueryRowContext(h.ctx, `select id::text from orgs limit 1`).Scan(&org) != nil {
		t.Fatal("fixture org missing")
	}
	var accepted, conflicts atomic.Int32
	var workers sync.WaitGroup
	for _, actor := range actors {
		for range 10 {
			input := push.Registration{BindingID: approvalTestUUID(t), OrganizationID: org, Provider: "fcm", Address: "c" + strings.Repeat("C", 21), RevokeSHA256: strings.Repeat("a", 64)}
			workers.Add(1)
			go func() {
				defer workers.Done()
				_, err := h.push.Register(h.ctx, actor, input)
				if err == nil {
					accepted.Add(1)
				} else if errors.Is(err, push.ErrConflict) {
					conflicts.Add(1)
				} else {
					t.Errorf("registration budget: %v", err)
				}
			}()
		}
	}
	workers.Wait()
	if accepted.Load() != 20 || conflicts.Load() != 10 {
		t.Fatal("extra devices bypassed the serialized user budget")
	}
}
