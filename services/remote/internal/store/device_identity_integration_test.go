package store

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/auth"
)

func TestDeviceRegistrationReconcilesConcurrentRetriesWithoutResurrectingAuthority(t *testing.T) {
	ctx, postgres := newPostgresIntegrationDatabase(t)
	const issuer = "https://id.example.edu"
	if _, err := postgres.DB.ExecContext(ctx, `insert into users (issuer, subject) values ($1, 'owner'), ($1, 'other')`, issuer); err != nil {
		t.Fatal(err)
	}
	publicKey := func() ([]byte, string) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		jwk, err := integrationP256JWK(key)
		if err != nil {
			t.Fatal(err)
		}
		jkt, err := auth.PublicP256JWKThumbprintJSON(jwk)
		if err != nil {
			t.Fatal(err)
		}
		return jwk, jkt
	}
	approvalJWK, approvalJKT := publicKey()
	proofJWK, proofJKT := publicKey()
	input := DeviceRegistration{Issuer: issuer, Subject: "owner", Name: strings.Repeat("校", 160), ApprovalPublicJWK: approvalJWK, ApprovalKeyThumbprint: approvalJKT, ProofPublicJWK: proofJWK, ProofKeyThumbprint: proofJKT}
	identity := UserIdentity{Issuer: issuer, Subject: "owner"}
	absent, err := postgres.CurrentDevice(ctx, identity, proofJKT)
	if err != nil || absent.State != "unregistered" || absent.Device != nil {
		t.Fatalf("fresh key unexpectedly enrolled: %#v, %v", absent, err)
	}
	var wait sync.WaitGroup
	type result struct {
		id  string
		err error
	}
	results := make(chan result, 8)
	for range 8 {
		wait.Go(func() { id, err := postgres.RegisterDevice(ctx, input); results <- result{id, err} })
	}
	wait.Wait()
	close(results)
	var deviceID string
	for result := range results {
		if result.err != nil || result.id == "" || deviceID != "" && deviceID != result.id {
			t.Fatalf("concurrent registration did not settle one device: id=%q error=%v", result.id, result.err)
		}
		deviceID = result.id
	}
	active, err := postgres.CurrentDevice(ctx, identity, proofJKT)
	if err != nil || active.State != "active" || active.Device == nil || active.Device.DeviceID != deviceID || active.Device.ApprovalKeyJKT != approvalJKT || active.Device.ProofKeyJKT != proofJKT || active.Device.KeyVersion != 1 {
		t.Fatalf("accepted key status missing: %#v, %v", active, err)
	}
	for _, changed := range []func(*DeviceRegistration){
		func(value *DeviceRegistration) { value.Name = "different phone" },
		func(value *DeviceRegistration) { value.Subject = "other" },
		func(value *DeviceRegistration) { value.ApprovalPublicJWK, value.ApprovalKeyThumbprint = publicKey() },
		func(value *DeviceRegistration) { value.ProofPublicJWK, value.ProofKeyThumbprint = publicKey() },
	} {
		variant := input
		changed(&variant)
		if _, err := postgres.RegisterDevice(ctx, variant); !errors.Is(err, ErrDeviceRegistrationConflict) {
			t.Fatalf("changed enrollment was accepted: %v", err)
		}
	}
	other, err := postgres.CurrentDevice(ctx, UserIdentity{Issuer: issuer, Subject: "other"}, proofJKT)
	if err != nil || other.State != "unregistered" || other.Device != nil {
		t.Fatalf("key from another account disclosed: %#v, %v", other, err)
	}
	for _, unknown := range []UserIdentity{{Issuer: "https://another.example.edu", Subject: "owner"}, {Issuer: issuer, Subject: "unknown"}} {
		if _, err := postgres.CurrentDevice(ctx, unknown, proofJKT); !errors.Is(err, ErrIdentityNotProvisioned) {
			t.Fatalf("unknown identity queried enrollment: %v", err)
		}
	}
	if _, err := postgres.DB.ExecContext(ctx, `update devices set key_version = 2 where id = $1`, deviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.RegisterDevice(ctx, input); !errors.Is(err, ErrDeviceRegistrationConflict) {
		t.Fatalf("registration replay rolled key version back: %v", err)
	}
	if err := postgres.RevokeDevice(ctx, issuer, "owner", deviceID); err != nil {
		t.Fatal(err)
	}
	revoked, err := postgres.CurrentDevice(ctx, identity, proofJKT)
	if err != nil || revoked.State != "revoked" || revoked.Device == nil || revoked.Device.DeviceID != deviceID || revoked.Device.KeyVersion != 2 {
		t.Fatalf("revoked key cannot reconcile: %#v, %v", revoked, err)
	}
	if _, err := postgres.RegisterDevice(ctx, input); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("registration retry resurrected revoked device: %v", err)
	}
	var devices, registrations int
	if err := postgres.DB.QueryRowContext(ctx, `select (select count(*) from devices), (select count(*) from audit_log where action = 'device.register')`).Scan(&devices, &registrations); err != nil || devices != 1 || registrations != 1 {
		t.Fatalf("retries duplicated device or audit: devices=%d registrations=%d err=%v", devices, registrations, err)
	}
	if _, err := postgres.DB.ExecContext(ctx, `update users set status = 'suspended' where issuer = $1 and subject = 'owner'`, issuer); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.CurrentDevice(ctx, identity, proofJKT); !errors.Is(err, ErrIdentityNotProvisioned) {
		t.Fatalf("suspended identity queried enrollment: %v", err)
	}
	if err := postgres.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.CurrentDevice(ctx, identity, proofJKT); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatalf("outage produced enrollment status: %v", err)
	}
}
