package approval

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"os"
	"testing"
	"time"
)

type authorityFixture struct {
	Issuer     string          `json:"issuer"`
	KeyID      string          `json:"key_id"`
	PublicJWK  json.RawMessage `json:"public_jwk"`
	JKT        string          `json:"key_jkt"`
	Active     bool            `json:"active"`
	ValidFrom  string          `json:"valid_from"`
	ValidUntil string          `json:"valid_until"`
}

func (fixture authorityFixture) trusted() TrustedAuthority {
	from, _ := utc(fixture.ValidFrom)
	until, _ := utc(fixture.ValidUntil)
	return TrustedAuthority{Issuer: fixture.Issuer, KeyID: fixture.KeyID, PublicJWK: fixture.PublicJWK, JKT: fixture.JKT, Active: fixture.Active, ValidFrom: from, ValidUntil: until}
}

type authorizationFixtures struct {
	Now          string             `json:"now"`
	Context      json.RawMessage    `json:"context"`
	DecisionJWS  string             `json:"decision_jws"`
	ConnectionID string             `json:"connection_id"`
	Lease        AuthorizationLease `json:"lease"`
	Authorities  []authorityFixture `json:"authorities"`
	Vectors      []struct {
		Name             string          `json:"name"`
		Compact          string          `json:"compact"`
		Authority        int             `json:"authority"`
		Invalid          bool            `json:"invalid"`
		Now              string          `json:"now"`
		DecisionJWS      string          `json:"decision_jws"`
		TrustedOverrides json.RawMessage `json:"trusted_overrides"`
	} `json:"vectors"`
}

func loadAuthorizationFixtures(t *testing.T) authorizationFixtures {
	t.Helper()
	raw, err := os.ReadFile("../../../../contracts/security/approval-leases.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture authorizationFixtures
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("invalid public authority fixtures")
	}
	return fixture
}

func TestAuthorizationGoAndTypeScriptSharedVectors(t *testing.T) {
	fixture := loadAuthorizationFixtures(t)
	for _, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			authority := fixture.Authorities[vector.Authority]
			if len(vector.TrustedOverrides) != 0 && json.Unmarshal(vector.TrustedOverrides, &authority) != nil {
				t.Fatal("invalid authority override")
			}
			now, _ := utc(fixture.Now)
			if vector.Now != "" {
				now, _ = utc(vector.Now)
			}
			decision := fixture.DecisionJWS
			if vector.DecisionJWS != "" {
				decision = vector.DecisionJWS
			}
			verified, err := VerifyAuthorization(vector.Compact, authority.trusted(), fixture.Context, decision, fixture.ConnectionID, now)
			if vector.Invalid {
				if err == nil {
					t.Fatal("invalid authorization was accepted")
				}
				return
			}
			if err != nil || verified.Lease.BindingSHA256 != fixture.Lease.BindingSHA256 || verified.Lease.Role != "owner" || !verified.Key.Active {
				t.Fatalf("valid cross-language authorization failed: %v", err)
			}
		})
	}
}

func TestAuthorizationSignerRejectsInvalidContextIntervalsAndKeys(t *testing.T) {
	fixture := loadAuthorizationFixtures(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*AuthorizationLease){
		func(lease *AuthorizationLease) { lease.Domain = "other" },
		func(lease *AuthorizationLease) { lease.Role = "operator" },
		func(lease *AuthorizationLease) { lease.ExpiresAt = "2026-10-24T12:00:05.001Z" },
		func(lease *AuthorizationLease) { lease.ApprovalPublicJWK = []byte(`{"kty":"EC","d":"private"}`) },
	} {
		lease := fixture.Lease
		mutate(&lease)
		if _, err := SignAuthorization(lease, "dsh-approval-authority/test", key); err == nil {
			t.Fatal("invalid lease signed")
		}
	}
	for _, badKey := range []*ecdsa.PrivateKey{nil, {}, {PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}}} {
		if _, err := SignAuthorization(fixture.Lease, "dsh-approval-authority/test", badKey); err == nil {
			t.Fatal("invalid signing key accepted")
		}
	}
	if _, err := SignAuthorization(fixture.Lease, "https://untrusted.example/key", key); err == nil {
		t.Fatal("key URL used as authority key identity")
	}
	if _, err := SignAuthorization(fixture.Lease, "dsh-approval-authority/test", key); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorizationNeverTransfersToAnotherContextConnectionOrTrustKey(t *testing.T) {
	fixture := loadAuthorizationFixtures(t)
	now, _ := utc(fixture.Now)
	valid := fixture.Vectors[0].Compact
	for _, field := range []string{"host_id", "installation_id", "runtime_id", "runtime_epoch", "session_id", "approval_id", "execution_id", "arguments"} {
		var context map[string]any
		if json.Unmarshal(fixture.Context, &context) != nil {
			t.Fatal("invalid context")
		}
		context[field] = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
		raw, _ := json.Marshal(context)
		if _, err := VerifyAuthorization(valid, fixture.Authorities[0].trusted(), raw, fixture.DecisionJWS, fixture.ConnectionID, now); err == nil {
			t.Fatalf("changed %s accepted", field)
		}
	}
	if _, err := VerifyAuthorization(valid, fixture.Authorities[0].trusted(), fixture.Context, fixture.DecisionJWS, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", now); err == nil {
		t.Fatal("old lease transferred to new connection")
	}
	changed := fixture.Authorities[0].trusted()
	changed.PublicJWK = append(changed.PublicJWK[:len(changed.PublicJWK)-1:len(changed.PublicJWK)-1], []byte(`,"d":"private"}`)...)
	if _, err := VerifyAuthorization(valid, changed, fixture.Context, fixture.DecisionJWS, fixture.ConnectionID, now); err == nil {
		t.Fatal("untrusted authority key accepted")
	}
	if _, err := VerifyAuthorization(valid, fixture.Authorities[0].trusted(), fixture.Context, fixture.DecisionJWS, fixture.ConnectionID, now.Add(-time.Millisecond)); err == nil {
		t.Fatal("future lease accepted with clock grace")
	}
}

func TestAuthorizationSignerCopiesKeysAndEnforcesItsOwnIssuerAndValidity(t *testing.T) {
	fixture := loadAuthorizationFixtures(t)
	now, _ := utc(fixture.Now)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []*ecdsa.PrivateKey{nil, {}, {PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}}} {
		if _, err := NewAuthorizationSigner(fixture.Lease.Issuer, "dsh-approval-authority/test", bad, now.Add(-time.Hour), now.Add(time.Hour)); err == nil {
			t.Fatal("invalid configured signing key accepted")
		}
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mismatched := *key
	mismatched.PublicKey = other.PublicKey
	if _, err := NewAuthorizationSigner(fixture.Lease.Issuer, "dsh-approval-authority/test", &mismatched, now.Add(-time.Hour), now.Add(time.Hour)); err == nil {
		t.Fatal("mismatched public/private key accepted")
	}
	signer, err := NewAuthorizationSigner(fixture.Lease.Issuer, "dsh-approval-authority/test", key, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	key.D.Set(big.NewInt(0))
	key.X.SetInt64(0)
	authority := signer.Authority()
	authority.Active = false
	authority.PublicJWK[0] = '!'
	compact, err := signer.Sign(fixture.Lease, now)
	if err != nil {
		t.Fatalf("caller mutation changed owned key: %v", err)
	}
	if _, err := VerifyAuthorization(compact, signer.Authority(), fixture.Context, fixture.DecisionJWS, fixture.ConnectionID, now); err != nil {
		t.Fatal(err)
	}
	changed := fixture.Lease
	changed.Issuer = "https://other.example.edu"
	if _, err := signer.Sign(changed, now); err == nil {
		t.Fatal("key signed for another issuer")
	}
	for _, clock := range []time.Time{now.Add(-time.Millisecond), now.Add(3 * time.Second)} {
		if _, err := signer.Sign(fixture.Lease, clock); err == nil {
			t.Fatal("future or expired lease signed")
		}
	}
}
