package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestVerifyHostCredentialProofBindsInstallationAndChallenge(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	installationJWK := testProofJWK(key)
	publicJWK, err := json.Marshal(installationJWK)
	if err != nil {
		t.Fatal(err)
	}
	installationThumbprint, err := JWKThumbprint(installationJWK)
	if err != nil {
		t.Fatal(err)
	}
	challengeBytes := make([]byte, 32)
	if _, err := rand.Read(challengeBytes); err != nil {
		t.Fatal(err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(challengeBytes)
	challengeHash := sha256.Sum256([]byte(nonce))
	issuedAt := time.Now().UTC().Truncate(time.Second)
	claims := map[string]any{
		"iss": "22222222-2222-4222-8222-222222222222", "aud": HostCredentialProofAudience,
		"challenge_id": "33333333-3333-4333-8333-333333333333", "nonce": nonce,
		"iat": issuedAt.Unix(), "jti": "host-proof-jti-0123456789",
	}
	sign := func(mutate func(map[string]any), signer *ecdsa.PrivateKey) string {
		copyClaims := make(map[string]any, len(claims))
		for name, value := range claims {
			copyClaims[name] = value
		}
		if mutate != nil {
			mutate(copyClaims)
		}
		return signCompact(t, map[string]any{"typ": hostCredentialProofType, "alg": "ES256"}, copyClaims, signer)
	}
	valid := sign(nil, key)
	if err := VerifyHostCredentialProof(valid, publicJWK,
		"22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", installationThumbprint, challengeHash[:]); err != nil {
		t.Fatalf("valid installation proof rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{{
		name: "wrong installation", mutate: func(claims map[string]any) { claims["iss"] = "44444444-4444-4444-8444-444444444444" },
	}, {
		name: "wrong audience", mutate: func(claims map[string]any) { claims["aud"] = "urn:another-service" },
	}, {
		name: "wrong challenge", mutate: func(claims map[string]any) { claims["challenge_id"] = "44444444-4444-4444-8444-444444444444" },
	}, {
		name: "wrong nonce", mutate: func(claims map[string]any) { claims["nonce"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) },
	}, {
		name: "stale proof", mutate: func(claims map[string]any) { claims["iat"] = issuedAt.Add(-3 * time.Minute).Unix() },
	}, {
		name: "unknown claim", mutate: func(claims map[string]any) { claims["sub"] = "unexpected" },
	}} {
		t.Run(test.name, func(t *testing.T) {
			if err := VerifyHostCredentialProof(sign(test.mutate, key), publicJWK,
				"22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", installationThumbprint, challengeHash[:]); err == nil {
				t.Fatal("invalid host proof accepted")
			}
		})
	}
	if err := VerifyHostCredentialProof(sign(nil, otherKey), publicJWK,
		"22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", installationThumbprint, challengeHash[:]); err == nil {
		t.Fatal("proof signed by a different key was accepted")
	}
	changedHash := sha256.Sum256([]byte("another challenge"))
	if err := VerifyHostCredentialProof(valid, publicJWK,
		"22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", installationThumbprint, changedHash[:]); err == nil {
		t.Fatal("proof accepted against a different stored challenge digest")
	}
	if err := VerifyHostCredentialProof(valid, publicJWK,
		"22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", "different-thumbprint", challengeHash[:]); err == nil {
		t.Fatal("proof accepted when stored key thumbprint differs from its JWK")
	}
}
