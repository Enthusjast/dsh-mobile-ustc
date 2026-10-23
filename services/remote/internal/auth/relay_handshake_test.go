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

func TestVerifyRelayHandshakeProofBindsSocketAndRegisteredKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := testProofJWK(key)
	publicJWK, err := json.Marshal(jwk)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := JWKThumbprint(jwk)
	if err != nil {
		t.Fatal(err)
	}
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		t.Fatal(err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	expected := RelayHandshakeExpectation{
		KeyThumbprint: thumbprint, Issuer: "device-uuid", ChallengeID: "challenge-uuid",
		ConnectionID: "connection-uuid", Nonce: nonce, RuntimeID: "runtime-uuid",
	}
	now := time.Now().UTC().Truncate(time.Second)
	claims := map[string]any{
		"iss": expected.Issuer, "aud": RelayHandshakeAudience, "challenge_id": expected.ChallengeID,
		"connection_id": expected.ConnectionID, "nonce": expected.Nonce, "runtime_id": expected.RuntimeID,
		"iat": now.Unix(), "jti": "relay-handshake-jti-00000001",
	}
	sign := func(mutate func(map[string]any), signer *ecdsa.PrivateKey) string {
		copyClaims := make(map[string]any, len(claims))
		for name, value := range claims {
			copyClaims[name] = value
		}
		if mutate != nil {
			mutate(copyClaims)
		}
		return signCompact(t, map[string]any{"typ": relayHandshakeProofType, "alg": "ES256"}, copyClaims, signer)
	}
	proof := sign(nil, key)
	if err := VerifyRelayHandshakeProof(proof, publicJWK, expected); err != nil {
		t.Fatalf("valid relay proof rejected: %v", err)
	}
	if err := VerifyRelayHandshakeProof(sign(nil, wrongKey), publicJWK, expected); err == nil {
		t.Fatal("proof signed by an unregistered key was accepted")
	}
	wrongThumbprint := expected
	wrongThumbprint.KeyThumbprint = "different-thumbprint"
	if err := VerifyRelayHandshakeProof(proof, publicJWK, wrongThumbprint); err == nil {
		t.Fatal("proof accepted against a different stored thumbprint")
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "wrong connection", mutate: func(claims map[string]any) { claims["connection_id"] = "another-connection" }},
		{name: "wrong challenge", mutate: func(claims map[string]any) { claims["challenge_id"] = "another-challenge" }},
		{name: "wrong nonce", mutate: func(claims map[string]any) { claims["nonce"] = "another-nonce" }},
		{name: "stale proof", mutate: func(claims map[string]any) { claims["iat"] = now.Add(-time.Minute).Unix() }},
		{name: "extra claim", mutate: func(claims map[string]any) { claims["scope"] = "all" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := VerifyRelayHandshakeProof(sign(test.mutate, key), publicJWK, expected); err == nil {
				t.Fatal("invalid relay proof was accepted")
			}
		})
	}
	changedChallenge := expected
	changedChallenge.ChallengeID = "challenge-from-another-connection"
	if err := VerifyRelayHandshakeProof(proof, publicJWK, changedChallenge); err == nil {
		t.Fatal("proof replayed against another connection challenge")
	}
	changedBytes := sha256.Sum256([]byte("different hello"))
	changedHello := expected
	changedHello.RuntimeEpoch = "runtime-epoch"
	changedHello.HelloSHA256 = base64.RawURLEncoding.EncodeToString(changedBytes[:])
	if err := VerifyRelayHandshakeProof(proof, publicJWK, changedHello); err == nil {
		t.Fatal("device proof without host metadata was accepted for a host handshake")
	}
}

func TestRelayHelloDigestIsStableAndLengthDelimited(t *testing.T) {
	first := RelayHelloDigest("host", "ab", "c")
	second := RelayHelloDigest("host", "a", "bc")
	if first == second {
		t.Fatal("different hello field boundaries produced the same digest")
	}
	if first != RelayHelloDigest("host", "ab", "c") {
		t.Fatal("identical normalized hello fields produced different digests")
	}
}
