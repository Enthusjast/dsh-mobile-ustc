package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type testKeys struct {
	issuer   string
	access   *rsa.PrivateKey
	proof    *ecdsa.PrivateKey
	proofJKT string
	server   *httptest.Server
	now      time.Time
	verifier *Authenticator
}

func newTestKeys(t *testing.T) *testKeys {
	t.Helper()
	access, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proofJKT, err := JWKThumbprint(testProofJWK(proof))
	if err != nil {
		t.Fatal(err)
	}
	issuer := "https://id.example.edu"
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Cache-Control", "max-age=300")
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"keys": []any{testRSAJWK(access, "issuer-key-1")}})
	}))
	t.Cleanup(server.Close)
	now := time.Now().UTC().Truncate(time.Second)
	verifier, err := New(Config{
		Issuer: issuer, Audience: "urn:dsh-remote", JWKSURL: server.URL,
		AllowedClients: []string{"android-public-client"}, RequiredScopes: []string{"remote.access"},
		PublicOrigin: "https://api.example.edu", MaxTokenLifetime: 15 * time.Minute, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return &testKeys{issuer: issuer, access: access, proof: proof, proofJKT: proofJKT, server: server, now: now, verifier: verifier}
}

func (keys *testKeys) token(t *testing.T, mutate func(map[string]any)) string {
	t.Helper()
	claims := map[string]any{
		"iss": keys.issuer, "sub": "user-ustc-123", "aud": []string{"urn:dsh-remote", "urn:another-resource"},
		"client_id": "android-public-client", "jti": "access-jti-001", "iat": keys.now.Unix(),
		"exp": keys.now.Add(5 * time.Minute).Unix(), "scope": "openid remote.access",
		"cnf": map[string]any{"jkt": keys.proofJKT},
	}
	if mutate != nil {
		mutate(claims)
	}
	return signCompact(t, map[string]any{"typ": "at+jwt", "alg": "RS256", "kid": "issuer-key-1"}, claims, keys.access)
}

func (keys *testKeys) proofToken(t *testing.T, access, method, uri, jti, nonce string, mutate func(map[string]any)) string {
	t.Helper()
	digest := sha256.Sum256([]byte(access))
	claims := map[string]any{
		"jti": jti, "htm": method, "htu": uri, "iat": keys.now.Unix(),
		"ath":   base64.RawURLEncoding.EncodeToString(digest[:]),
		"nonce": nonce,
	}
	if mutate != nil {
		mutate(claims)
	}
	return signCompact(t, map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": testProofJWK(keys.proof)}, claims, keys.proof)
}

func testProofJWK(key *ecdsa.PrivateKey) map[string]any {
	return map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(key.PublicKey.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.FillBytes(make([]byte, 32))),
	}
}

func testRSAJWK(key *rsa.PrivateKey, kid string) map[string]any {
	return map[string]any{
		"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}
}

func signCompact(t *testing.T, header, claims map[string]any, signer crypto.Signer) string {
	t.Helper()
	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerBytes)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsBytes)
	input := encodedHeader + "." + encodedClaims
	digest := sha256.Sum256([]byte(input))
	var signature []byte
	switch key := signer.(type) {
	case *rsa.PrivateKey:
		signature, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	case *ecdsa.PrivateKey:
		var r, s *big.Int
		r, s, err = ecdsa.Sign(rand.Reader, key, digest[:])
		if err == nil {
			signature = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
		}
	default:
		t.Fatalf("unsupported test signer %T", signer)
	}
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}
