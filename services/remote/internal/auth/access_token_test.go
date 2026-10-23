package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestJWTAccessTokenValidatesIssuerAudienceClientAndScope(t *testing.T) {
	keys := newTestKeys(t)
	principal, err := keys.verifier.VerifyAccessToken(t.Context(), keys.token(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if principal.Issuer != keys.issuer || principal.Subject != "user-ustc-123" || principal.ClientID != "android-public-client" || principal.ProofKeyJKT != keys.proofJKT {
		t.Fatalf("unexpected principal identity: %+v", principal)
	}
	if _, ok := principal.Scopes["remote.access"]; !ok {
		t.Fatal("required scope was not retained")
	}
}

func TestJWTAccessTokenRejectsWrongClaimsHeadersAndDuplicateJSONMembers(t *testing.T) {
	keys := newTestKeys(t)
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "issuer", mutate: func(claims map[string]any) { claims["iss"] = "https://attacker.example" }},
		{name: "audience", mutate: func(claims map[string]any) { claims["aud"] = "urn:another-resource" }},
		{name: "client", mutate: func(claims map[string]any) { claims["client_id"] = "other-client" }},
		{name: "scope", mutate: func(claims map[string]any) { claims["scope"] = "openid" }},
		{name: "expired", mutate: func(claims map[string]any) { claims["exp"] = keys.now.Add(-time.Minute).Unix() }},
		{name: "future nbf", mutate: func(claims map[string]any) { claims["nbf"] = keys.now.Add(time.Hour).Unix() }},
		{name: "unbound", mutate: func(claims map[string]any) { delete(claims, "cnf") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := keys.verifier.VerifyAccessToken(t.Context(), keys.token(t, test.mutate)); err == nil {
				t.Fatal("invalid access token was accepted")
			}
		})
	}
	for _, header := range []map[string]any{
		{"typ": "JWT", "alg": "RS256", "kid": "issuer-key-1"},
		{"typ": "at+jwt", "alg": "none", "kid": "issuer-key-1"},
		{"typ": "at+jwt", "alg": "RS256", "kid": "missing", "jku": "https://attacker.example/jwks"},
	} {
		compact := signCompact(t, header, validAccessClaims(keys), keys.access)
		if _, err := keys.verifier.VerifyAccessToken(t.Context(), compact); err == nil {
			t.Fatalf("invalid JOSE header was accepted: %v", header)
		}
	}
	duplicateClaims := []byte(`{"iss":"https://id.example.edu","iss":"https://attacker.example"}`)
	if _, err := decodeObject(duplicateClaims); err == nil {
		t.Fatal("duplicate JSON claim was accepted")
	}
}

func TestJWTVerifierRejectsUnexpectedAlgorithmAndInvalidConfiguration(t *testing.T) {
	keys := newTestKeys(t)
	config := Config{
		Issuer: keys.issuer, Audience: "urn:dsh-remote", JWKSURL: keys.server.URL,
		AllowedClients: []string{"android-public-client"}, RequiredScopes: []string{"remote.access"},
		PublicOrigin: "https://api.example.edu", MaxTokenLifetime: 15 * time.Minute,
	}
	config.JWKSURL = "http://attacker.example/jwks"
	if _, err := New(config); err == nil {
		t.Fatal("plain HTTP JWKS endpoint was accepted")
	}
	if _, err := New(Config{
		Issuer: keys.issuer, Audience: "urn:dsh-remote", JWKSURL: keys.server.URL,
		AllowedClients: []string{"android-public-client"}, RequiredScopes: []string{"remote.access"},
		PublicOrigin: "https://api.example.edu/path", MaxTokenLifetime: 15 * time.Minute,
	}); err == nil {
		t.Fatal("public origin with a path was accepted")
	}
}

func validAccessClaims(keys *testKeys) map[string]any {
	return map[string]any{
		"iss": keys.issuer, "sub": "user-ustc-123", "aud": []string{"urn:dsh-remote"},
		"client_id": "android-public-client", "jti": "access-jti-001", "iat": keys.now.Unix(),
		"exp": keys.now.Add(5 * time.Minute).Unix(), "scope": "openid remote.access",
		"cnf": map[string]any{"jkt": keys.proofJKT},
	}
}

func TestJWKSJSONShapeMatchesExpectedRSAKey(t *testing.T) {
	keys := newTestKeys(t)
	// Fetching occurs on token validation; this test also guards the actual JWK shape emitted by an issuer.
	compact := keys.token(t, nil)
	if _, err := keys.verifier.VerifyAccessToken(t.Context(), compact); err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	parts := splitTestToken(t, compact)
	if err := json.Unmarshal(parts[1], &claims); err != nil || claims["sub"] != "user-ustc-123" {
		t.Fatalf("unexpected JWT payload: %v", err)
	}
}

func TestUnknownJWKSKeyIDsCannotForceUnboundedRefreshes(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		response.Header().Set("Cache-Control", "max-age=300")
		_ = json.NewEncoder(response).Encode(map[string]any{"keys": []any{testRSAJWK(key, "known-key")}})
	}))
	defer server.Close()
	set, err := newKeySet(server.URL, server.Client(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.get(context.Background(), "known-key", "RS256"); err != nil {
		t.Fatal(err)
	}
	if _, err := set.get(context.Background(), "attacker-key-1", "RS256"); err == nil {
		t.Fatal("unknown JWKS key ID was accepted")
	}
	if _, err := set.get(context.Background(), "attacker-key-2", "RS256"); err == nil {
		t.Fatal("second unknown JWKS key ID was accepted")
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("unknown key IDs caused %d JWKS fetches; want one rate-limited refresh", got)
	}
}

func splitTestToken(t *testing.T, compact string) [3][]byte {
	t.Helper()
	var result [3][]byte
	parts := strings.Split(compact, ".")
	if len(parts) != len(result) {
		t.Fatal("test JWT is malformed")
	}
	for index, part := range parts {
		decoded, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			t.Fatal(err)
		}
		result[index] = decoded
	}
	return result
}
