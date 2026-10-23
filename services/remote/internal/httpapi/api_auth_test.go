package httpapi

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
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/store"
)

func TestProtectedRoutesRequireActiveDeviceAndBindCommandStatusToIt(t *testing.T) {
	accessKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	proofKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	issuer := "https://id.example.edu"
	proofJWK := httpProofJWK(proofKey)
	proofJKT, err := auth.JWKThumbprint(proofJWK)
	if err != nil {
		t.Fatal(err)
	}
	keyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Cache-Control", "max-age=300")
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"keys": []any{httpTestRSAJWK(accessKey)}})
	}))
	t.Cleanup(keyServer.Close)
	identity, err := auth.New(auth.Config{
		Issuer: issuer, Audience: "urn:dsh-remote", JWKSURL: keyServer.URL,
		AllowedClients: []string{"mobile-client"}, RequiredScopes: []string{"remote.access"},
		PublicOrigin: "https://api.example.edu", MaxTokenLifetime: 15 * time.Minute, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	access := httpSignCompact(t, map[string]any{"typ": "at+jwt", "alg": "RS256", "kid": "issuer-key"}, map[string]any{
		"iss": issuer, "sub": "user-ustc-123", "aud": "urn:dsh-remote", "client_id": "mobile-client",
		"jti": "access-token-id-0001", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"scope": "remote.access", "cnf": map[string]any{"jkt": proofJKT},
	}, accessKey)
	deviceID := "44444444-4444-4444-8444-444444444444"
	repo := &fakeRepository{activeDeviceID: deviceID, activeDeviceErr: store.ErrDeviceNotFound}
	handler := New(repo, identity)
	requestURI := "https://api.example.edu/v1/hosts"
	challenge := sendDPoPRequest(t, handler, access, proofKey, proofJWK, http.MethodGet, requestURI, "proof-jti-inactive-0001", "")
	if challenge.Code != http.StatusUnauthorized || challenge.Header().Get("DPoP-Nonce") == "" {
		t.Fatalf("initial DPoP nonce challenge status=%d headers=%v", challenge.Code, challenge.Header())
	}
	denied := sendDPoPRequest(t, handler, access, proofKey, proofJWK, http.MethodGet, requestURI, "proof-jti-inactive-0002", challenge.Header().Get("DPoP-Nonce"))
	if denied.Code != http.StatusForbidden || repo.activeDeviceCall != 1 || repo.listCalls != 0 {
		t.Fatalf("revoked or unregistered device was not denied before listing: status=%d active-checks=%d list-calls=%d", denied.Code, repo.activeDeviceCall, repo.listCalls)
	}

	repo.activeDeviceErr = nil
	listed := sendDPoPRequest(t, handler, access, proofKey, proofJWK, http.MethodGet, requestURI, "proof-jti-active-0003", denied.Header().Get("DPoP-Nonce"))
	if listed.Code != http.StatusOK || repo.activeDeviceCall != 2 || repo.listCalls != 1 {
		t.Fatalf("active device could not list hosts: status=%d active-checks=%d list-calls=%d body=%s", listed.Code, repo.activeDeviceCall, repo.listCalls, listed.Body.String())
	}

	requestID := "66666666-6666-4666-8666-666666666666"
	otherDeviceID := "55555555-5555-4555-8555-555555555555"
	commandURI := "https://api.example.edu/v1/commands/" + requestID
	status := sendDPoPRequest(t, handler, access, proofKey, proofJWK, http.MethodGet,
		commandURI+"?device_id="+otherDeviceID, "proof-jti-other-device-0004", listed.Header().Get("DPoP-Nonce"))
	if status.Code != http.StatusForbidden || repo.commandCalls != 0 {
		t.Fatalf("device queried another device's command: status=%d command-calls=%d", status.Code, repo.commandCalls)
	}
}

func sendDPoPRequest(t *testing.T, handler http.Handler, access string, proofKey *ecdsa.PrivateKey, proofJWK map[string]any, method, uri, jti, nonce string) *httptest.ResponseRecorder {
	t.Helper()
	digest := sha256.Sum256([]byte(access))
	proofURI := uri
	if before, _, hasQuery := strings.Cut(uri, "?"); hasQuery {
		proofURI = before
	}
	proof := httpSignCompact(t, map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": proofJWK}, map[string]any{
		"jti": jti, "htm": method, "htu": proofURI, "iat": time.Now().Unix(),
		"ath": base64.RawURLEncoding.EncodeToString(digest[:]), "nonce": nonce,
	}, proofKey)
	request := httptest.NewRequest(method, uri, nil)
	request.URL.Scheme = "https"
	request.URL.Host = "api.example.edu"
	request.Host = "api.example.edu"
	request.Header.Set("Authorization", "DPoP "+access)
	request.Header.Set("DPoP", proof)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func httpProofJWK(key *ecdsa.PrivateKey) map[string]any {
	return map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(key.PublicKey.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.FillBytes(make([]byte, 32))),
	}
}

func httpTestRSAJWK(key *rsa.PrivateKey) map[string]any {
	return map[string]any{
		"kty": "RSA", "kid": "issuer-key", "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}
}

func httpSignCompact(t *testing.T, header, claims map[string]any, signer crypto.Signer) string {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
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
