package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestDPoPChallengeAndNonceAreBoundToAccessTokenAndRequest(t *testing.T) {
	keys := newTestKeys(t)
	access := keys.token(t, nil)
	var handled atomic.Int64
	handler := keys.verifier.Middleware(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		principal, ok := PrincipalFromContext(request.Context())
		if !ok || principal.Subject != "user-ustc-123" {
			t.Error("verified user principal was not attached to the request")
		}
		handled.Add(1)
		response.WriteHeader(http.StatusNoContent)
	}))

	uri := "https://api.example.edu/v1/hosts"
	firstProof := keys.proofToken(t, access, http.MethodGet, uri, "proof-jti-initial-0001", "", nil)
	challenge := sendRequest(t, handler, "/v1/hosts?cursor=redacted", http.MethodGet, access, firstProof)
	if challenge.Code != http.StatusUnauthorized || challenge.Header().Get("WWW-Authenticate") != `DPoP error="use_dpop_nonce"` || challenge.Header().Get("DPoP-Nonce") == "" {
		t.Fatalf("expected a nonce challenge, got status=%d headers=%v body=%s", challenge.Code, challenge.Header(), challenge.Body.String())
	}
	if handled.Load() != 0 {
		t.Fatal("handler ran before a DPoP nonce was presented")
	}

	nonce := challenge.Header().Get("DPoP-Nonce")
	acceptedProof := keys.proofToken(t, access, http.MethodGet, uri, "proof-jti-first-use-0002", nonce, nil)
	accepted := sendRequest(t, handler, "/v1/hosts?cursor=redacted", http.MethodGet, access, acceptedProof)
	if accepted.Code != http.StatusNoContent || accepted.Header().Get("DPoP-Nonce") == "" {
		t.Fatalf("valid DPoP request was rejected: status=%d body=%s", accepted.Code, accepted.Body.String())
	}
	if handled.Load() != 1 {
		t.Fatalf("handler called %d times, want 1", handled.Load())
	}

	replay := sendRequest(t, handler, "/v1/hosts?cursor=redacted", http.MethodGet, access, acceptedProof)
	if replay.Code != http.StatusUnauthorized || replay.Header().Get("DPoP-Nonce") == "" {
		t.Fatalf("replayed proof was not challenged: status=%d body=%s", replay.Code, replay.Body.String())
	}
	if handled.Load() != 1 {
		t.Fatal("replayed proof reached the handler")
	}

	retryProof := keys.proofToken(t, access, http.MethodGet, uri, "proof-jti-retry-0003", replay.Header().Get("DPoP-Nonce"), nil)
	retry := sendRequest(t, handler, "/v1/hosts?cursor=redacted", http.MethodGet, access, retryProof)
	if retry.Code != http.StatusNoContent || handled.Load() != 2 {
		t.Fatalf("fresh nonce retry was rejected: status=%d handled=%d body=%s", retry.Code, handled.Load(), retry.Body.String())
	}
}

func TestDPoPChecksMethodURIAndAccessTokenHashBeforeAcceptingProof(t *testing.T) {
	keys := newTestKeys(t)
	access := keys.token(t, nil)
	server := httptest.NewServer(keys.verifier.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("invalid proof reached the handler")
	})))
	defer server.Close()

	tests := []struct {
		name     string
		method   string
		target   string
		proofURI string
		mutate   func(map[string]any)
	}{
		{name: "wrong method", method: http.MethodPost, target: "/v1/hosts", proofURI: "/v1/hosts"},
		{name: "wrong path", method: http.MethodGet, target: "/v1/devices", proofURI: "/v1/hosts"},
		{name: "wrong access token hash", method: http.MethodGet, target: "/v1/hosts", proofURI: "/v1/hosts", mutate: func(claims map[string]any) { claims["ath"] = "not-the-access-token-hash" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proofURL := "https://api.example.edu" + test.proofURI
			proof := keys.proofToken(t, access, http.MethodGet, proofURL, "proof-jti-"+strings.ReplaceAll(test.name, " ", "-"), "", test.mutate)
			response := sendRequest(t, keys.verifier.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("invalid proof reached the handler")
			})), test.target, test.method, access, proof)
			if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "auth.proof_invalid") {
				t.Fatalf("invalid proof accepted: status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestDPoPRejectsPrivateJWKAndConcurrentReplay(t *testing.T) {
	keys := newTestKeys(t)
	access := keys.token(t, nil)
	handler := keys.verifier.Middleware(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))

	privateJWK := testProofJWK(keys.proof)
	privateJWK["d"] = base64.RawURLEncoding.EncodeToString(keys.proof.D.FillBytes(make([]byte, 32)))
	privateProof := signCompact(t, map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": privateJWK}, map[string]any{
		"jti": "proof-jti-private-0001", "htm": http.MethodGet, "htu": "https://api.example.edu/v1/hosts",
		"iat": keys.now.Unix(), "ath": tokenHash(access),
	}, keys.proof)
	privateResponse := sendRequest(t, handler, "/v1/hosts", http.MethodGet, access, privateProof)
	if privateResponse.Code != http.StatusUnauthorized {
		t.Fatalf("proof with private JWK member was accepted: status=%d", privateResponse.Code)
	}

	nonce, err := keys.verifier.proofs.Challenge(context.Background(), keys.proofJKT)
	if err != nil {
		t.Fatal(err)
	}
	proof := keys.proofToken(t, access, http.MethodGet, "https://api.example.edu/v1/hosts", "proof-jti-race-0002", nonce, nil)
	var wait sync.WaitGroup
	statuses := make(chan int, 8)
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			statuses <- sendRequest(t, handler, "/v1/hosts", http.MethodGet, access, proof).Code
		}()
	}
	wait.Wait()
	close(statuses)
	accepted := 0
	for status := range statuses {
		if status == http.StatusNoContent {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("concurrent DPoP replay accepted %d times, want one", accepted)
	}
}

func TestDPoPBoundTokenRejectsBearerAuthorizationScheme(t *testing.T) {
	keys := newTestKeys(t)
	access := keys.token(t, nil)
	proof := keys.proofToken(t, access, http.MethodGet, "https://api.example.edu/v1/hosts", "proof-jti-wrong-scheme-0001", "", nil)
	request := httptest.NewRequest(http.MethodGet, "/v1/hosts", nil)
	request.URL.Scheme = "https"
	request.URL.Host = "api.example.edu"
	request.Host = "api.example.edu"
	request.Header.Set("Authorization", "Bearer "+access)
	request.Header.Set("DPoP", proof)
	response := httptest.NewRecorder()
	keys.verifier.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("DPoP-bound token was accepted with the Bearer scheme")
	})).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Bearer scheme accepted a DPoP-bound token: status=%d", response.Code)
	}
}

func sendRequest(t *testing.T, handler http.Handler, target, method, access, proof string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, nil)
	request.Header.Set("Authorization", "DPoP "+access)
	request.Header.Set("DPoP", proof)
	response := httptest.NewRecorder()
	request.URL.Scheme = "https"
	request.URL.Host = "api.example.edu"
	request.Host = "api.example.edu"
	handler.ServeHTTP(response, request)
	return response
}

func tokenHash(access string) string {
	digest := sha256.Sum256([]byte(access))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
