package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRoutingInspectionNeverConsumesOrAuthenticatesARequest(t *testing.T) {
	keys := newTestKeys(t)
	access := keys.token(t, nil)
	path := "/v1/approvals/aaaaaaaa-1111-4111-8111-111111111111/decisions"
	makeRequest := func(proof string) *http.Request {
		request := httptest.NewRequest("POST", path, nil)
		request.Header.Set("Authorization", "DPoP "+access)
		request.Header.Set("DPoP", proof)
		return request
	}
	nonce, err := keys.verifier.proofs.Challenge(context.Background(), keys.proofJKT)
	if err != nil {
		t.Fatal(err)
	}
	proof := keys.proofToken(t, access, "POST", "https://api.example.edu"+path, "routing-proof-one-use-0001", nonce, nil)
	for range 2 {
		request := makeRequest(proof)
		principal, err := keys.verifier.InspectRequestForRouting(request)
		if err != nil || principal.Subject != "user-ustc-123" || principal.ProofJTI != "" {
			t.Fatal("routing inspection failed or claimed completed authentication", err)
		}
		if _, ok := PrincipalFromContext(request.Context()); ok {
			t.Fatal("routing inspection authenticated handler context")
		}
	}
	handled := 0
	handler := keys.verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handled++; w.WriteHeader(204) }))
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, makeRequest(proof))
	if first.Code != 204 || handled != 1 {
		t.Fatal("routing consumed original proof before owner", first.Code)
	}
	replay := httptest.NewRecorder()
	handler.ServeHTTP(replay, makeRequest(proof))
	if replay.Code != 401 || handled != 1 {
		t.Fatal("inspection bypassed one-use gate", replay.Code)
	}
	missingNonce := keys.proofToken(t, access, "POST", "https://api.example.edu"+path, "routing-proof-no-nonce-0002", "", nil)
	if _, err := keys.verifier.InspectRequestForRouting(makeRequest(missingNonce)); err != nil {
		t.Fatal("transport inspection unexpectedly consumed nonce state", err)
	}
	rejected := httptest.NewRecorder()
	handler.ServeHTTP(rejected, makeRequest(missingNonce))
	if rejected.Code != 401 || handled != 1 {
		t.Fatal("unconsumed inspection authorized nonce-free operation")
	}
	wrongPath := keys.proofToken(t, access, "POST", "https://api.example.edu/v1/hosts", "routing-proof-wrong-path-0003", nonce, nil)
	if _, err := keys.verifier.InspectRequestForRouting(makeRequest(wrongPath)); err == nil {
		t.Fatal("invalid URI selected private routing")
	}
}
