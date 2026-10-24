package httpapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/approval"
	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/relay"
	"dsh-mobile-ustc/services/remote/internal/store"
)

func TestApprovalHTTPSAdmissionRequiresFreshDPoPActiveDeviceAndAdmittedSocket(t *testing.T) {
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	proofKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proofJWK := httpProofJWK(proofKey)
	proofJKT, err := auth.JWKThumbprint(proofJWK)
	if err != nil {
		t.Fatal(err)
	}
	keys := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(response).Encode(map[string]any{"keys": []any{httpTestRSAJWK(issuerKey)}})
	}))
	defer keys.Close()
	now := time.Now().UTC().Truncate(time.Second)
	verifier, err := auth.New(auth.Config{Issuer: "https://id.example.edu", Audience: "urn:dsh-remote", JWKSURL: keys.URL, AllowedClients: []string{"mobile-client"}, RequiredScopes: []string{"remote.access"}, PublicOrigin: "https://api.example.edu", MaxTokenLifetime: 15 * time.Minute, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	access := httpSignCompact(t, map[string]any{"typ": "at+jwt", "alg": "RS256", "kid": "issuer-key"}, map[string]any{
		"iss": "https://id.example.edu", "sub": "owner", "aud": "urn:dsh-remote", "client_id": "mobile-client", "jti": "approval-access-token", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"scope": "remote.access", "cnf": map[string]any{"jkt": proofJKT}, "auth_time": now.Add(-time.Second).Unix(), "acr": "school:2", "amr": []string{"otp"},
	}, issuerKey)
	assurance, err := auth.NewAssuranceVerifier([]auth.AssuranceMapping{{Issuer: "https://id.example.edu", ClientID: "mobile-client", Profile: "school/step-up", ACR: "school:2", RequiredAMR: []string{"otp"}}})
	if err != nil {
		t.Fatal(err)
	}
	control, err := store.NewApprovalControl(&store.Postgres{DB: &sql.DB{}}, store.ApprovalPolicy{Version: 7, AssuranceProfile: "school/step-up", MaxAuthAgeSeconds: 60}, assurance)
	if err != nil {
		t.Fatal(err)
	}
	serviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := approval.NewAuthorizationSigner("https://remote.example.edu", "dsh-approval-authority/http-test", serviceKey, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	leases, err := store.NewApprovalLeaseProvider(control, signer)
	if err != nil {
		t.Fatal(err)
	}
	repo := &fakeRepository{activeDeviceID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
	handler := New(repo, verifier, Config{Approvals: &relay.ApprovalConfig{Control: control, Leases: leases}})
	uri := "https://api.example.edu/v1/approvals/66666666-6666-4666-8666-666666666666/decisions"
	body := map[string]any{"connection_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "decision_jws": "e30.e30.AA"}
	unauthenticated := httptest.NewRecorder()
	handler.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodPost, uri, strings.NewReader(`{}`)))
	if unauthenticated.Code != http.StatusUnauthorized || repo.activeDeviceCall != 0 {
		t.Fatal("approval endpoint skipped identity verification")
	}
	challenge := sendDPoPRequest(t, handler, access, proofKey, proofJWK, http.MethodPost, uri, "approval-proof-1", "", body)
	if challenge.Code != http.StatusUnauthorized || challenge.Header().Get("DPoP-Nonce") == "" {
		t.Fatal("approval endpoint skipped DPoP nonce admission")
	}
	invalid := sendDPoPRequest(t, handler, access, proofKey, proofJWK, http.MethodPost, uri, "approval-proof-2", challenge.Header().Get("DPoP-Nonce"), map[string]any{"connection_id": body["connection_id"], "decision_jws": body["decision_jws"], "role": "owner"})
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("phone supplied its own authority: %d %s", invalid.Code, invalid.Body.String())
	}
	missingSocket := sendDPoPRequest(t, handler, access, proofKey, proofJWK, http.MethodPost, uri, "approval-proof-3", invalid.Header().Get("DPoP-Nonce"), body)
	if missingSocket.Code != http.StatusForbidden || !strings.Contains(missingSocket.Body.String(), "access.denied") {
		t.Fatalf("HTTP request invented an admitted socket: %d %s", missingSocket.Code, missingSocket.Body.String())
	}
	calls := repo.activeDeviceCall
	replay := sendDPoPRequest(t, handler, access, proofKey, proofJWK, http.MethodPost, uri, "approval-proof-3", missingSocket.Header().Get("DPoP-Nonce"), body)
	if replay.Code != http.StatusUnauthorized || repo.activeDeviceCall != calls {
		t.Fatal("replayed DPoP reached approval operation")
	}
	repo.activeDeviceErr = store.ErrDeviceNotFound
	revoked := sendDPoPRequest(t, handler, access, proofKey, proofJWK, http.MethodPost, uri, "approval-proof-4", replay.Header().Get("DPoP-Nonce"), body)
	if revoked.Code != http.StatusForbidden {
		t.Fatal("revoked phone reached approval operation")
	}
	disabled := New(repo, verifier)
	response := httptest.NewRecorder()
	disabled.ServeHTTP(response, httptest.NewRequest(http.MethodPost, uri, strings.NewReader(`{}`)))
	if response.Code != http.StatusNotFound {
		t.Fatal("unconfigured approval endpoint was exposed")
	}
}

func TestApprovalAdmissionBodyRejectsCaseAliasesNullAndCallerKeys(t *testing.T) {
	for _, raw := range []string{
		`{"Connection_ID":"id","decision_jws":"proof"}`,
		`{"connection_id":null,"decision_jws":"proof"}`,
		`{"connection_id":"id","decision_jws":"proof","public_jwk":{}}`,
		`{"connection_id":"id","decision_jws":12}`,
	} {
		var input approvalDecisionRequest
		if json.Unmarshal([]byte(raw), &input) == nil {
			t.Fatalf("invalid admission body accepted: %s", raw)
		}
	}
}
