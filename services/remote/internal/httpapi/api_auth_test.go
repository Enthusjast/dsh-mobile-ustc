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
	"io"
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
		AllowedClients: []string{"mobile-client", "host-client"}, RequiredScopes: []string{"remote.access"},
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
	hostAccess := httpSignCompact(t, map[string]any{"typ": "at+jwt", "alg": "RS256", "kid": "issuer-key"}, map[string]any{
		"iss": issuer, "sub": "user-ustc-123", "aud": "urn:dsh-remote", "client_id": "host-client",
		"jti": "access-token-id-host-0002", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
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
	repo.account = store.AccountIdentity{UserID: "11111111-1111-4111-8111-111111111111", Memberships: []store.OrganizationMembership{
		{OrganizationID: "33333333-3333-4333-8333-333333333333", Role: "member"},
	}}
	me := sendDPoPRequest(t, handler, access, proofKey, proofJWK, http.MethodGet,
		"https://api.example.edu/v1/me?user_id=attacker&organization_id=untrusted", "proof-jti-account-lookup-0001", denied.Header().Get("DPoP-Nonce"))
	var meBody struct {
		OK   bool `json:"ok"`
		Data struct {
			Issuer      string                         `json:"issuer"`
			Subject     string                         `json:"subject"`
			UserID      string                         `json:"user_id"`
			Memberships []store.OrganizationMembership `json:"memberships"`
		} `json:"data"`
	}
	if err := json.Unmarshal(me.Body.Bytes(), &meBody); err != nil {
		t.Fatal(err)
	}
	if me.Code != http.StatusOK || !meBody.OK || meBody.Data.UserID != repo.account.UserID || len(meBody.Data.Memberships) != 1 ||
		meBody.Data.Memberships[0] != repo.account.Memberships[0] || meBody.Data.Issuer != issuer || meBody.Data.Subject != "user-ustc-123" ||
		repo.accountLookup != (store.UserIdentity{Issuer: issuer, Subject: "user-ustc-123"}) || repo.activeDeviceCall != 1 || me.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("identity was not resolved before enrollment from verified claims: status=%d body=%s", me.Code, me.Body.String())
	}
	accountNonce := me.Header().Get("DPoP-Nonce")
	for _, failed := range []struct {
		err    error
		status int
		jti    string
	}{
		{store.ErrIdentityNotProvisioned, http.StatusForbidden, "proof-jti-account-unknown-0002"},
		{store.ErrDatabaseUnavailable, http.StatusServiceUnavailable, "proof-jti-account-outage-0003"},
	} {
		repo.accountErr = failed.err
		response := sendDPoPRequest(t, handler, access, proofKey, proofJWK, http.MethodGet, "https://api.example.edu/v1/me", failed.jti, accountNonce)
		if response.Code != failed.status || strings.Contains(response.Body.String(), `"user_id"`) || strings.Contains(response.Body.String(), `"subject"`) {
			t.Fatalf("failed identity lookup disclosed an account: status=%d body=%s", response.Code, response.Body.String())
		}
		accountNonce = response.Header().Get("DPoP-Nonce")
	}
	repo.accountErr = nil
	repo.currentDevice = store.CurrentDevice{State: "active", Device: &store.DeviceIdentity{DeviceID: deviceID, KeyVersion: 1, ApprovalKeyJKT: "approval-fixture", ProofKeyJKT: proofJKT}}
	current := sendDPoPRequest(t, handler, access, proofKey, proofJWK, http.MethodGet,
		"https://api.example.edu/v1/devices/current?device_id=untrusted&proof_key_jkt=untrusted", "proof-jti-current-device-0004", accountNonce)
	if current.Code != http.StatusOK || repo.currentDeviceIdentity != repo.accountLookup || repo.currentDeviceJKT != proofJKT ||
		repo.activeDeviceCall != 1 || !strings.Contains(current.Body.String(), deviceID) || current.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("device reconciliation trusted a caller selector or required prior enrollment: status=%d body=%s", current.Code, current.Body.String())
	}
	repo.currentDeviceErr = store.ErrDatabaseUnavailable
	unknownDevice := sendDPoPRequest(t, handler, access, proofKey, proofJWK, http.MethodGet,
		"https://api.example.edu/v1/devices/current", "proof-jti-current-device-outage-0005", current.Header().Get("DPoP-Nonce"))
	if unknownDevice.Code != http.StatusServiceUnavailable || strings.Contains(unknownDevice.Body.String(), `"device_id"`) {
		t.Fatalf("outage disclosed a device result: status=%d body=%s", unknownDevice.Code, unknownDevice.Body.String())
	}
	repo.currentDeviceErr = nil
	accountNonce = unknownDevice.Header().Get("DPoP-Nonce")

	repo.activeDeviceErr = nil
	listed := sendDPoPRequest(t, handler, access, proofKey, proofJWK, http.MethodGet, requestURI, "proof-jti-active-0003", accountNonce)
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
	ticketRequest := map[string]any{
		"runtime_id": "55555555-5555-4555-8555-555555555555",
		"scope":      map[string]any{"actions": []string{"session.list"}, "workspaces": []string{}, "sessions": []string{}},
	}
	ticket := sendDPoPRequest(t, handler, access, proofKey, proofJWK, http.MethodPost,
		"https://api.example.edu/v1/realtime/tickets", "proof-jti-ticket-create-0005", status.Header().Get("DPoP-Nonce"), ticketRequest)
	if ticket.Code != http.StatusCreated || repo.ticketCalls != 1 || !strings.Contains(ticket.Body.String(), `"ticket"`) {
		t.Fatalf("active device could not request a scoped Relay ticket: status=%d calls=%d body=%s", ticket.Code, repo.ticketCalls, ticket.Body.String())
	}
	hostEnroll := sendDPoPRequest(t, handler, access, proofKey, proofJWK, http.MethodPost,
		"https://api.example.edu/v1/enrollments", "proof-jti-mobile-host-enroll-0006", ticket.Header().Get("DPoP-Nonce"), map[string]any{})
	if hostEnroll.Code != http.StatusForbidden || repo.enrollmentCalls != 0 {
		t.Fatalf("mobile OAuth client reached host enrollment: status=%d enrollment-calls=%d", hostEnroll.Code, repo.enrollmentCalls)
	}
	hostChallengeDenied := sendDPoPRequest(t, handler, access, proofKey, proofJWK, http.MethodPost,
		"https://api.example.edu/v1/host-credentials/challenges", "proof-jti-mobile-host-challenge-0007", hostEnroll.Header().Get("DPoP-Nonce"))
	if hostChallengeDenied.Code != http.StatusForbidden || repo.challengeCalls != 0 {
		t.Fatalf("mobile OAuth client reached host credential challenge: status=%d calls=%d", hostChallengeDenied.Code, repo.challengeCalls)
	}
	hostExchangeDenied := sendDPoPRequest(t, handler, access, proofKey, proofJWK, http.MethodPost,
		"https://api.example.edu/v1/host-credentials", "proof-jti-mobile-host-exchange-0008", hostChallengeDenied.Header().Get("DPoP-Nonce"), map[string]any{})
	if hostExchangeDenied.Code != http.StatusForbidden || repo.credentialCalls != 0 {
		t.Fatalf("mobile OAuth client reached host credential exchange: status=%d calls=%d", hostExchangeDenied.Code, repo.credentialCalls)
	}
	repo.enrollmentResult = store.EnrollmentCreated{
		EnrollmentID: "77777777-7777-4777-8777-777777777777", HostID: "11111111-1111-4111-8111-111111111111",
		InstallationID: "22222222-2222-4222-8222-222222222222", RuntimeID: "55555555-5555-4555-8555-555555555555",
		RequestID: "66666666-6666-4666-8666-666666666666", ProfileRef: "profile", State: "pending",
		ExpiresAt: now.Add(5 * time.Minute), Workspaces: []store.EnrollmentWorkspace{},
	}
	hostAPI := New(repo, identity, Config{HostClientIDs: []string{"host-client"}})
	wrongClientChallenge := sendDPoPRequest(t, hostAPI, access, proofKey, proofJWK, http.MethodPost,
		"https://api.example.edu/v1/host-credentials/challenges", "proof-jti-mobile-on-host-api-0009", hostExchangeDenied.Header().Get("DPoP-Nonce"))
	if wrongClientChallenge.Code != http.StatusForbidden || repo.challengeCalls != 0 {
		t.Fatalf("mobile OAuth client reached host-client API: status=%d calls=%d", wrongClientChallenge.Code, repo.challengeCalls)
	}
	createBody := map[string]any{
		"request_id": "66666666-6666-4666-8666-666666666666", "organization_id": "33333333-3333-4333-8333-333333333333",
		"alias": "host", "profile_ref": "profile", "dsh_version": "0.2.1-rc.2", "application_version": "1.0",
		"plugin_version": "1.0", "protocol_version": 1, "installation_public_jwk": proofJWK,
		"code": base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "workspace_refs": []string{"project"},
	}
	created := sendDPoPRequest(t, hostAPI, hostAccess, proofKey, proofJWK, http.MethodPost,
		"https://api.example.edu/v1/enrollments", "proof-jti-host-enroll-0010", wrongClientChallenge.Header().Get("DPoP-Nonce"), createBody)
	if created.Code != http.StatusCreated || repo.enrollmentCalls != 1 {
		t.Fatalf("allowlisted DPoP host client could not create enrollment: status=%d calls=%d body=%s", created.Code, repo.enrollmentCalls, created.Body.String())
	}
	confirmed := sendDPoPRequest(t, hostAPI, hostAccess, proofKey, proofJWK, http.MethodPost,
		"https://api.example.edu/v1/enrollments/77777777-7777-4777-8777-777777777777/host-confirm",
		"proof-jti-host-confirm-0011", created.Header().Get("DPoP-Nonce"), map[string]any{"code": createBody["code"]})
	if confirmed.Code != http.StatusOK || repo.hostConfirmCalls != 1 || repo.hostConfirmJKT != proofJKT {
		t.Fatalf("host confirmation did not bind to the DPoP installation key: status=%d calls=%d key=%s", confirmed.Code, repo.hostConfirmCalls, repo.hostConfirmJKT)
	}
	repo.challengeResult = store.HostCredentialChallenge{
		ChallengeID: "88888888-8888-4888-8888-888888888888", Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		InstallationID: "22222222-2222-4222-8222-222222222222", Audience: auth.HostCredentialProofAudience, ExpiresAt: now.Add(90 * time.Second),
	}
	hostCredentialChallenge := sendDPoPRequest(t, hostAPI, hostAccess, proofKey, proofJWK, http.MethodPost,
		"https://api.example.edu/v1/host-credentials/challenges", "proof-jti-host-challenge-0012", confirmed.Header().Get("DPoP-Nonce"))
	if hostCredentialChallenge.Code != http.StatusCreated || repo.challengeCalls != 1 || repo.challengeJKT != proofJKT ||
		!strings.Contains(hostCredentialChallenge.Body.String(), `"challenge_id"`) {
		t.Fatalf("allowlisted host could not request a key-bound challenge: status=%d calls=%d key=%s body=%s", hostCredentialChallenge.Code, repo.challengeCalls, repo.challengeJKT, hostCredentialChallenge.Body.String())
	}
	repo.credentialResult = store.HostConnectionCredential{
		Credential: strings.Repeat("B", 43), TokenType: "DSH-Host", InstallationID: repo.challengeResult.InstallationID,
		KeyThumbprint: proofJKT, ExpiresAt: now.Add(5 * time.Minute),
	}
	credential := sendDPoPRequest(t, hostAPI, hostAccess, proofKey, proofJWK, http.MethodPost,
		"https://api.example.edu/v1/host-credentials", "proof-jti-host-credential-0013", hostCredentialChallenge.Header().Get("DPoP-Nonce"),
		map[string]any{"challenge_id": repo.challengeResult.ChallengeID, "proof": "installation-signature"})
	if credential.Code != http.StatusCreated || repo.credentialCalls != 1 || repo.credentialJKT != proofJKT ||
		repo.credentialID != repo.challengeResult.ChallengeID || repo.credentialProof != "installation-signature" ||
		!strings.Contains(credential.Body.String(), `"credential"`) {
		t.Fatalf("host credential exchange did not bind challenge and DPoP key: status=%d calls=%d key=%s challenge=%s body=%s", credential.Code, repo.credentialCalls, repo.credentialJKT, repo.credentialID, credential.Body.String())
	}
}

func sendDPoPRequest(t *testing.T, handler http.Handler, access string, proofKey *ecdsa.PrivateKey, proofJWK map[string]any, method, uri, jti, nonce string, body ...any) *httptest.ResponseRecorder {
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
	var requestBody io.Reader
	if len(body) > 0 {
		encoded, err := json.Marshal(body[0])
		if err != nil {
			t.Fatal(err)
		}
		requestBody = strings.NewReader(string(encoded))
	}
	request := httptest.NewRequest(method, uri, requestBody)
	request.URL.Scheme = "https"
	request.URL.Host = "api.example.edu"
	request.Host = "api.example.edu"
	request.Header.Set("Authorization", "DPoP "+access)
	request.Header.Set("DPoP", proof)
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
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
