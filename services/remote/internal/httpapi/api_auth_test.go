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
	"fmt"
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
	missingReview := sendDPoPRequest(t, hostAPI, hostAccess, proofKey, proofJWK, http.MethodPost,
		"https://api.example.edu/v1/enrollments/77777777-7777-4777-8777-777777777777/host-confirm",
		"proof-jti-host-confirm-missing", created.Header().Get("DPoP-Nonce"), map[string]any{"code": createBody["code"]})
	if missingReview.Code != http.StatusBadRequest || repo.hostConfirmCalls != 0 {
		t.Fatal("host confirmation accepted an unspecified phone user")
	}
	confirmed := sendDPoPRequest(t, hostAPI, hostAccess, proofKey, proofJWK, http.MethodPost,
		"https://api.example.edu/v1/enrollments/77777777-7777-4777-8777-777777777777/host-confirm",
		"proof-jti-host-confirm-0011", missingReview.Header().Get("DPoP-Nonce"), map[string]any{"code": createBody["code"], "confirmed_user_id": "66666666-6666-4666-8666-666666666666"})
	if confirmed.Code != http.StatusOK || repo.hostConfirmCalls != 1 || repo.hostConfirmJKT != proofJKT || repo.hostConfirmUser != "66666666-6666-4666-8666-666666666666" {
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
	t.Run("enrollment preview is device protected and host status is key bound", func(t *testing.T) {
		repo.enrollmentInfo = store.EnrollmentInfo{EnrollmentID: repo.enrollmentResult.EnrollmentID, InstallationKeyJKT: proofJKT, ProfileRef: "private-profile"}
		nonce := credential.Header().Get("DPoP-Nonce")
		sequence := 0
		send := func(token, method, path string, body ...any) *httptest.ResponseRecorder {
			sequence++
			response := sendDPoPRequest(t, hostAPI, token, proofKey, proofJWK, method, "https://api.example.edu"+path, fmt.Sprintf("proof-jti-binding-%04d", sequence), nonce, body...)
			nonce = response.Header().Get("DPoP-Nonce")
			return response
		}
		path := "/v1/enrollments/" + repo.enrollmentResult.EnrollmentID
		repo.activeDeviceErr = store.ErrDeviceNotFound
		denied := send(access, http.MethodPost, path+"/preview", map[string]any{"code": createBody["code"]})
		if denied.Code != http.StatusForbidden || repo.enrollmentPreviewCalls != 0 {
			t.Fatal("unregistered phone reached enrollment preview")
		}
		before := repo.activeDeviceCall
		hostStatus := send(hostAccess, http.MethodGet, path)
		if hostStatus.Code != http.StatusOK || repo.activeDeviceCall != before || hostStatus.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("installation owner cannot read its own key-bound status")
		}
		repo.enrollmentInfo.InstallationKeyJKT = strings.Repeat("A", 43)
		wrongHost := send(hostAccess, http.MethodGet, path)
		if wrongHost.Code != http.StatusForbidden || strings.Contains(wrongHost.Body.String(), "private-profile") {
			t.Fatal("a different installation key read host metadata")
		}
		repo.enrollmentInfo.InstallationKeyJKT = proofJKT
		for index, route := range []struct {
			method, path string
			body         any
		}{
			{http.MethodPost, "/v1/devices", map[string]any{}},
			{http.MethodGet, "/v1/devices/current", nil},
			{http.MethodPost, path + "/preview", map[string]any{"code": createBody["code"]}},
			{http.MethodPost, path + "/confirm", map[string]any{"code": createBody["code"]}},
		} {
			beforeDeviceCalls := repo.activeDeviceCall
			var denied *httptest.ResponseRecorder
			if route.body == nil {
				denied = send(hostAccess, route.method, route.path)
			} else {
				denied = send(hostAccess, route.method, route.path, route.body)
			}
			if denied.Code != http.StatusForbidden || repo.activeDeviceCall != beforeDeviceCalls {
				t.Fatalf("host client crossed phone route %d", index)
			}
		}
		phoneStatus := send(access, http.MethodGet, path)
		if phoneStatus.Code != http.StatusForbidden || repo.enrollmentReadCalls != 2 {
			t.Fatal("phone status bypassed active-device check")
		}
		repo.activeDeviceErr = nil
		extra := send(access, http.MethodPost, path+"/preview", map[string]any{"code": createBody["code"], "user_id": "attacker"})
		if extra.Code != http.StatusBadRequest || repo.enrollmentPreviewCalls != 0 {
			t.Fatal("preview accepted caller identity fields")
		}
		preview := send(access, http.MethodPost, path+"/preview?user_id=attacker", map[string]any{"code": createBody["code"]})
		if preview.Code != http.StatusOK || repo.enrollmentPreviewCalls != 1 || repo.enrollmentPreviewCode != createBody["code"] || repo.enrollmentPreviewActor != (store.UserIdentity{Issuer: issuer, Subject: "user-ustc-123"}) || preview.Header().Get("Cache-Control") != "no-store" || strings.Contains(preview.Body.String(), createBody["code"].(string)) {
			t.Fatal("preview did not bind verified identity and private request body")
		}
		repo.enrollmentInfo.HostReviewOwner = true
		repo.enrollmentInfo.HostReviewTargetActive = true
		repo.enrollmentInfo.HostReviewUser = &store.EnrollmentReviewUser{UserID: "66666666-6666-4666-8666-666666666666", Issuer: issuer, Subject: "private-confirmed-subject", Eligible: true}
		plain := send(hostAccess, http.MethodGet, path)
		if plain.Code != http.StatusOK || strings.Contains(plain.Body.String(), "private-confirmed-subject") {
			t.Fatal("ordinary status disclosed host-only identity")
		}
		phoneReview := send(access, http.MethodGet, path+"/host-review")
		if phoneReview.Code != http.StatusForbidden || strings.Contains(phoneReview.Body.String(), "private-confirmed-subject") {
			t.Fatal("phone client accessed host-only review")
		}
		repo.enrollmentInfo.HostReviewOwner = false
		otherOwner := send(hostAccess, http.MethodGet, path+"/host-review")
		if otherOwner.Code != http.StatusForbidden || strings.Contains(otherOwner.Body.String(), "private-confirmed-subject") {
			t.Fatal("non-owner accessed host review")
		}
		repo.enrollmentInfo.HostReviewOwner = true
		repo.enrollmentInfo.HostReviewTargetActive = false
		revokedTarget := send(hostAccess, http.MethodGet, path+"/host-review")
		if revokedTarget.Code != http.StatusForbidden || strings.Contains(revokedTarget.Body.String(), "private-confirmed-subject") {
			t.Fatal("revoked installation accessed host review")
		}
		repo.enrollmentInfo.HostReviewTargetActive = true
		repo.enrollmentInfo.InstallationKeyJKT = strings.Repeat("A", 43)
		otherKey := send(hostAccess, http.MethodGet, path+"/host-review")
		if otherKey.Code != http.StatusForbidden || strings.Contains(otherKey.Body.String(), "private-confirmed-subject") {
			t.Fatal("different installation key accessed host review")
		}
		repo.enrollmentInfo.InstallationKeyJKT = proofJKT
		selector := send(hostAccess, http.MethodGet, path+"/host-review?user_id=attacker")
		if selector.Code != http.StatusBadRequest {
			t.Fatal("host review accepted a caller identity selector")
		}
		review := send(hostAccess, http.MethodGet, path+"/host-review")
		if review.Code != http.StatusOK || review.Header().Get("Cache-Control") != "no-store" || !strings.Contains(review.Body.String(), "private-confirmed-subject") || !strings.Contains(review.Body.String(), `"eligible":true`) {
			t.Fatal("owner could not review the verified confirming identity")
		}
	})
	t.Run("cache read access binds the current phone and exact resource", func(t *testing.T) {
		const runtime = "55555555-5555-4555-8555-555555555555"
		const session = "66666666-6666-4666-8666-666666666666"
		uri := "https://api.example.edu/v1/runtimes/" + runtime + "/sessions/" + session + "/read-access"
		nonce := ""
		sequence := 0
		send := func(token, path string) *httptest.ResponseRecorder {
			sequence++
			result := sendDPoPRequest(t, hostAPI, token, proofKey, proofJWK, http.MethodGet, path, fmt.Sprintf("cache-proof-%04d", sequence), nonce)
			nonce = result.Header().Get("DPoP-Nonce")
			if result.Code == http.StatusUnauthorized {
				sequence++
				result = sendDPoPRequest(t, hostAPI, token, proofKey, proofJWK, http.MethodGet, path, fmt.Sprintf("cache-proof-%04d", sequence), nonce)
				nonce = result.Header().Get("DPoP-Nonce")
			}
			return result
		}
		repo.activeDeviceErr = nil
		repo.cacheAccess = store.SessionReadAccess{RuntimeID: runtime, SessionID: session, GrantVersion: 7, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
		allowed := send(access, uri)
		if allowed.Code != http.StatusOK || repo.cacheAccessCalls != 1 || repo.cacheIdentity != (store.UserIdentity{Issuer: issuer, Subject: "user-ustc-123"}) || repo.cacheDevice != deviceID || repo.cacheJKT != proofJKT || repo.cacheRuntime != runtime || repo.cacheSession != session || !repo.cacheCredentialUntil.Equal(now.Add(5*time.Minute)) || allowed.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("cache admission lost verified identity/resource bounds: status=%d", allowed.Code)
		}
		if denied := send(access, uri+"?device_id=untrusted"); denied.Code != http.StatusBadRequest || repo.cacheAccessCalls != 1 {
			t.Fatal("caller selector reached cache admission")
		}
		repo.activeDeviceErr = store.ErrDeviceNotFound
		if denied := send(access, uri); denied.Code != http.StatusForbidden || repo.cacheAccessCalls != 1 {
			t.Fatal("unregistered device reached cached body authority")
		}
		repo.activeDeviceErr = nil
		if denied := send(hostAccess, uri); denied.Code != http.StatusForbidden || repo.cacheAccessCalls != 1 {
			t.Fatal("host OAuth client reached phone cache authority")
		}
		repo.cacheAccessErr = store.ErrDatabaseUnavailable
		if failed := send(access, uri); failed.Code != http.StatusServiceUnavailable || strings.Contains(failed.Body.String(), "grant_version") {
			t.Fatal("failed cache admission disclosed an authority result")
		}
		repo.cacheAccessErr = nil
	})
	t.Run("known targets and answer status use the verified actor instead of caller selectors", func(t *testing.T) {
		const runtime = "55555555-5555-4555-8555-555555555555"
		const session = "66666666-6666-4666-8666-666666666666"
		const id = "77777777-7777-4777-8777-777777777777"
		repo.target = store.SessionTarget{Runtime: store.Runtime{ID: runtime, HostID: runtime, ProtocolVersion: 1, Access: &store.RuntimeAccess{Role: "operator", GrantVersion: 7, Scope: store.GrantScope{Actions: []string{"session.read", "question.answer"}, Sessions: []string{session}, Workspaces: []string{}}}}, Session: store.Session{ID: session, State: "available", UpdatedAt: now}}
		repo.answerStatus = store.CommandStatus{RequestID: id, SessionID: session, State: "settled", PayloadSHA256: strings.Repeat("a", 64), UpdatedAt: now}
		nonce := ""
		sequence := 0
		send := func(token, path string) *httptest.ResponseRecorder {
			sequence++
			result := sendDPoPRequest(t, hostAPI, token, proofKey, proofJWK, http.MethodGet, path, fmt.Sprintf("known-proof-%04d", sequence), nonce)
			nonce = result.Header().Get("DPoP-Nonce")
			if result.Code == http.StatusUnauthorized {
				sequence++
				result = sendDPoPRequest(t, hostAPI, token, proofKey, proofJWK, http.MethodGet, path, fmt.Sprintf("known-proof-%04d", sequence), nonce)
				nonce = result.Header().Get("DPoP-Nonce")
			}
			return result
		}
		base := "https://api.example.edu/v1/runtimes/" + runtime + "/sessions/" + session
		for _, path := range []string{base, base + "/question-answers/" + id} {
			response := send(access, path)
			if response.Code != 200 || response.Header().Get("Cache-Control") != "no-store" || repo.cacheIdentity != (store.UserIdentity{Issuer: issuer, Subject: "user-ustc-123"}) || repo.cacheDevice != deviceID || repo.cacheJKT != proofJKT || repo.cacheRuntime != runtime || repo.cacheSession != session || !repo.cacheCredentialUntil.Equal(now.Add(5*time.Minute)) {
				t.Fatal("known-resource authority lost its authenticated context", response.Code)
			}
			before := repo.targetCalls + repo.answerStatusCalls
			if response = send(access, path+"?device_id=untrusted"); response.Code != 400 || before != repo.targetCalls+repo.answerStatusCalls {
				t.Fatal("caller selector reached resource lookup", response.Code)
			}
			if response = send(hostAccess, path); response.Code != 403 || before != repo.targetCalls+repo.answerStatusCalls {
				t.Fatal("host OAuth client reached phone resource lookup", response.Code)
			}
		}
		if repo.targetCalls != 1 || repo.answerStatusCalls != 1 || repo.answerRequest != id {
			t.Fatal("known-resource routes did not select their own operations")
		}
	})
	t.Run("own device directory derives identity and rejects caller selectors", func(t *testing.T) {
		api := New(repo, identity, Config{HostClientIDs: []string{"host-client"}})
		repo.activeDeviceErr = nil
		repo.deviceDirectory = store.DeviceDirectory{Items: []store.DeviceSummary{{ID: deviceID, Name: "Current phone", KeyVersion: 1, State: "active", Current: true, CreatedAt: now}}}
		nonce := ""
		sequence := 0
		send := func(token, path string) *httptest.ResponseRecorder {
			sequence++
			uri := "https://api.example.edu/v1/devices" + path
			response := sendDPoPRequest(t, api, token, proofKey, proofJWK, http.MethodGet, uri, fmt.Sprintf("directory-proof-%04d", sequence), nonce)
			nonce = response.Header().Get("DPoP-Nonce")
			if response.Code == 401 {
				sequence++
				response = sendDPoPRequest(t, api, token, proofKey, proofJWK, http.MethodGet, uri, fmt.Sprintf("directory-proof-%04d", sequence), nonce)
				nonce = response.Header().Get("DPoP-Nonce")
			}
			return response
		}
		response := send(access, "?limit=2&cursor=opaque")
		if response.Code != 200 || response.Header().Get("Cache-Control") != "no-store" || repo.deviceDirectoryIdentity != (store.UserIdentity{Issuer: issuer, Subject: "user-ustc-123"}) || repo.deviceDirectoryDevice != deviceID || repo.deviceDirectoryJKT != proofJKT || repo.deviceDirectoryLimit != 2 || repo.deviceDirectoryCursor != "opaque" {
			t.Fatal("directory lost its authenticated caller", response.Code)
		}
		before := repo.deviceDirectoryCalls
		for _, query := range []string{"?user_id=attacker", "?device_id=attacker", "?limit=0", "?limit=101", "?limit=01", "?limit=2&limit=3", "?cursor=", "?x=%zz"} {
			if response := send(access, query); response.Code != 400 || repo.deviceDirectoryCalls != before {
				t.Fatal("invalid directory selectors reached repository", response.Code)
			}
		}
		if response := send(hostAccess, ""); response.Code != 403 || repo.deviceDirectoryCalls != before {
			t.Fatal("host client enumerated phone devices", response.Code)
		}
		repo.activeDeviceErr = store.ErrDeviceNotFound
		if response := send(access, ""); response.Code != 403 || repo.deviceDirectoryCalls != before {
			t.Fatal("unregistered or revoked key enumerated devices", response.Code)
		}
		repo.activeDeviceErr = nil
		for _, failure := range []struct {
			err    error
			status int
		}{{store.ErrAccessDenied, 403}, {store.ErrDeviceDirectoryInvalid, 400}, {store.ErrDatabaseUnavailable, 503}} {
			repo.deviceDirectoryErr = failure.err
			if response := send(access, ""); response.Code != failure.status || strings.Contains(response.Body.String(), "Current phone") {
				t.Fatal("directory failure disclosed records", response.Code)
			}
		}
		repo.deviceDirectoryErr = nil
	})
	t.Run("grant writes pass the verified actor proof into the transaction", func(t *testing.T) {
		api := New(repo, identity, Config{HostClientIDs: []string{"host-client"}})
		repo.activeDeviceErr = nil
		const runtime = "55555555-5555-4555-8555-555555555555"
		const target = "66666666-6666-4666-8666-666666666666"
		input := map[string]any{"role": "viewer", "scope": map[string]any{"actions": []string{"host.list"}, "workspaces": []string{}, "sessions": []string{}}}
		nonce := ""
		sequence := 0
		send := func(token, method, query string, body ...any) *httptest.ResponseRecorder {
			sequence++
			uri := "https://api.example.edu/v1/runtimes/" + runtime + "/grants/" + target + query
			response := sendDPoPRequest(t, api, token, proofKey, proofJWK, method, uri, fmt.Sprintf("grant-write-proof-%04d", sequence), nonce, body...)
			nonce = response.Header().Get("DPoP-Nonce")
			if response.Code == 401 {
				sequence++
				response = sendDPoPRequest(t, api, token, proofKey, proofJWK, method, uri, fmt.Sprintf("grant-write-proof-%04d", sequence), nonce, body...)
				nonce = response.Header().Get("DPoP-Nonce")
			}
			return response
		}
		for _, method := range []string{http.MethodPut, http.MethodDelete} {
			var body []any
			if method == http.MethodPut {
				body = []any{input}
			}
			response := send(access, method, "", body...)
			if response.Code != 200 || repo.grantWriteIdentity != (store.UserIdentity{Issuer: issuer, Subject: "user-ustc-123"}) || repo.grantWriteDevice != deviceID || repo.grantWriteJKT != proofJKT || repo.grantWriteRuntime != runtime || repo.grantWriteTarget != target {
				t.Fatal("grant write lost current verified actor", response.Code)
			}
			before := repo.grantWriteCalls
			for _, query := range []string{"?user_id=attacker", "?device_id=attacker"} {
				if response := send(access, method, query, body...); response.Code != 400 || repo.grantWriteCalls != before {
					t.Fatal("grant selectors reached transaction", response.Code)
				}
			}
			if response := send(hostAccess, method, "", body...); response.Code != 403 || repo.grantWriteCalls != before {
				t.Fatal("host client managed grants", response.Code)
			}
			repo.activeDeviceErr = store.ErrDeviceNotFound
			if response := send(access, method, "", body...); response.Code != 403 || repo.grantWriteCalls != before {
				t.Fatal("inactive device reached grant mutation", response.Code)
			}
			repo.activeDeviceErr = nil
			for _, failure := range []struct {
				err    error
				status int
			}{{store.ErrAccessDenied, 403}, {store.ErrGrantInvalid, 400}, {store.ErrDatabaseUnavailable, 503}} {
				repo.grantWriteErr = failure.err
				if response := send(access, method, "", body...); response.Code != failure.status || strings.Contains(response.Body.String(), "grant_version") {
					t.Fatal("failed transaction reported a grant result", response.Code)
				}
			}
			repo.grantWriteErr = nil
		}
		before := repo.grantWriteCalls
		if response := send(access, http.MethodDelete, "", input); response.Code != 400 || repo.grantWriteCalls != before {
			t.Fatal("DELETE accepted a grant body", response.Code)
		}
	})
	t.Run("runtime grant directory binds the current manager phone and target", func(t *testing.T) {
		api := New(repo, identity, Config{HostClientIDs: []string{"host-client"}})
		repo.activeDeviceErr = nil
		repo.grantDirectory = store.RuntimeGrantDirectory{RuntimeID: "55555555-5555-4555-8555-555555555555", Items: []store.RuntimeGrantSummary{{UserID: "22222222-2222-4222-8222-222222222222", Role: "owner", Version: 1, State: "active"}}}
		nonce := ""
		sequence := 0
		send := func(token, path string, body ...any) *httptest.ResponseRecorder {
			sequence++
			uri := "https://api.example.edu/v1/runtimes/55555555-5555-4555-8555-555555555555/grants" + path
			response := sendDPoPRequest(t, api, token, proofKey, proofJWK, http.MethodGet, uri, fmt.Sprintf("grant-directory-proof-%04d", sequence), nonce, body...)
			nonce = response.Header().Get("DPoP-Nonce")
			if response.Code == 401 {
				sequence++
				response = sendDPoPRequest(t, api, token, proofKey, proofJWK, http.MethodGet, uri, fmt.Sprintf("grant-directory-proof-%04d", sequence), nonce, body...)
				nonce = response.Header().Get("DPoP-Nonce")
			}
			return response
		}
		response := send(access, "?limit=2&cursor=opaque")
		if response.Code != 200 || response.Header().Get("Cache-Control") != "no-store" || repo.grantDirectoryIdentity != (store.UserIdentity{Issuer: issuer, Subject: "user-ustc-123"}) || repo.grantDirectoryDevice != deviceID || repo.grantDirectoryJKT != proofJKT || repo.grantDirectoryRuntime != "55555555-5555-4555-8555-555555555555" || repo.grantDirectoryLimit != 2 || repo.grantDirectoryCursor != "opaque" {
			t.Fatal("directory lost its authenticated caller", response.Code)
		}
		if response := send(access, ""); response.Code != 200 || repo.grantDirectoryLimit != 50 || repo.grantDirectoryCursor != "" {
			t.Fatal("default paging failed", response.Code)
		}
		before := repo.grantDirectoryCalls
		if response := send(access, "", map[string]string{"user_id": "attacker"}); response.Code != 400 || repo.grantDirectoryCalls != before {
			t.Fatal("GET body reached directory repository", response.Code)
		}
		for _, query := range []string{"?user_id=attacker", "?device_id=attacker", "?limit=0", "?limit=101", "?limit=01", "?limit=2&limit=3", "?cursor=", "?x=%zz"} {
			if response := send(access, query); response.Code != 400 || repo.grantDirectoryCalls != before {
				t.Fatal("invalid directory selectors reached repository", response.Code)
			}
		}
		if response := send(hostAccess, ""); response.Code != 403 || repo.grantDirectoryCalls != before {
			t.Fatal("host client enumerated runtime grants", response.Code)
		}
		repo.activeDeviceErr = store.ErrDeviceNotFound
		if response := send(access, ""); response.Code != 403 || repo.grantDirectoryCalls != before {
			t.Fatal("unregistered or revoked key enumerated devices", response.Code)
		}
		repo.activeDeviceErr = nil
		for _, failure := range []struct {
			err    error
			status int
		}{{store.ErrAccessDenied, 403}, {store.ErrGrantDirectoryInvalid, 400}, {store.ErrDatabaseUnavailable, 503}} {
			repo.grantDirectoryErr = failure.err
			if response := send(access, ""); response.Code != failure.status || strings.Contains(response.Body.String(), "grant_version") {
				t.Fatal("directory failure disclosed records", response.Code)
			}
		}
		repo.grantDirectoryErr = nil
	})
	t.Run("HTTP approval metadata binds the current phone without a socket", func(t *testing.T) {
		api := New(repo, identity, Config{HostClientIDs: []string{"host-client"}})
		repo.activeDeviceErr = nil
		const id = "66666666-6666-4666-8666-666666666666"
		repo.phoneApproval = store.ApprovalStatus{ApprovalID: id, RuntimeID: "55555555-5555-4555-8555-555555555555", RuntimeEpoch: "eeeeeeee-1111-4111-8111-111111111111", SessionID: "99999999-9999-4999-8999-999999999999", ExecutionID: "88888888-8888-4888-8888-888888888888", BindingSHA256: strings.Repeat("a", 64), State: "pending", ExpiresAt: now.Add(time.Minute)}
		nonce := ""
		sequence := 0
		send := func(token, path string, body ...any) *httptest.ResponseRecorder {
			sequence++
			uri := "https://api.example.edu/v1/approvals/" + path
			response := sendDPoPRequest(t, api, token, proofKey, proofJWK, http.MethodGet, uri, fmt.Sprintf("approval-status-proof-%04d", sequence), nonce, body...)
			nonce = response.Header().Get("DPoP-Nonce")
			if response.Code == 401 {
				sequence++
				response = sendDPoPRequest(t, api, token, proofKey, proofJWK, http.MethodGet, uri, fmt.Sprintf("approval-status-proof-%04d", sequence), nonce, body...)
				nonce = response.Header().Get("DPoP-Nonce")
			}
			return response
		}
		response := send(access, id)
		if response.Code != 200 || response.Header().Get("Cache-Control") != "no-store" || repo.phoneApprovalIdentity != (store.UserIdentity{Issuer: issuer, Subject: "user-ustc-123"}) || repo.phoneApprovalDevice != deviceID || repo.phoneApprovalJKT != proofJKT || repo.phoneApprovalID != id {
			t.Fatal("approval metadata lost its current HTTP actor", response.Code)
		}
		before := repo.phoneApprovalCalls
		for _, path := range []string{"invalid", id + "?user_id=attacker", id + "?connection_id=attacker", id + "?device_id=attacker"} {
			if response := send(access, path); response.Code != 400 || repo.phoneApprovalCalls != before {
				t.Fatal("caller approval selectors reached store", response.Code)
			}
		}
		if response := send(access, id, map[string]string{"runtime_id": "attacker"}); response.Code != 400 || repo.phoneApprovalCalls != before {
			t.Fatal("approval GET accepted a body", response.Code)
		}
		if response := send(hostAccess, id); response.Code != 403 || repo.phoneApprovalCalls != before {
			t.Fatal("Host client read phone approval metadata", response.Code)
		}
		repo.activeDeviceErr = store.ErrDeviceNotFound
		if response := send(access, id); response.Code != 403 || repo.phoneApprovalCalls != before {
			t.Fatal("unregistered phone read approval metadata", response.Code)
		}
		repo.activeDeviceErr = nil
		for _, failure := range []struct {
			err    error
			status int
		}{{store.ErrAccessDenied, 403}, {store.ErrApprovalInvalid, 400}, {store.ErrDatabaseUnavailable, 503}} {
			repo.phoneApprovalErr = failure.err
			if response := send(access, id); response.Code != failure.status || strings.Contains(response.Body.String(), "binding_sha256") {
				t.Fatal("failed status read disclosed a result", response.Code)
			}
		}
		repo.phoneApprovalErr = nil
	})
	t.Run("session directory binds its phone and resource before bounded paging", func(t *testing.T) {
		api := New(repo, identity, Config{HostClientIDs: []string{"host-client"}})
		repo.activeDeviceErr = nil
		repo.sessionDirectory = store.SessionDirectory{RuntimeID: "55555555-5555-4555-8555-555555555555", Items: []store.Session{{ID: "99999999-9999-4999-8999-999999999999", State: "available", LastPersistedSeq: 7, UpdatedAt: now}}}
		nonce := ""
		sequence := 0
		send := func(token, path string, body ...any) *httptest.ResponseRecorder {
			sequence++
			uri := "https://api.example.edu/v1/runtimes/55555555-5555-4555-8555-555555555555/session-directory" + path
			response := sendDPoPRequest(t, api, token, proofKey, proofJWK, http.MethodGet, uri, fmt.Sprintf("session-directory-proof-%04d", sequence), nonce, body...)
			nonce = response.Header().Get("DPoP-Nonce")
			if response.Code == 401 {
				sequence++
				response = sendDPoPRequest(t, api, token, proofKey, proofJWK, http.MethodGet, uri, fmt.Sprintf("session-directory-proof-%04d", sequence), nonce, body...)
				nonce = response.Header().Get("DPoP-Nonce")
			}
			return response
		}
		response := send(access, "?limit=2&cursor=opaque")
		if response.Code != 200 || response.Header().Get("Cache-Control") != "no-store" || repo.sessionDirectoryIdentity != (store.UserIdentity{Issuer: issuer, Subject: "user-ustc-123"}) || repo.sessionDirectoryDevice != deviceID || repo.sessionDirectoryJKT != proofJKT || repo.sessionDirectoryRuntime != "55555555-5555-4555-8555-555555555555" || repo.sessionDirectoryLimit != 2 || repo.sessionDirectoryCursor != "opaque" {
			t.Fatal("directory lost its authenticated caller", response.Code)
		}
		if response := send(access, ""); response.Code != 200 || repo.sessionDirectoryLimit != 50 || repo.sessionDirectoryCursor != "" {
			t.Fatal("default paging failed", response.Code)
		}
		before := repo.sessionDirectoryCalls
		if response := send(access, "", map[string]string{"user_id": "attacker"}); response.Code != 400 || repo.sessionDirectoryCalls != before {
			t.Fatal("GET body reached directory repository", response.Code)
		}
		for _, query := range []string{"?user_id=attacker", "?device_id=attacker", "?limit=0", "?limit=101", "?limit=01", "?limit=2&limit=3", "?cursor=", "?x=%zz"} {
			if response := send(access, query); response.Code != 400 || repo.sessionDirectoryCalls != before {
				t.Fatal("invalid directory selectors reached repository", response.Code)
			}
		}
		if response := send(hostAccess, ""); response.Code != 403 || repo.sessionDirectoryCalls != before {
			t.Fatal("host client enumerated runtime grants", response.Code)
		}
		repo.activeDeviceErr = store.ErrDeviceNotFound
		if response := send(access, ""); response.Code != 403 || repo.sessionDirectoryCalls != before {
			t.Fatal("unregistered or revoked key enumerated devices", response.Code)
		}
		repo.activeDeviceErr = nil
		for _, failure := range []struct {
			err    error
			status int
		}{{store.ErrAccessDenied, 403}, {store.ErrSessionDirectoryInvalid, 400}, {store.ErrDatabaseUnavailable, 503}} {
			repo.sessionDirectoryErr = failure.err
			if response := send(access, ""); response.Code != failure.status || strings.Contains(response.Body.String(), "last_persisted_seq") {
				t.Fatal("directory failure disclosed records", response.Code)
			}
		}
		repo.sessionDirectoryErr = nil
	})
	t.Run("installation management derives its current phone and rejects selectors", func(t *testing.T) {
		api := New(repo, identity, Config{HostClientIDs: []string{"host-client"}})
		repo.activeDeviceErr = nil
		target := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
		repo.installationDirectory = store.InstallationDirectory{Items: []store.InstallationSummary{{ID: target, HostID: "11111111-1111-4111-8111-111111111111", OrganizationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", HostAlias: "Private host metadata", OwnerUserID: "22222222-2222-4222-8222-222222222222", IsOwner: true, KeyVersion: 1, State: "active", CreatedAt: now}}}
		nonce := ""
		sequence := 0
		send := func(token, method, path string, body ...any) *httptest.ResponseRecorder {
			sequence++
			uri := "https://api.example.edu/v1/installations" + path
			response := sendDPoPRequest(t, api, token, proofKey, proofJWK, method, uri, fmt.Sprintf("installation-proof-%04d", sequence), nonce, body...)
			nonce = response.Header().Get("DPoP-Nonce")
			if response.Code == 401 {
				sequence++
				response = sendDPoPRequest(t, api, token, proofKey, proofJWK, method, uri, fmt.Sprintf("installation-proof-%04d", sequence), nonce, body...)
				nonce = response.Header().Get("DPoP-Nonce")
			}
			return response
		}
		if response := send(access, http.MethodGet, "?limit=2&cursor=opaque"); response.Code != 200 || response.Header().Get("Cache-Control") != "no-store" || repo.installationIdentity != (store.UserIdentity{Issuer: issuer, Subject: "user-ustc-123"}) || repo.installationDevice != deviceID || repo.installationJKT != proofJKT || repo.installationLimit != 2 || repo.installationCursor != "opaque" {
			t.Fatal("directory lost its authenticated caller", response.Code)
		}
		if response := send(access, http.MethodDelete, "/"+target); response.Code != 200 || repo.installationTarget != target || repo.installationDevice != deviceID || repo.installationJKT != proofJKT {
			t.Fatal("revocation lost its authenticated caller", response.Code)
		}
		before := repo.installationCalls + repo.installationRevokes
		for _, query := range []string{"?user_id=attacker", "?limit=0", "?limit=101", "?limit=2&limit=3", "?cursor="} {
			if response := send(access, http.MethodGet, query); response.Code != 400 || repo.installationCalls+repo.installationRevokes != before {
				t.Fatal("invalid directory query reached repository", response.Code)
			}
		}
		for _, path := range []string{"/invalid", "/" + target + "?user_id=attacker"} {
			if response := send(access, http.MethodDelete, path); response.Code != 400 || repo.installationCalls+repo.installationRevokes != before {
				t.Fatal("invalid installation target reached repository", response.Code)
			}
		}
		if response := send(access, http.MethodDelete, "/"+target, map[string]bool{"revoked": true}); response.Code != 400 || repo.installationCalls+repo.installationRevokes != before {
			t.Fatal("installation revoke accepted a body", response.Code)
		}
		for _, method := range []string{http.MethodGet, http.MethodDelete} {
			path := ""
			if method == http.MethodDelete {
				path = "/" + target
			}
			if response := send(hostAccess, method, path); response.Code != 403 || repo.installationCalls+repo.installationRevokes != before {
				t.Fatal("host client reached phone management", response.Code)
			}
		}
		repo.activeDeviceErr = store.ErrDeviceNotFound
		if response := send(access, http.MethodDelete, "/"+target); response.Code != 403 || repo.installationCalls+repo.installationRevokes != before {
			t.Fatal("revoked current phone managed installation", response.Code)
		}
		repo.activeDeviceErr = nil
		for _, failure := range []struct {
			err    error
			status int
		}{{store.ErrAccessDenied, 403}, {store.ErrInstallationManagementInvalid, 400}, {store.ErrDatabaseUnavailable, 503}} {
			repo.installationErr = failure.err
			for _, method := range []string{http.MethodGet, http.MethodDelete} {
				path := ""
				if method == http.MethodDelete {
					path = "/" + target
				}
				if response := send(access, method, path); response.Code != failure.status || strings.Contains(response.Body.String(), "Private host metadata") {
					t.Fatal("failed installation lookup exposed metadata", response.Code)
				}
			}
		}
		repo.installationErr = nil
	})
	t.Run("installation profile management derives its phone and rejects selectors", func(t *testing.T) {
		api := New(repo, identity, Config{HostClientIDs: []string{"host-client"}})
		repo.activeDeviceErr = nil
		target := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
		runtime := "55555555-5555-4555-8555-555555555555"
		repo.installationRuntimes = store.InstallationRuntimeDirectory{InstallationID: target, Items: []store.InstallationRuntimeSummary{{ID: runtime, State: "active"}}}
		nonce := ""
		sequence := 0
		send := func(token, method, path string, body ...any) *httptest.ResponseRecorder {
			sequence++
			uri := "https://api.example.edu/v1/installations/" + target + "/runtimes" + path
			response := sendDPoPRequest(t, api, token, proofKey, proofJWK, method, uri, fmt.Sprintf("profile-proof-%04d", sequence), nonce, body...)
			nonce = response.Header().Get("DPoP-Nonce")
			if response.Code == 401 {
				sequence++
				response = sendDPoPRequest(t, api, token, proofKey, proofJWK, method, uri, fmt.Sprintf("profile-proof-%04d", sequence), nonce, body...)
				nonce = response.Header().Get("DPoP-Nonce")
			}
			return response
		}
		if response := send(access, http.MethodGet, "?limit=2&cursor=opaque"); response.Code != 200 || response.Header().Get("Cache-Control") != "no-store" || repo.installationIdentity != (store.UserIdentity{Issuer: issuer, Subject: "user-ustc-123"}) || repo.installationDevice != deviceID || repo.installationJKT != proofJKT || repo.installationLimit != 2 || repo.installationCursor != "opaque" {
			t.Fatal("directory lost its authenticated caller", response.Code)
		}
		if response := send(access, http.MethodDelete, "/"+runtime); response.Code != 200 || repo.installationTarget != target || repo.installationRuntimeTarget != runtime || repo.installationDevice != deviceID || repo.installationJKT != proofJKT {
			t.Fatal("revocation lost its authenticated caller", response.Code)
		}
		before := repo.installationRuntimeCalls + repo.installationRuntimeRevokes
		for _, query := range []string{"?user_id=attacker", "?limit=0", "?limit=101", "?limit=2&limit=3", "?cursor="} {
			if response := send(access, http.MethodGet, query); response.Code != 400 || repo.installationRuntimeCalls+repo.installationRuntimeRevokes != before {
				t.Fatal("invalid directory query reached repository", response.Code)
			}
		}
		for _, path := range []string{"/invalid", "/" + runtime + "?user_id=attacker"} {
			if response := send(access, http.MethodDelete, path); response.Code != 400 || repo.installationRuntimeCalls+repo.installationRuntimeRevokes != before {
				t.Fatal("invalid installation target reached repository", response.Code)
			}
		}
		if response := send(access, http.MethodDelete, "/"+runtime, map[string]bool{"revoked": true}); response.Code != 400 || repo.installationRuntimeCalls+repo.installationRuntimeRevokes != before {
			t.Fatal("installation revoke accepted a body", response.Code)
		}
		for _, method := range []string{http.MethodGet, http.MethodDelete} {
			path := ""
			if method == http.MethodDelete {
				path = "/" + runtime
			}
			if response := send(hostAccess, method, path); response.Code != 403 || repo.installationRuntimeCalls+repo.installationRuntimeRevokes != before {
				t.Fatal("host client reached phone management", response.Code)
			}
		}
		repo.activeDeviceErr = store.ErrDeviceNotFound
		if response := send(access, http.MethodDelete, "/"+runtime); response.Code != 403 || repo.installationRuntimeCalls+repo.installationRuntimeRevokes != before {
			t.Fatal("revoked current phone managed installation", response.Code)
		}
		repo.activeDeviceErr = nil
		for _, failure := range []struct {
			err    error
			status int
		}{{store.ErrAccessDenied, 403}, {store.ErrInstallationManagementInvalid, 400}, {store.ErrDatabaseUnavailable, 503}} {
			repo.installationErr = failure.err
			for _, method := range []string{http.MethodGet, http.MethodDelete} {
				path := ""
				if method == http.MethodDelete {
					path = "/" + runtime
				}
				if response := send(access, method, path); response.Code != failure.status || strings.Contains(response.Body.String(), "last_seen_at") {
					t.Fatal("failed installation lookup exposed metadata", response.Code)
				}
			}
		}
		repo.installationErr = nil
	})
	t.Run("APK release selection binds current organization and phone proof", func(t *testing.T) {
		api := New(repo, identity, Config{HostClientIDs: []string{"host-client"}, Releases: releaseCatalog(t)})
		repo.releaseUser = "22222222-2222-4222-8222-222222222222"
		repo.activeDeviceErr = nil
		nonce := ""
		sequence := 0
		send := func(token, query string) *httptest.ResponseRecorder {
			uri := "https://api.example.edu/v1/app/releases/latest" + query
			sequence++
			response := sendDPoPRequest(t, api, token, proofKey, proofJWK, http.MethodGet, uri, fmt.Sprintf("release-proof-%04d", sequence), nonce)
			nonce = response.Header().Get("DPoP-Nonce")
			if response.Code == http.StatusUnauthorized {
				sequence++
				response = sendDPoPRequest(t, api, token, proofKey, proofJWK, http.MethodGet, uri, fmt.Sprintf("release-proof-%04d", sequence), nonce)
				nonce = response.Header().Get("DPoP-Nonce")
			}
			return response
		}
		query := "?organization_id=11111111-1111-4111-8111-111111111111&version_code=1&protocol_version=1&android_api=26"
		response := send(access, query)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"version_code":2`) || response.Header().Get("Cache-Control") != "no-store" ||
			repo.releaseCalls != 1 || repo.releaseIdentity != (store.UserIdentity{Issuer: issuer, Subject: "user-ustc-123"}) || repo.releaseDevice != deviceID || repo.releaseProof != proofJKT || repo.releaseOrganization != "11111111-1111-4111-8111-111111111111" || !repo.releaseUntil.Equal(now.Add(5*time.Minute)) {
			t.Fatal("release selection lost current authenticated actor", response.Code, response.Body.String())
		}
		for _, bad := range []string{"", query + "&device_id=attacker", query + "&version_code=2", strings.Replace(query, "version_code=1", "version_code=01", 1), strings.Replace(query, "android_api=26", "android_api=25", 1), query + "&x=%zz"} {
			if response := send(access, bad); response.Code != http.StatusBadRequest || repo.releaseCalls != 1 {
				t.Fatal("invalid release selector reached database", response.Code)
			}
		}
		if response := send(hostAccess, query); response.Code != http.StatusForbidden || repo.releaseCalls != 1 {
			t.Fatal("host client selected phone APK release", response.Code)
		}
		repo.activeDeviceErr = store.ErrDeviceNotFound
		if response := send(access, query); response.Code != http.StatusForbidden || repo.releaseCalls != 1 {
			t.Fatal("unregistered device reached release actor", response.Code)
		}
		repo.activeDeviceErr = nil
		for _, denied := range []struct {
			err  error
			code int
		}{{store.ErrAccessDenied, http.StatusForbidden}, {store.ErrDatabaseUnavailable, http.StatusServiceUnavailable}} {
			repo.releaseErr = denied.err
			if response := send(access, query); response.Code != denied.code || strings.Contains(response.Body.String(), "download_url") {
				t.Fatal("failed actor lookup disclosed release metadata", response.Code)
			}
		}
		repo.releaseErr = nil
	})
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
