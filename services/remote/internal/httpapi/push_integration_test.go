package httpapi_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/httpapi"
	"dsh-mobile-ustc/services/remote/internal/push"
	"dsh-mobile-ustc/services/remote/internal/store"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
	jose "github.com/go-jose/go-jose/v4"
)

type pushGoogleFixtureTransport struct {
	target    *url.URL
	transport http.RoundTripper
}

func (fixture pushGoogleFixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Host != "fcm.googleapis.com" && request.URL.Host != "oauth2.googleapis.com" {
		return nil, errors.New("unexpected fixture destination")
	}
	copy := request.Clone(request.Context())
	address := *request.URL
	copy.URL = &address
	copy.URL.Scheme = fixture.target.Scheme
	copy.URL.Host = fixture.target.Host
	return fixture.transport.RoundTrip(copy)
}
func TestPushHTTPSDPoPOwnershipChallengeThroughRealOAuthAndFCMTransport(t *testing.T) {
	ctx, database := testsupport.PostgresDatabase(t)
	proof, other, approval, issuer := approvalKey(t), approvalKey(t), approvalKey(t), approvalKey(t)
	proofJSON, proofJKT := approvalPublic(t, proof)
	otherJSON, otherJKT := approvalPublic(t, other)
	approvalJSON, approvalJKT := approvalPublic(t, approval)
	for _, input := range []struct {
		sql  string
		args []any
	}{
		{`insert into orgs(id,slug,name) values('11111111-1111-4111-8111-111111111111','push','Push fixture')`, nil},
		{`insert into users(id,issuer,subject) values('22222222-2222-4222-8222-222222222222','https://id.example.edu','push-owner')`, nil},
		{`insert into org_memberships(org_id,user_id,role) values('11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222','member')`, nil},
		{`insert into devices(id,user_id,name,approval_public_jwk,approval_key_thumbprint,proof_public_jwk,proof_key_thumbprint) values('33333333-3333-4333-8333-333333333333','22222222-2222-4222-8222-222222222222','phone',$1,$2,$3,$4),('44444444-4444-4444-8444-444444444444','22222222-2222-4222-8222-222222222222','other',$1,$5,$6,$7)`, []any{approvalJSON, approvalJKT, proofJSON, proofJKT, "other-approval", otherJSON, otherJKT}},
	} {
		if _, err := database.ExecContext(ctx, input.sql, input.args...); err != nil {
			t.Fatal(err)
		}
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var oauthCalls, providerCalls atomic.Int32
	packets := make(chan map[string]string, 4)
	google := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			oauthCalls.Add(1)
			if r.ParseForm() != nil {
				t.Error("OAuth form invalid")
			}
			signed, err := jose.ParseSigned(r.Form.Get("assertion"), []jose.SignatureAlgorithm{jose.RS256})
			if err != nil {
				t.Error("OAuth assertion invalid")
				w.WriteHeader(400)
				return
			}
			payload, err := signed.Verify(&rsaKey.PublicKey)
			if err != nil {
				t.Error("OAuth signature invalid")
				w.WriteHeader(400)
				return
			}
			var claims map[string]any
			_ = json.Unmarshal(payload, &claims)
			if claims["aud"] != "https://oauth2.googleapis.com/token" || claims["scope"] != "https://www.googleapis.com/auth/firebase.messaging" {
				t.Error("OAuth purpose changed")
			}
			_, _ = w.Write([]byte(`{"access_token":"PRIVATE_GOOGLE_ACCESS","token_type":"Bearer","expires_in":3600}`))
		case "/v1/projects/fixture-project/messages:send":
			providerCalls.Add(1)
			var body struct {
				Message struct {
					FID     string            `json:"fid"`
					Data    map[string]string `json:"data"`
					Android map[string]any    `json:"android"`
				} `json:"message"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || r.Header.Get("Authorization") != "Bearer PRIVATE_GOOGLE_ACCESS" || body.Message.FID != "c"+strings.Repeat("A", 21) || body.Message.Android["priority"] != "NORMAL" {
				t.Error("provider ownership packet invalid")
			}
			packets <- body.Message.Data
			_, _ = w.Write([]byte(`{"name":"projects/fixture-project/messages/proof-packet"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer google.Close()
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	serviceAccount, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "sender@fixture-project.iam.gserviceaccount.com", "private_key_id": "fixture-key", "private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})), "token_uri": "https://oauth2.googleapis.com/token"})
	peerURL, _ := url.Parse(google.URL)
	client := google.Client()
	client.Transport = pushGoogleFixtureTransport{target: peerURL, transport: client.Transport}
	source, err := push.NewServiceAccountTokens(serviceAccount, client)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := push.NewFCM("fixture-project", "cn.edu.ustc.dsh.mobile", source, client)
	if err != nil {
		t.Fatal(err)
	}
	key, lookup := make([]byte, 32), make([]byte, 32)
	_, _ = rand.Read(key)
	_, _ = rand.Read(lookup)
	cipher, err := push.NewCipher("one", map[string][]byte{"one": key}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(lookup)
	postgres := &store.Postgres{DB: database}
	repository, err := store.NewPushStore(ctx, postgres, cipher, "https://id.example.edu", "fixture-project", "cn.edu.ustc.dsh.mobile", hex.EncodeToString(fingerprint[:]), nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jose.JSONWebKey{Key: &issuer.PublicKey, KeyID: "push-issuer", Use: "sig", Algorithm: "ES256"}}})
	}))
	defer keys.Close()
	var handler http.Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	identity, err := auth.New(auth.Config{Issuer: "https://id.example.edu", Audience: "urn:dsh-push", JWKSURL: keys.URL, AllowedClients: []string{"mobile", "host"}, RequiredScopes: []string{"remote.access"}, PublicOrigin: server.URL, MaxTokenLifetime: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	handler = httpapi.New(postgres, identity, httpapi.Config{HostClientIDs: []string{"host"}, Push: repository})
	token := func(jkt string) string {
		now := time.Now()
		return approvalSign(t, issuer, jose.ES256, "push-issuer", "at+jwt", map[string]any{"iss": "https://id.example.edu", "sub": "push-owner", "aud": "urn:dsh-push", "client_id": "mobile", "jti": "push-access", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "scope": "remote.access", "cnf": map[string]string{"jkt": jkt}}, nil)
	}
	caller := &fileHTTPCaller{t: t, ctx: ctx, client: server.Client(), base: server.URL, key: proof, jwk: proofJSON}
	otherCaller := &fileHTTPCaller{t: t, ctx: ctx, client: server.Client(), base: server.URL, key: other, jwk: otherJSON}
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	revoke := base64.RawURLEncoding.EncodeToString(secret)
	id := exportTestUUID(t)
	registration := push.Registration{BindingID: id, OrganizationID: "11111111-1111-4111-8111-111111111111", Provider: "fcm", Address: "c" + strings.Repeat("A", 21), RevokeSHA256: push.SecretHash(revoke)}
	unauthenticated, err := server.Client().Post(server.URL+"/v1/push-bindings", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	unauthenticated.Body.Close()
	if unauthenticated.StatusCode != 401 {
		t.Fatal("push skipped authentication")
	}
	for _, path := range []string{"/v1/push-bindings", "/v1/push-bindings/" + id + "/confirm", "/v1/push-bindings/" + id + "/lease", "/v1/notifications/" + id + "/receipts"} {
		code, body := caller.call(token(proofJKT), "POST", path, map[string]string{"untrusted": "must-reject"})
		if code != 400 || !strings.Contains(string(body), "protocol.invalid") {
			t.Fatal("invalid notification request body looked successful")
		}
	}
	code, raw := caller.call(token(proofJKT), "POST", "/v1/push-bindings", registration)
	if code != 201 || strings.Contains(string(raw), registration.Address) || strings.Contains(string(raw), registration.RevokeSHA256) {
		t.Fatalf("registration response exposed endpoint or failed: %d", code)
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); push.Run(workerCtx, repository, sender) }()
	defer func() { cancel(); <-done }()
	var packet map[string]string
	select {
	case packet = <-packets:
	case <-time.After(5 * time.Second):
		t.Fatal("provider ownership packet missing")
	}
	if packet["binding_id"] != id || packet["kind"] != "registration_challenge" || !push.Secret(packet["challenge"]) {
		t.Fatal("ownership packet lost binding")
	}
	code, _ = otherCaller.call(token(otherJKT), "POST", "/v1/push-bindings/"+id+"/confirm", map[string]string{"challenge": packet["challenge"]})
	if code != 403 {
		t.Fatal("provider proof crossed devices")
	}
	code, raw = caller.call(token(proofJKT), "POST", "/v1/push-bindings/"+id+"/confirm", map[string]string{"challenge": packet["challenge"]})
	if code != 200 || !strings.Contains(string(raw), `"state":"active"`) {
		t.Fatalf("receiver proof failed: %d", code)
	}
	code, _ = caller.call(token(proofJKT), "POST", "/v1/push-bindings/"+id+"/lease", map[string]any{})
	if code != 200 {
		t.Fatal("confirmed channel did not renew")
	}
	if oauthCalls.Load() != 1 || providerCalls.Load() != 1 {
		t.Fatal("ownership proof was automatically resent")
	}
	request, _ := http.NewRequest("DELETE", server.URL+"/v1/push-bindings/"+id, nil)
	request.Header.Set("Authorization", "DSH-Push-Revoke "+revoke)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal("logout cleanup needed an expired OAuth session")
	}
	code, raw = caller.call(token(proofJKT), "GET", "/v1/push-bindings/"+id, nil)
	if code != 200 || !strings.Contains(string(raw), `"state":"disabled"`) {
		t.Fatal("logout left provider endpoint active")
	}
}
