package httpapi_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func TestAndroidIssuerFixtureRequiresItsPermitPKCEBoundKeyAndOneUseCode(t *testing.T) {
	fixture := &androidOIDCFixture{t: t, secret: androidSecret(t), key: approvalKey(t), codes: map[string]androidAuthorization{}, proofs: map[string]bool{}}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !fixture.serve(response, request) {
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	fixture.origin, fixture.issuer = server.URL, server.URL+"/issuer"
	proofKey := approvalKey(t)
	public, jkt := approvalPublic(t, proofKey)
	verifier := androidSecret(t)
	hash := sha256.Sum256([]byte(verifier))
	params := url.Values{"client_id": {"mobile"}, "redirect_uri": {"cn.edu.ustc.dsh.mobile:/oauth2redirect"}, "response_type": {"code"}, "resource": {"urn:dsh-android-relay"},
		"scope": {"openid remote.access"}, "nonce": {androidSecret(t)}, "state": {androidSecret(t)}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}, "dpop_jkt": {jkt}}
	authorize := func(permit string, want int) string {
		t.Helper()
		raw, _ := json.Marshal(map[string]string{"authorization_uri": server.URL + "/authorize?" + params.Encode()})
		request, _ := http.NewRequest("POST", server.URL+"/fixture/authorize", strings.NewReader(string(raw)))
		request.Header.Set("X-DSH-Fixture", permit)
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("authorization status=%d, want=%d", response.StatusCode, want)
		}
		var body map[string]string
		if json.NewDecoder(response.Body).Decode(&body) != nil {
			t.Fatal("invalid fixture envelope")
		}
		return body["code"]
	}
	proof := func(key any, jwk json.RawMessage, id string) string {
		return approvalSign(t, key, jose.ES256, "", "dpop+jwt", map[string]any{"htm": "POST", "htu": server.URL + "/token", "iat": time.Now().Unix(), "jti": id}, map[jose.HeaderKey]any{"jwk": jwk})
	}
	exchange := func(code, codeVerifier, dpop string, want int) {
		t.Helper()
		form := url.Values{"code": {code}, "code_verifier": {codeVerifier}, "client_id": {"mobile"}, "redirect_uri": {"cn.edu.ustc.dsh.mobile:/oauth2redirect"}, "resource": {"urn:dsh-android-relay"}, "grant_type": {"authorization_code"}}
		request, _ := http.NewRequest("POST", server.URL+"/token", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("DPoP", dpop)
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("token status=%d, want=%d", response.StatusCode, want)
		}
	}
	authorize("", 403)
	code := authorize(fixture.secret, 200)
	valid := proof(proofKey, json.RawMessage(public), "valid-fixture-proof-0001")
	exchange(code, "wrong-verifier", valid, 400)
	wrong := approvalKey(t)
	wrongPublic, _ := approvalPublic(t, wrong)
	exchange(code, verifier, proof(wrong, json.RawMessage(wrongPublic), "wrong-key-fixture-proof-0001"), 400)
	exchange(code, verifier, valid, 200)
	exchange(code, verifier, proof(proofKey, json.RawMessage(public), "reused-code-fixture-proof-0001"), 400)
	second := authorize(fixture.secret, 200)
	exchange(second, verifier, valid, 400)
}
