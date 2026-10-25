package httpapi_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	jose "github.com/go-jose/go-jose/v4"
)

// This issuer exists only in the explicit device composition. It authenticates
// the fixture subject, verifies real PKCE/DPoP and never replaces production IdP setup.
type androidAuthorization struct {
	nonce, challenge, jkt string
	expires               time.Time
}
type androidOIDCFixture struct {
	t                      *testing.T
	origin, issuer, secret string
	key                    *ecdsa.PrivateKey
	mu                     sync.Mutex
	codes                  map[string]androidAuthorization
	proofs                 map[string]bool
	exchanges              int
}

func androidSecret(t *testing.T) string {
	t.Helper()
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}
func androidJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
func (fixture *androidOIDCFixture) serve(response http.ResponseWriter, request *http.Request) bool {
	switch request.URL.Path {
	case "/issuer/.well-known/openid-configuration":
		androidJSON(response, 200, map[string]any{"issuer": fixture.issuer, "authorization_endpoint": fixture.origin + "/authorize", "token_endpoint": fixture.origin + "/token", "jwks_uri": fixture.origin + "/jwks",
			"response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"}, "grant_types_supported": []string{"authorization_code"},
			"token_endpoint_auth_methods_supported": []string{"none"}, "dpop_signing_alg_values_supported": []string{"ES256"}, "id_token_signing_alg_values_supported": []string{"ES256"}})
	case "/jwks":
		androidJSON(response, 200, map[string]any{"keys": []jose.JSONWebKey{{Key: &fixture.key.PublicKey, KeyID: "android-fixture", Algorithm: "ES256", Use: "sig"}}})
	case "/fixture/authorize":
		fixture.authorize(response, request)
	case "/token":
		fixture.token(response, request)
	case "/authorize":
		androidJSON(response, 400, map[string]string{"error": "fixture_requires_explicit_authorization"})
	default:
		return false
	}
	return true
}
func (fixture *androidOIDCFixture) authorize(response http.ResponseWriter, request *http.Request) {
	var input struct {
		URI string `json:"authorization_uri"`
	}
	request.Body = http.MaxBytesReader(response, request.Body, 16<<10)
	if request.Method != "POST" || subtle.ConstantTimeCompare([]byte(request.Header.Get("X-DSH-Fixture")), []byte(fixture.secret)) != 1 || json.NewDecoder(request.Body).Decode(&input) != nil {
		androidJSON(response, 403, map[string]string{"error": "fixture_denied"})
		return
	}
	uri, err := url.Parse(input.URI)
	if err != nil || uri.Scheme+"://"+uri.Host+uri.Path != fixture.origin+"/authorize" || uri.User != nil || uri.Fragment != "" {
		androidJSON(response, 400, map[string]string{"error": "fixture_invalid_authorization"})
		return
	}
	params := uri.Query()
	for _, values := range params {
		if len(values) != 1 {
			androidJSON(response, 400, map[string]string{"error": "fixture_duplicate_parameter"})
			return
		}
	}
	validNonce := func(value string) bool {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
		return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
	}
	if params.Get("client_id") != "mobile" || params.Get("redirect_uri") != "cn.edu.ustc.dsh.mobile:/oauth2redirect" || params.Get("response_type") != "code" || params.Get("resource") != "urn:dsh-android-relay" ||
		params.Get("code_challenge_method") != "S256" || !validNonce(params.Get("nonce")) || !validNonce(params.Get("state")) || !validNonce(params.Get("code_challenge")) || !validNonce(params.Get("dpop_jkt")) {
		androidJSON(response, 400, map[string]string{"error": "fixture_invalid_binding"})
		return
	}
	scopes := strings.Fields(params.Get("scope"))
	if len(scopes) != 2 || !(scopes[0] == "openid" && scopes[1] == "remote.access" || scopes[1] == "openid" && scopes[0] == "remote.access") {
		androidJSON(response, 400, map[string]string{"error": "fixture_invalid_scope"})
		return
	}
	code := androidSecret(fixture.t)
	fixture.mu.Lock()
	fixture.codes[code] = androidAuthorization{nonce: params.Get("nonce"), challenge: params.Get("code_challenge"), jkt: params.Get("dpop_jkt"), expires: time.Now().Add(90 * time.Second)}
	fixture.mu.Unlock()
	androidJSON(response, 200, map[string]string{"code": code, "state": params.Get("state")})
}
func (fixture *androidOIDCFixture) token(response http.ResponseWriter, request *http.Request) {
	fail := func() { androidJSON(response, 400, map[string]string{"error": "invalid_grant"}) }
	request.Body = http.MaxBytesReader(response, request.Body, 16<<10)
	if request.Method != "POST" || request.ParseForm() != nil || request.Header.Get("Authorization") != "" {
		fail()
		return
	}
	for _, values := range request.PostForm {
		if len(values) != 1 {
			fail()
			return
		}
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	code := request.PostForm.Get("code")
	authorization, ok := fixture.codes[code]
	verifierHash := sha256.Sum256([]byte(request.PostForm.Get("code_verifier")))
	if !ok || !authorization.expires.After(time.Now()) || request.PostForm.Get("grant_type") != "authorization_code" || request.PostForm.Get("client_id") != "mobile" || request.PostForm.Get("redirect_uri") != "cn.edu.ustc.dsh.mobile:/oauth2redirect" ||
		request.PostForm.Get("resource") != "urn:dsh-android-relay" || base64.RawURLEncoding.EncodeToString(verifierHash[:]) != authorization.challenge {
		fail()
		return
	}
	compact := request.Header.Get("DPoP")
	if len(compact) == 0 || len(compact) > 16<<10 {
		fail()
		return
	}
	signed, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(signed.Signatures) != 1 {
		fail()
		return
	}
	header := signed.Signatures[0].Protected
	if header.JSONWebKey == nil || !header.JSONWebKey.IsPublic() || header.ExtraHeaders["typ"] != "dpop+jwt" {
		fail()
		return
	}
	public, err := json.Marshal(header.JSONWebKey)
	if err != nil {
		fail()
		return
	}
	jkt, err := auth.PublicP256JWKThumbprintJSON(public)
	if err != nil || jkt != authorization.jkt {
		fail()
		return
	}
	raw, err := signed.Verify(header.JSONWebKey.Key)
	var proof struct {
		Method string `json:"htm"`
		URI    string `json:"htu"`
		IAT    int64  `json:"iat"`
		JTI    string `json:"jti"`
		ATH    string `json:"ath"`
	}
	if err != nil || json.Unmarshal(raw, &proof) != nil || proof.Method != "POST" || proof.URI != fixture.origin+"/token" || proof.IAT < time.Now().Unix()-5 || proof.IAT > time.Now().Unix()+5 || len(proof.JTI) < 16 || proof.ATH != "" || fixture.proofs[proof.JTI] {
		fail()
		return
	}
	fixture.proofs[proof.JTI] = true
	delete(fixture.codes, code)
	fixture.exchanges++
	now := time.Now().UTC().Truncate(time.Second)
	common := map[string]any{"iss": fixture.issuer, "sub": "android-fixture", "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix()}
	access := map[string]any{}
	for name, value := range common {
		access[name] = value
	}
	access["aud"], access["client_id"], access["jti"], access["scope"] = "urn:dsh-android-relay", "mobile", androidSecret(fixture.t), "remote.access"
	access["cnf"], access["auth_time"], access["acr"], access["amr"] = map[string]string{"jkt": jkt}, now.Unix(), "fixture:2", []string{"otp"}
	identity := map[string]any{}
	for name, value := range common {
		identity[name] = value
	}
	identity["aud"], identity["nonce"], identity["auth_time"] = "mobile", authorization.nonce, now.Unix()
	androidJSON(response, 200, map[string]any{"access_token": approvalSign(fixture.t, fixture.key, jose.ES256, "android-fixture", "at+jwt", access, nil),
		"id_token": approvalSign(fixture.t, fixture.key, jose.ES256, "android-fixture", "JWT", identity, nil), "token_type": "DPoP", "expires_in": 600})
}
