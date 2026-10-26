package push

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestCipherRotationOwnerBindingAndLogRedaction(t *testing.T) {
	one, two, lookup := make([]byte, 32), make([]byte, 32), make([]byte, 32)
	_, _ = rand.Read(one)
	_, _ = rand.Read(two)
	_, _ = rand.Read(lookup)
	old, err := NewCipher("one", map[string][]byte{"one": one}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := old.Seal([]byte("PRIVATE_ADDRESS"), "owner/device/key/binding")
	if err != nil {
		t.Fatal(err)
	}
	current, err := NewCipher("two", map[string][]byte{"one": one, "two": two}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := current.Open(sealed, "owner/device/key/binding")
	if err != nil || string(plain) != "PRIVATE_ADDRESS" {
		t.Fatal("rotation lost original ciphertext")
	}
	if _, err := current.Open(sealed, "another/device/key/binding"); err == nil {
		t.Fatal("ciphertext moved between owners")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := current.Open(sealed, "owner/device/key/binding"); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	if old.AddressHash("fcm", "project", "PRIVATE_ADDRESS") != current.AddressHash("fcm", "project", "PRIVATE_ADDRESS") || old.AddressHash("fcm", "other", "PRIVATE_ADDRESS") == old.AddressHash("fcm", "project", "PRIVATE_ADDRESS") {
		t.Fatal("endpoint lookup binding changed")
	}
	out := Outbound{Provider: "fcm", Address: "PRIVATE_ADDRESS", Challenge: "PRIVATE_NONCE"}
	if strings.Contains(fmt.Sprintf("%v %#v %+v", out, out, current), "PRIVATE") {
		t.Fatal("secret entered log representation")
	}
	if _, err := json.Marshal(out); err == nil {
		t.Fatal("generic serialization leaked transport secrets")
	}
}

func account(t *testing.T) (*ServiceAccountTokens, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "sender@fixture-project.iam.gserviceaccount.com", "private_key_id": "fixture-key", "private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})), "token_uri": googleTokenURL})
	value, err := NewServiceAccountTokens(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return value, key
}
func TestOAuthUsesBoundServiceAccountJWTAndCachesWithoutLeakingErrors(t *testing.T) {
	source, key := account(t)
	var calls atomic.Int32
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.Header.Get("Authorization") != "" || r.ParseForm() != nil || r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Error("invalid OAuth request")
		}
		signed, err := jose.ParseSigned(r.Form.Get("assertion"), []jose.SignatureAlgorithm{jose.RS256})
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		payload, err := signed.Verify(&key.PublicKey)
		if err != nil {
			t.Error(err)
			return
		}
		var claims map[string]any
		_ = json.Unmarshal(payload, &claims)
		if claims["aud"] != googleTokenURL || claims["scope"] != messagingScope || claims["iss"] != source.email || int64(claims["exp"].(float64)-claims["iat"].(float64)) != 3600 {
			t.Error("OAuth JWT purpose changed")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"PRIVATE_ACCESS_TOKEN","token_type":"Bearer","expires_in":3600}`))
	}))
	defer peer.Close()
	source.endpoint = peer.URL
	source.client = secureClient(peer.Client())
	for range 2 {
		token, err := source.Token(context.Background())
		if err != nil || token != "PRIVATE_ACCESS_TOKEN" {
			t.Fatal("OAuth failed")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("token was not cached")
	}
	source.Invalidate("another token")
	_, _ = source.Token(context.Background())
	if calls.Load() != 1 {
		t.Fatal("late invalidation erased a newer token")
	}
	source.Invalidate("PRIVATE_ACCESS_TOKEN")
	_, _ = source.Token(context.Background())
	if calls.Load() != 2 {
		t.Fatal("rejected token was reused")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", source, source), "PRIVATE") {
		t.Fatal("OAuth secret in logs")
	}
}

type fixedTokens struct{ calls atomic.Int32 }

func (tokens *fixedTokens) Token(context.Context) (string, error) {
	tokens.calls.Add(1)
	return "PRIVATE_ACCESS_TOKEN", nil
}
func TestFCMDataOnlyFIDTransportPreservesReferencesAndRechecksAfterAuthentication(t *testing.T) {
	var calls atomic.Int32
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer PRIVATE_ACCESS_TOKEN" || r.Header.Get("Cookie") != "" {
			t.Error("provider authentication changed")
		}
		var root struct {
			Message map[string]json.RawMessage `json:"message"`
		}
		if json.NewDecoder(r.Body).Decode(&root) != nil {
			t.Error("invalid body")
		}
		if len(root.Message) != 3 || root.Message["fid"] == nil || root.Message["notification"] != nil || root.Message["token"] != nil {
			t.Error("unbounded/automatic notification payload")
		}
		var android map[string]any
		_ = json.Unmarshal(root.Message["android"], &android)
		if len(android) != 3 || android["collapse_key"] != nil || android["restricted_package_name"] != "cn.edu.ustc.dsh.mobile" {
			t.Error("collapsed unrelated requests or lost package binding")
		}
		var data map[string]string
		_ = json.Unmarshal(root.Message["data"], &data)
		if len(data) != 5 || data["runtime_id"] != "" || data["session_id"] != "" || data["arguments"] != "" {
			t.Error("push carried protected context")
		}
		if data["kind"] == "interaction" && (android["priority"] != "HIGH" || data["notification_id"] == "") || data["kind"] == "registration_challenge" && (android["priority"] != "NORMAL" || data["challenge"] == "") {
			t.Error("invalid priority/purpose")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"projects/fixture-project/messages/opaque-result"}`))
	}))
	defer peer.Close()
	tokens := &fixedTokens{}
	sender, err := NewFCM("fixture-project", "cn.edu.ustc.dsh.mobile", tokens, peer.Client())
	if err != nil {
		t.Fatal(err)
	}
	sender.endpoint = peer.URL
	base := Outbound{Provider: "fcm", Address: "c" + strings.Repeat("A", 21), BindingID: "11111111-1111-4111-8111-111111111111", NotificationID: "22222222-2222-4222-8222-222222222222", Kind: "approval", ExpiresAt: time.Now().Add(time.Minute)}
	checks := 0
	result := sender.Send(context.Background(), base, func(context.Context) error {
		if tokens.calls.Load() == 0 {
			t.Error("authority checked before potentially slow OAuth")
		}
		checks++
		return nil
	})
	if result.State != Accepted || !Digest(result.ProviderID) || checks != 1 {
		t.Fatal("provider acceptance missing")
	}
	base.Kind = "challenge"
	base.NotificationID = ""
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	base.Challenge = base64.RawURLEncoding.EncodeToString(nonce)
	if sender.Send(context.Background(), base, func(context.Context) error { return nil }).State != Accepted {
		t.Fatal("ownership challenge failed")
	}
	if sender.Send(context.Background(), base, func(context.Context) error { return ErrAccess }).State != Expired || calls.Load() != 2 {
		t.Fatal("revoked authority reached provider")
	}
}
func TestFCMFailureClassificationIsBoundedAndSecretFree(t *testing.T) {
	status := 503
	body := `{"error":{"message":"PRIVATE_PROVIDER_SECRET"}}`
	redirect := false
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if redirect {
			w.Header().Set("Location", "https://must-not-contact.example.invalid")
			w.WriteHeader(307)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer peer.Close()
	sender, _ := NewFCM("fixture-project", "cn.edu.ustc.dsh.mobile", &fixedTokens{}, peer.Client())
	sender.endpoint = peer.URL
	out := Outbound{Provider: "fcm", Address: "c" + strings.Repeat("B", 21), BindingID: "11111111-1111-4111-8111-111111111111", NotificationID: "22222222-2222-4222-8222-222222222222", Kind: "approval", ExpiresAt: time.Now().Add(time.Minute)}
	check := func(context.Context) error { return nil }
	result := sender.Send(context.Background(), out, check)
	if result.State != Retry || result.RetryAfter != 120*time.Second || strings.Contains(fmt.Sprint(result), "PRIVATE") {
		t.Fatal("unbounded provider retry/error")
	}
	status = 404
	body = `{"error":{"details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}`
	if sender.Send(context.Background(), out, check).State != InvalidEndpoint {
		t.Fatal("dead installation retained")
	}
	status = 400
	body = `{"error":{"message":"PRIVATE_PROVIDER_SECRET"}}`
	if sender.Send(context.Background(), out, check).State != Failed {
		t.Fatal("invalid payload retried indefinitely")
	}
	redirect = true
	if sender.Send(context.Background(), out, check).State == Accepted {
		t.Fatal("redirect accepted")
	}
}
