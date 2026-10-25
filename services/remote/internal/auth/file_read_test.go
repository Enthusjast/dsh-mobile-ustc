package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNodeFileReadProofGoldenUsesRegisteredInstallationKey(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../contracts/security/file-read-proof.json"))
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Now      time.Time       `json:"now"`
		Public   json.RawMessage `json:"public_jwk"`
		Compact  string          `json:"compact"`
		Identity struct {
			InstallationID string `json:"installationId"`
			RuntimeID      string `json:"runtimeId"`
			Epoch          string `json:"epoch"`
			ConnectionID   string `json:"connectionId"`
			HandoffID      string `json:"handoffId"`
			FileID         string `json:"fileId"`
			Token          string `json:"token"`
			URI            string `json:"uri"`
		} `json:"identity"`
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	thumb, err := PublicP256JWKThumbprintJSON(golden.Public)
	if err != nil {
		t.Fatal(err)
	}
	origin, _ := url.Parse("https://api.example.edu")
	verifier := &Authenticator{publicOrigin: origin, clock: func() time.Time { return golden.Now }}
	identity := golden.Identity
	expected := FileReadExpectation{InstallationID: identity.InstallationID, KeyThumbprint: thumb, RuntimeID: identity.RuntimeID, RuntimeEpoch: identity.Epoch, ConnectionID: identity.ConnectionID, HandoffID: identity.HandoffID, FileID: identity.FileID, Token: identity.Token}
	if err := verifier.VerifyFileReadProof(httptest.NewRequest("GET", identity.URI, nil), golden.Compact, golden.Public, expected); err != nil {
		t.Fatal(err)
	}
}

func TestFileReadProofBindsPurposeRouteTicketAndLiveHostGeneration(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := testProofJWK(key)
	public, _ := json.Marshal(jwk)
	thumb, _ := JWKThumbprint(jwk)
	now := time.Now().UTC().Truncate(time.Second)
	origin, _ := url.Parse("https://api.example.edu")
	verifier := &Authenticator{publicOrigin: origin, clock: func() time.Time { return now }}
	expected := FileReadExpectation{InstallationID: "11111111-1111-4111-8111-111111111111", KeyThumbprint: thumb, RuntimeID: "22222222-2222-4222-8222-222222222222", RuntimeEpoch: "33333333-3333-4333-8333-333333333333", ConnectionID: "44444444-4444-4444-8444-444444444444", HandoffID: "55555555-5555-4555-8555-555555555555", FileID: "66666666-6666-4666-8666-666666666666", Token: strings.Repeat("A", 43)}
	path := "/v1/host-files/" + expected.HandoffID + "/content"
	request := httptest.NewRequest("GET", origin.String()+path, nil)
	tokenHash := sha256.Sum256([]byte(expected.Token))
	claims := map[string]any{"iss": expected.InstallationID, "aud": FileReadAudience, "htm": "GET", "htu": origin.String() + path, "runtime_id": expected.RuntimeID, "runtime_epoch": expected.RuntimeEpoch, "connection_id": expected.ConnectionID, "handoff_id": expected.HandoffID, "file_id": expected.FileID, "ath": base64.RawURLEncoding.EncodeToString(tokenHash[:]), "iat": now.Unix(), "jti": "file-read-proof-00000001"}
	sign := func(mutate func(map[string]any), signer *ecdsa.PrivateKey, header map[string]any) string {
		copy := map[string]any{}
		for key, value := range claims {
			copy[key] = value
		}
		if mutate != nil {
			mutate(copy)
		}
		if header == nil {
			header = map[string]any{"typ": FileReadProofType, "alg": "ES256"}
		}
		return signCompact(t, header, copy, signer)
	}
	if err := verifier.VerifyFileReadProof(request, sign(nil, key, nil), public, expected); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"iss", "aud", "htm", "htu", "runtime_id", "runtime_epoch", "connection_id", "handoff_id", "file_id", "ath"} {
		t.Run(field, func(t *testing.T) {
			proof := sign(func(claims map[string]any) { claims[field] = "wrong-purpose-or-target" }, key, nil)
			if verifier.VerifyFileReadProof(request, proof, public, expected) == nil {
				t.Fatal("unbound proof accepted")
			}
		})
	}
	for _, proof := range []string{sign(nil, other, nil), sign(func(claims map[string]any) { claims["iat"] = now.Add(-time.Minute).Unix() }, key, nil), sign(func(claims map[string]any) { claims["extra"] = "selector" }, key, nil), sign(nil, key, map[string]any{"typ": FileReadProofType, "alg": "ES256", "jwk": jwk})} {
		if verifier.VerifyFileReadProof(request, proof, public, expected) == nil {
			t.Fatal("invalid proof accepted")
		}
	}
	for _, target := range []string{path + "?file_id=other", path + "/../content", "/v1/other-files/" + expected.HandoffID + "/content"} {
		if verifier.VerifyFileReadProof(httptest.NewRequest("GET", origin.String()+target, nil), sign(nil, key, nil), public, expected) == nil {
			t.Fatal("proof replayed on another request route")
		}
	}
}
