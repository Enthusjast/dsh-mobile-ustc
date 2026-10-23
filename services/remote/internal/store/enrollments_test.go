package store

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/auth"
)

func TestNormalizeEnrollmentInputCanonicalizesWorkspacesAndBindsRequestBody(t *testing.T) {
	input := validEnrollmentInput(t)
	normalized, codeHash, requestHash, err := NormalizeEnrollmentInput(input)
	if err != nil {
		t.Fatalf("valid enrollment rejected: %v", err)
	}
	if normalized.Alias != "Lab host" || normalized.ProfileRef != "profile-main" {
		t.Fatalf("display values were not normalized: %+v", normalized)
	}
	if normalized.WorkspaceRefs[0] != "alpha" || normalized.WorkspaceRefs[1] != "project" {
		t.Fatalf("workspace refs were not sorted: %v", normalized.WorkspaceRefs)
	}
	if len(codeHash) != 32 || len(requestHash) != 32 {
		t.Fatalf("hash lengths are code=%d request=%d, want 32", len(codeHash), len(requestHash))
	}

	reordered := input
	reordered.WorkspaceRefs = []string{"alpha", "project"}
	_, _, reorderedHash, err := NormalizeEnrollmentInput(reordered)
	if err != nil || string(reorderedHash) != string(requestHash) {
		t.Fatalf("workspace order changed request fingerprint: %v", err)
	}
	changed := input
	changed.Alias = "Different host"
	_, _, changedHash, err := NormalizeEnrollmentInput(changed)
	if err != nil || string(changedHash) == string(requestHash) {
		t.Fatal("changed enrollment details kept the same request fingerprint")
	}
}

func TestNormalizeEnrollmentInputRejectsUnsafeOrAmbiguousValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*EnrollmentInput)
	}{
		{name: "path profile", mutate: func(input *EnrollmentInput) { input.ProfileRef = "../workspace" }},
		{name: "path workspace", mutate: func(input *EnrollmentInput) { input.WorkspaceRefs = []string{"../../secret"} }},
		{name: "duplicate workspace", mutate: func(input *EnrollmentInput) { input.WorkspaceRefs = []string{"project", "project"} }},
		{name: "invalid confirmation code", mutate: func(input *EnrollmentInput) { input.Code = "not-a-random-code" }},
		{name: "mismatched key thumbprint", mutate: func(input *EnrollmentInput) { input.InstallationKeyThumbprint = strings.Repeat("A", 43) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validEnrollmentInput(t)
			test.mutate(&input)
			if _, _, _, err := NormalizeEnrollmentInput(input); !errors.Is(err, ErrEnrollmentInvalid) {
				t.Fatalf("NormalizeEnrollmentInput() error=%v, want ErrEnrollmentInvalid", err)
			}
		})
	}
}

func validEnrollmentInput(t *testing.T) EnrollmentInput {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := json.Marshal(map[string]string{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(key.PublicKey.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.FillBytes(make([]byte, 32))),
	})
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := auth.PublicP256JWKThumbprintJSON(jwk)
	if err != nil {
		t.Fatal(err)
	}
	code := make([]byte, 32)
	if _, err := rand.Read(code); err != nil {
		t.Fatal(err)
	}
	return EnrollmentInput{
		Issuer: "https://id.example.edu", Subject: "host-owner", RequestID: "44444444-4444-4444-8444-444444444444",
		OrganizationID: "55555555-5555-4555-8555-555555555555", Alias: "  Lab host  ", ProfileRef: " profile-main ",
		DSHVersion: "0.2.1-rc.2", ApplicationVersion: "1.0.0", PluginVersion: "0.1.0", ProtocolVersion: 1,
		InstallationPublicJWK: jwk, InstallationKeyThumbprint: thumbprint,
		Code: base64.RawURLEncoding.EncodeToString(code), WorkspaceRefs: []string{"project", "alpha"},
	}
}
