package auth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAuthenticationEvidenceComesFromVerifiedAccessToken(t *testing.T) {
	keys := newTestKeys(t)
	principal, err := keys.verifier.VerifyAccessToken(t.Context(), keys.token(t, func(claims map[string]any) {
		claims["auth_time"] = keys.now.Add(-time.Minute).Unix()
		claims["acr"] = "urn:test:school:step-up"
		claims["amr"] = []string{"pwd", "otp"}
	}))
	if err != nil || !principal.AuthenticatedAt.Equal(keys.now.Add(-time.Minute)) || principal.ACR != "urn:test:school:step-up" || len(principal.AMR) != 2 {
		t.Fatalf("verified authentication evidence was not retained: %+v, %v", principal, err)
	}
	ordinary, err := keys.verifier.VerifyAccessToken(t.Context(), keys.token(t, nil))
	if err != nil || !ordinary.AuthenticatedAt.IsZero() || ordinary.ACR != "" || ordinary.AMR != nil {
		t.Fatalf("optional claims acquired implicit evidence: %+v, %v", ordinary, err)
	}
}

func TestJWTRejectsMalformedAuthenticationEvidence(t *testing.T) {
	keys := newTestKeys(t)
	for _, test := range []struct {
		name, claim string
		value       any
	}{
		{"string time", "auth_time", "123"},
		{"null time", "auth_time", nil},
		{"negative time", "auth_time", -1},
		{"future time", "auth_time", keys.now.Add(time.Minute).Unix()},
		{"null acr", "acr", nil},
		{"empty acr", "acr", ""},
		{"long acr", "acr", strings.Repeat("a", 513)},
		{"control acr", "acr", "school\nadmin"},
		{"string amr", "amr", "otp"},
		{"null amr", "amr", nil},
		{"object method", "amr", []any{map[string]any{"otp": true}}},
		{"duplicate methods", "amr", []string{"otp", "otp"}},
		{"empty method", "amr", []string{""}},
		{"long method", "amr", []string{strings.Repeat("a", 129)}},
		{"control method", "amr", []string{"otp\n"}},
		{"too many methods", "amr", make([]string, 33)},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := keys.verifier.VerifyAccessToken(t.Context(), keys.token(t, func(claims map[string]any) { claims[test.claim] = test.value }))
			if err == nil {
				t.Fatal("malformed signed authentication evidence was accepted")
			}
		})
	}
}

func TestAssuranceRequiresExplicitIssuerClientProfileAndFreshAuthentication(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	mappings := []AssuranceMapping{{Profile: "school/step-up", Issuer: "https://id.example.edu", ClientID: "android",
		ACR: "urn:school:step-up", RequiredAMR: []string{"pwd", "otp"}}}
	verifier, err := NewAssuranceVerifier(mappings)
	if err != nil {
		t.Fatal(err)
	}
	valid := Principal{Issuer: "https://id.example.edu", ClientID: "android", ACR: "urn:school:step-up", AMR: []string{"otp", "pwd", "hwk"},
		IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute), AuthenticatedAt: now.Add(-60 * time.Second)}
	if err := verifier.Verify(valid, "school/step-up", 60, now); err != nil {
		t.Fatalf("exact boundary and unordered AMR rejected: %v", err)
	}
	// Configuration is copied, so subsequent caller mutation cannot relax it.
	mappings[0].RequiredAMR[1] = "hwk"
	for _, test := range []struct {
		name   string
		mutate func(*Principal)
	}{
		{"issuer", func(p *Principal) { p.Issuer = "https://other.example.edu" }},
		{"client", func(p *Principal) { p.ClientID = "desktop" }},
		{"different acr", func(p *Principal) { p.ACR = "urn:school:step-up-highest" }},
		{"acr case", func(p *Principal) { p.ACR = "URN:school:step-up" }},
		{"missing auth time", func(p *Principal) { p.AuthenticatedAt = time.Time{} }},
		{"missing acr", func(p *Principal) { p.ACR = "" }},
		{"missing required amr", func(p *Principal) { p.AMR = []string{"pwd", "hwk"} }},
		{"amr case", func(p *Principal) { p.AMR = []string{"pwd", "OTP"} }},
		{"stale", func(p *Principal) { p.AuthenticatedAt = now.Add(-60*time.Second - time.Nanosecond) }},
		{"future auth", func(p *Principal) { p.AuthenticatedAt = now.Add(time.Nanosecond) }},
		{"auth after issuance", func(p *Principal) { p.AuthenticatedAt = now }},
		{"future issuance", func(p *Principal) { p.IssuedAt = now.Add(time.Nanosecond) }},
		{"expired token", func(p *Principal) { p.ExpiresAt = now }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			if !errors.Is(verifier.Verify(candidate, "school/step-up", 60, now), ErrAssurance) {
				t.Fatal("untrusted or stale authentication evidence accepted")
			}
		})
	}
	empty, _ := NewAssuranceVerifier(nil)
	for _, verifier := range []*AssuranceVerifier{nil, empty} {
		if verifier.Verify(valid, "school/step-up", 60, now) == nil {
			t.Fatal("unconfigured assurance accepted")
		}
	}
	for _, requirement := range []struct {
		profile string
		age     int64
	}{{"other", 60}, {"SCHOOL/step-up", 60}, {"school/step-up", -1}, {"school/step-up", 901}, {"school/step-up", 0}} {
		if verifier.Verify(valid, requirement.profile, requirement.age, now) == nil {
			t.Fatal("invalid or unsatisfied requirement accepted")
		}
	}
}

func TestAssuranceConfigurationRejectsAmbiguousOrMalformedMappings(t *testing.T) {
	valid := AssuranceMapping{Profile: "school/step-up", Issuer: "https://id.example.edu", ClientID: "android", ACR: "school:2", RequiredAMR: []string{"otp"}}
	for _, mutate := range []func(*AssuranceMapping){
		func(m *AssuranceMapping) { m.Profile = "Bad" },
		func(m *AssuranceMapping) { m.Issuer = "http://untrusted.example.edu" },
		func(m *AssuranceMapping) { m.ClientID = "" },
		func(m *AssuranceMapping) { m.ACR = "" },
		func(m *AssuranceMapping) { m.RequiredAMR = []string{"otp", "otp"} },
	} {
		candidate := valid
		mutate(&candidate)
		if _, err := NewAssuranceVerifier([]AssuranceMapping{candidate}); err == nil {
			t.Fatal("malformed assurance mapping accepted")
		}
	}
	if _, err := NewAssuranceVerifier([]AssuranceMapping{valid, valid}); err == nil {
		t.Fatal("duplicate issuer/client/profile rule accepted")
	}
	if _, err := NewAssuranceVerifier(make([]AssuranceMapping, 65)); err == nil {
		t.Fatal("unbounded mapping list accepted")
	}
}
