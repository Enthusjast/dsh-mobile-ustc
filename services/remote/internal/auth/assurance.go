package auth

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrAssurance = errors.New("auth: required authentication assurance is unavailable")
var assuranceProfilePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9./_-]{0,127}$`)

// AssuranceMapping is deployment configuration, never request data. ACR values
// are opaque issuer-specific strings; no ordering or implicit MFA is inferred.
type AssuranceMapping struct {
	Profile     string   `json:"profile"`
	Issuer      string   `json:"issuer"`
	ClientID    string   `json:"client_id"`
	ACR         string   `json:"acr"`
	RequiredAMR []string `json:"required_amr"`
}

type AssuranceVerifier struct{ mappings []AssuranceMapping }

func NewAssuranceVerifier(mappings []AssuranceMapping) (*AssuranceVerifier, error) {
	if len(mappings) > 64 {
		return nil, ErrAssurance
	}
	verifier := &AssuranceVerifier{}
	seen := map[string]bool{}
	for _, mapping := range mappings {
		if !assuranceProfilePattern.MatchString(mapping.Profile) || !claimText(mapping.ClientID, 256) ||
			!claimText(mapping.ACR, 512) || !validAMR(mapping.RequiredAMR) {
			return nil, ErrAssurance
		}
		if _, err := parseBaseURL(mapping.Issuer, "assurance issuer"); err != nil {
			return nil, ErrAssurance
		}
		// One explicit rule per issuer/client/profile avoids ambiguous policy.
		key := mapping.Issuer + "\x00" + mapping.ClientID + "\x00" + mapping.Profile
		if seen[key] {
			return nil, ErrAssurance
		}
		seen[key] = true
		mapping.RequiredAMR = slices.Clone(mapping.RequiredAMR)
		verifier.mappings = append(verifier.mappings, mapping)
	}
	return verifier, nil
}

// Verify accepts a Principal supplied by JWT/DPoP middleware, not JSON from the
// client. Sensitive admission uses strict expiry and no future-auth clock grace.
func (verifier *AssuranceVerifier) Verify(principal Principal, profile string, maxAuthAgeSeconds int64, now time.Time) error {
	if verifier == nil || !assuranceProfilePattern.MatchString(profile) || maxAuthAgeSeconds < 0 || maxAuthAgeSeconds > 900 ||
		principal.AuthenticatedAt.IsZero() || principal.AuthenticatedAt.After(now) ||
		principal.IssuedAt.After(now) || !principal.ExpiresAt.After(now) ||
		principal.AuthenticatedAt.After(principal.IssuedAt) || now.Sub(principal.AuthenticatedAt) > time.Duration(maxAuthAgeSeconds)*time.Second ||
		!validAMR(principal.AMR) {
		return ErrAssurance
	}
	for _, mapping := range verifier.mappings {
		if mapping.Profile != profile || mapping.Issuer != principal.Issuer || mapping.ClientID != principal.ClientID || mapping.ACR != principal.ACR {
			continue
		}
		for _, method := range mapping.RequiredAMR {
			if !slices.Contains(principal.AMR, method) {
				return ErrAssurance
			}
		}
		return nil
	}
	return ErrAssurance
}

func authenticationClaims(claims map[string]any, issuedAt time.Time, skew time.Duration) (time.Time, string, []string, error) {
	var authenticatedAt time.Time
	var acr string
	var amr []string
	if value, present := claims["auth_time"]; present {
		parsed, ok := numericDate(value)
		if !ok || parsed.Before(time.Unix(0, 0)) || parsed.After(issuedAt.Add(skew)) {
			return time.Time{}, "", nil, errInvalidToken
		}
		authenticatedAt = parsed
	}
	if value, present := claims["acr"]; present {
		var ok bool
		acr, ok = value.(string)
		if !ok || !claimText(acr, 512) {
			return time.Time{}, "", nil, errInvalidToken
		}
	}
	if value, present := claims["amr"]; present {
		array, ok := value.([]any)
		if !ok || len(array) > 32 {
			return time.Time{}, "", nil, errInvalidToken
		}
		amr = make([]string, len(array))
		for index, method := range array {
			var ok bool
			amr[index], ok = method.(string)
			if !ok {
				return time.Time{}, "", nil, errInvalidToken
			}
		}
		if !validAMR(amr) {
			return time.Time{}, "", nil, errInvalidToken
		}
	}
	return authenticatedAt, acr, amr, nil
}

func validAMR(methods []string) bool {
	if len(methods) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, method := range methods {
		if !claimText(method, 128) || seen[method] {
			return false
		}
		seen[method] = true
	}
	return true
}

func claimText(value string, maxBytes int) bool {
	return value != "" && len(value) <= maxBytes && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}
