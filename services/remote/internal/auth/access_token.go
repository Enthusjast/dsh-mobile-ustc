package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxAccessTokenBytes = 64 << 10

var errInvalidToken = errors.New("auth: invalid access token")

type Config struct {
	Issuer           string
	Audience         string
	JWKSURL          string
	AllowedClients   []string
	RequiredScopes   []string
	PublicOrigin     string
	ClockSkew        time.Duration
	MaxTokenLifetime time.Duration
	HTTPClient       *http.Client
	Clock            func() time.Time
	Proofs           ProofRepository
}

type Principal struct {
	Issuer      string
	Subject     string
	ClientID    string
	TokenID     string
	Scopes      map[string]struct{}
	ProofKeyJKT string
	ProofJTI    string
	ExpiresAt   time.Time
	IssuedAt    time.Time
	// These optional claims come only from a verified access token. Their presence
	// alone does not establish a local assurance profile.
	AuthenticatedAt time.Time
	ACR             string
	AMR             []string
}

type Authenticator struct {
	issuer         string
	audience       string
	allowedClients map[string]struct{}
	requiredScopes []string
	publicOrigin   *url.URL
	clockSkew      time.Duration
	maxLifetime    time.Duration
	clock          func() time.Time
	keys           *keySet
	proofs         ProofRepository
}

func New(config Config) (*Authenticator, error) {
	issuer, err := parseBaseURL(config.Issuer, "issuer")
	if err != nil {
		return nil, err
	}
	if config.Audience == "" || len(config.AllowedClients) == 0 || len(config.RequiredScopes) == 0 {
		return nil, errors.New("auth: audience, allowed clients, and required scopes are required")
	}
	publicOrigin, err := parseOrigin(config.PublicOrigin)
	if err != nil {
		return nil, err
	}
	if config.ClockSkew < 0 || config.ClockSkew > time.Minute {
		return nil, errors.New("auth: clock skew must be between zero and one minute")
	}
	if config.MaxTokenLifetime <= 0 || config.MaxTokenLifetime > time.Hour {
		return nil, errors.New("auth: maximum token lifetime must be between one nanosecond and one hour")
	}
	keys, err := newKeySet(config.JWKSURL, config.HTTPClient, config.Clock)
	if err != nil {
		return nil, err
	}
	clients := make(map[string]struct{}, len(config.AllowedClients))
	for _, id := range config.AllowedClients {
		if strings.TrimSpace(id) == "" {
			return nil, errors.New("auth: empty client ID is not allowed")
		}
		clients[id] = struct{}{}
	}
	scope, err := ProofScope(config.Issuer, config.Audience, config.PublicOrigin)
	if err != nil {
		return nil, err
	}
	if config.Proofs == nil {
		config.Proofs = NewProofStore(scope)
	}
	if config.Proofs.Scope() != scope {
		return nil, errors.New("auth: proof repository belongs to another resource")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	skew := config.ClockSkew
	if skew == 0 {
		skew = 30 * time.Second
	}
	return &Authenticator{
		issuer: issuer.String(), audience: config.Audience, allowedClients: clients,
		requiredScopes: append([]string(nil), config.RequiredScopes...), publicOrigin: publicOrigin,
		clockSkew: skew, maxLifetime: config.MaxTokenLifetime, clock: clock, keys: keys, proofs: config.Proofs,
	}, nil
}

func parseBaseURL(value, name string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !isLoopbackHTTP(u)) {
		return nil, errors.New("auth: " + name + " must be a trusted HTTPS URL")
	}
	return u, nil
}

func parseOrigin(value string) (*url.URL, error) {
	u, err := parseBaseURL(value, "public origin")
	if err != nil || u.Path != "" {
		return nil, errors.New("auth: public origin must be an HTTPS origin without a path")
	}
	return u, nil
}

func (auth *Authenticator) VerifyAccessToken(ctx context.Context, compact string) (Principal, error) {
	if len(compact) == 0 || len(compact) > maxAccessTokenBytes {
		return Principal{}, errInvalidToken
	}
	header, claims, signingInput, signature, err := parseCompactJWS(compact)
	if err != nil || !validAccessTokenType(header["typ"]) {
		return Principal{}, errInvalidToken
	}
	algorithm, ok := header["alg"].(string)
	if !ok || (algorithm != "RS256" && algorithm != "ES256") || header["kid"] == nil {
		return Principal{}, errInvalidToken
	}
	keyID, ok := header["kid"].(string)
	if !ok || keyID == "" || len(keyID) > 256 || header["jku"] != nil || header["x5u"] != nil || header["crit"] != nil || header["b64"] != nil {
		return Principal{}, errInvalidToken
	}
	key, err := auth.keys.get(ctx, keyID, algorithm)
	if err != nil || verifySignature(key, algorithm, signingInput, signature) != nil {
		return Principal{}, errInvalidToken
	}
	principal, err := auth.validateClaims(claims)
	if err != nil {
		return Principal{}, errInvalidToken
	}
	return principal, nil
}

func validAccessTokenType(value any) bool {
	typ, ok := value.(string)
	return ok && (strings.EqualFold(typ, "at+jwt") || strings.EqualFold(typ, "application/at+jwt"))
}

func (auth *Authenticator) validateClaims(claims map[string]any) (Principal, error) {
	issuer, _ := claims["iss"].(string)
	subject, _ := claims["sub"].(string)
	clientID, _ := claims["client_id"].(string)
	tokenID, _ := claims["jti"].(string)
	if issuer != auth.issuer || subject == "" || clientID == "" || tokenID == "" {
		return Principal{}, errInvalidToken
	}
	if _, ok := auth.allowedClients[clientID]; !ok || !audienceContains(claims["aud"], auth.audience) {
		return Principal{}, errInvalidToken
	}
	now := auth.clock()
	issuedAt, okIssuedAt := numericDate(claims["iat"])
	expiresAt, okExpiresAt := numericDate(claims["exp"])
	if !okIssuedAt || !okExpiresAt || issuedAt.After(now.Add(auth.clockSkew)) || !expiresAt.After(now.Add(-auth.clockSkew)) ||
		!expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > auth.maxLifetime {
		return Principal{}, errInvalidToken
	}
	if raw, present := claims["nbf"]; present {
		notBefore, ok := numericDate(raw)
		if !ok || notBefore.After(now.Add(auth.clockSkew)) {
			return Principal{}, errInvalidToken
		}
	}
	scopeText, _ := claims["scope"].(string)
	scopes := make(map[string]struct{})
	for _, scope := range strings.Fields(scopeText) {
		scopes[scope] = struct{}{}
	}
	for _, scope := range auth.requiredScopes {
		if _, ok := scopes[scope]; !ok {
			return Principal{}, errInvalidToken
		}
	}
	cnf, _ := claims["cnf"].(map[string]any)
	jkt, _ := cnf["jkt"].(string)
	if jkt == "" {
		return Principal{}, errInvalidToken
	}
	authenticatedAt, acr, amr, err := authenticationClaims(claims, issuedAt, auth.clockSkew)
	if err != nil {
		return Principal{}, errInvalidToken
	}
	return Principal{Issuer: issuer, Subject: subject, ClientID: clientID, TokenID: tokenID, Scopes: scopes,
		ProofKeyJKT: jkt, ExpiresAt: expiresAt, IssuedAt: issuedAt,
		AuthenticatedAt: authenticatedAt, ACR: acr, AMR: amr}, nil
}

func audienceContains(value any, expected string) bool {
	switch audience := value.(type) {
	case string:
		return audience == expected
	case []any:
		for _, item := range audience {
			if item == expected {
				return true
			}
		}
	}
	return false
}

func numericDate(value any) (time.Time, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return time.Time{}, false
	}
	seconds, err := number.Float64()
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || math.Abs(seconds) > 1e12 {
		return time.Time{}, false
	}
	whole, fraction := math.Modf(seconds)
	return time.Unix(int64(whole), int64(fraction*float64(time.Second))), true
}

func parseCompactJWS(compact string) (map[string]any, map[string]any, []byte, []byte, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, nil, nil, nil, errInvalidToken
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, nil, errInvalidToken
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, nil, errInvalidToken
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, nil, errInvalidToken
	}
	header, err := decodeObject(headerBytes)
	if err != nil {
		return nil, nil, nil, nil, errInvalidToken
	}
	claims, err := decodeObject(claimsBytes)
	if err != nil {
		return nil, nil, nil, nil, errInvalidToken
	}
	return header, claims, []byte(parts[0] + "." + parts[1]), signature, nil
}

// JWKThumbprint returns the RFC 7638 thumbprint for a P-256 public JWK.
func JWKThumbprint(raw map[string]any) (string, error) {
	if _, hasPrivateMaterial := raw["d"]; hasPrivateMaterial || raw["kty"] != "EC" || raw["crv"] != "P-256" {
		return "", errors.New("auth: DPoP requires a public P-256 JWK")
	}
	x, _ := raw["x"].(string)
	y, _ := raw["y"].(string)
	if _, err := decodeCoordinate(x); err != nil {
		return "", err
	}
	if _, err := decodeCoordinate(y); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(struct {
		Curve string `json:"crv"`
		Type  string `json:"kty"`
		X     string `json:"x"`
		Y     string `json:"y"`
	}{Curve: "P-256", Type: "EC", X: x, Y: y})
	if err != nil {
		return "", errors.New("auth: unable to serialize JWK thumbprint")
	}
	digest := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

// PublicP256JWKThumbprint validates the EC public-key form used for DPoP and approvals.
func PublicP256JWKThumbprint(raw map[string]any) (string, error) {
	for name := range raw {
		switch name {
		case "kty", "crv", "x", "y", "alg", "use", "key_ops", "kid", "ext":
		default:
			return "", errors.New("auth: unsupported public JWK member")
		}
	}
	if value, exists := raw["alg"]; exists {
		algorithm, ok := value.(string)
		if !ok || algorithm != "ES256" {
			return "", errors.New("auth: public JWK algorithm must be ES256")
		}
	}
	if value, exists := raw["use"]; exists {
		usage, ok := value.(string)
		if !ok || usage != "sig" {
			return "", errors.New("auth: public JWK use must be sig")
		}
	}
	if value, exists := raw["key_ops"]; exists {
		operations, ok := value.([]any)
		if !ok || len(operations) != 1 || operations[0] != "verify" {
			return "", errors.New("auth: public JWK key_ops must contain only verify")
		}
	}
	if value, exists := raw["kid"]; exists {
		keyID, ok := value.(string)
		if !ok || len(keyID) > 128 {
			return "", errors.New("auth: invalid public JWK key ID")
		}
	}
	if value, exists := raw["ext"]; exists {
		if _, ok := value.(bool); !ok {
			return "", errors.New("auth: invalid public JWK ext member")
		}
	}
	key, err := parsePublicJWK(raw)
	if err != nil || !keyMatchesAlgorithm(key.key, "ES256") {
		return "", errors.New("auth: public key must be P-256")
	}
	return JWKThumbprint(raw)
}

func PublicP256JWKThumbprintJSON(value []byte) (string, error) {
	if len(value) == 0 || len(value) > 8<<10 {
		return "", errors.New("auth: invalid public JWK size")
	}
	object, err := decodeObject(value)
	if err != nil {
		return "", err
	}
	return PublicP256JWKThumbprint(object)
}
