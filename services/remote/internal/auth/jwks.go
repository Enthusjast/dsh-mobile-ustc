package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxJWKSBytes = 1 << 20
const unknownKIDRefreshCooldown = 5 * time.Second

type publicJWK struct {
	kid string
	alg string
	key crypto.PublicKey
}

type jwksDocument struct {
	Keys []map[string]any `json:"keys"`
}

type keySet struct {
	url    string
	client *http.Client
	clock  func() time.Time

	mu                  sync.Mutex
	keys                map[string]publicJWK
	expires             time.Time
	unknownRefreshAfter time.Time
}

func newKeySet(rawURL string, client *http.Client, clock func() time.Time) (*keySet, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("auth: invalid JWKS URL")
	}
	if u.Scheme != "https" && !isLoopbackHTTP(u) {
		return nil, errors.New("auth: JWKS URL must use HTTPS")
	}
	if client == nil {
		client = &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(request *http.Request, via []*http.Request) error {
				if len(via) >= 3 || request.URL.Scheme != u.Scheme || !strings.EqualFold(request.URL.Host, u.Host) {
					return errors.New("auth: unsafe JWKS redirect")
				}
				return nil
			},
		}
	}
	if clock == nil {
		clock = time.Now
	}
	return &keySet{url: u.String(), client: client, clock: clock, keys: make(map[string]publicJWK)}, nil
}

func isLoopbackHTTP(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	return u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
}

func (set *keySet) get(ctx context.Context, kid, alg string) (crypto.PublicKey, error) {
	set.mu.Lock()
	defer set.mu.Unlock()
	refreshed := false
	if !set.clock().Before(set.expires) {
		if err := set.refresh(ctx); err != nil {
			return nil, err
		}
		refreshed = true
	}
	key, ok := set.keys[kid]
	if !ok && !refreshed {
		now := set.clock()
		if now.Before(set.unknownRefreshAfter) {
			return nil, errors.New("auth: signing key not found")
		}
		set.unknownRefreshAfter = now.Add(unknownKIDRefreshCooldown)
		if err := set.refresh(ctx); err != nil {
			return nil, err
		}
		key, ok = set.keys[kid]
	}
	if !ok || key.alg != "" && key.alg != alg || !keyMatchesAlgorithm(key.key, alg) {
		return nil, errors.New("auth: signing key not found")
	}
	return key.key, nil
}

func (set *keySet) refresh(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, set.url, nil)
	if err != nil {
		return errors.New("auth: JWKS fetch failed")
	}
	request.Header.Set("Accept", "application/json")
	response, err := set.client.Do(request)
	if err != nil {
		return errors.New("auth: JWKS fetch failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("auth: JWKS fetch failed")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSBytes+1))
	if err != nil || len(body) > maxJWKSBytes {
		return errors.New("auth: invalid JWKS response")
	}
	var document jwksDocument
	if err := json.Unmarshal(body, &document); err != nil || len(document.Keys) == 0 {
		return errors.New("auth: invalid JWKS response")
	}
	keys := make(map[string]publicJWK, len(document.Keys))
	for _, raw := range document.Keys {
		parsed, err := parsePublicJWK(raw)
		if err != nil {
			return errors.New("auth: invalid JWKS key")
		}
		if parsed.kid == "" {
			continue
		}
		if _, duplicate := keys[parsed.kid]; duplicate {
			return errors.New("auth: ambiguous JWKS key ID")
		}
		keys[parsed.kid] = parsed
	}
	if len(keys) == 0 {
		return errors.New("auth: no usable signing keys")
	}
	set.keys = keys
	set.expires = set.clock().Add(cacheDuration(response.Header.Get("Cache-Control")))
	return nil
}

func cacheDuration(value string) time.Duration {
	for _, part := range strings.Split(value, ",") {
		name, raw, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || !strings.EqualFold(name, "max-age") {
			continue
		}
		seconds, err := strconv.Atoi(strings.Trim(raw, "\""))
		if err == nil {
			duration := time.Duration(seconds) * time.Second
			if duration < time.Minute {
				return time.Minute
			}
			if duration > time.Hour {
				return time.Hour
			}
			return duration
		}
	}
	return 5 * time.Minute
}

func parsePublicJWK(raw map[string]any) (publicJWK, error) {
	stringClaim := func(name string) string {
		value, _ := raw[name].(string)
		return value
	}
	kid, alg := stringClaim("kid"), stringClaim("alg")
	if raw["d"] != nil || raw["jku"] != nil || raw["x5u"] != nil {
		return publicJWK{}, errors.New("auth: private or remote JWK is not accepted")
	}
	if usage := stringClaim("use"); usage != "" && usage != "sig" {
		return publicJWK{}, errors.New("auth: non-signing JWK")
	}
	if operations, ok := raw["key_ops"].([]any); ok && !containsString(operations, "verify") {
		return publicJWK{}, errors.New("auth: JWK cannot verify signatures")
	}
	switch stringClaim("kty") {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(stringClaim("n"))
		if err != nil || len(nBytes) < 256 || len(nBytes) > 1024 {
			return publicJWK{}, errors.New("auth: invalid RSA modulus")
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(stringClaim("e"))
		if err != nil || len(eBytes) == 0 || len(eBytes) > 4 {
			return publicJWK{}, errors.New("auth: invalid RSA exponent")
		}
		exponent := int(new(big.Int).SetBytes(eBytes).Int64())
		if exponent < 3 || exponent%2 == 0 {
			return publicJWK{}, errors.New("auth: invalid RSA exponent")
		}
		return publicJWK{kid: kid, alg: alg, key: &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: exponent}}, nil
	case "EC":
		if stringClaim("crv") != "P-256" {
			return publicJWK{}, errors.New("auth: unsupported elliptic curve")
		}
		x, err := decodeCoordinate(stringClaim("x"))
		if err != nil {
			return publicJWK{}, err
		}
		y, err := decodeCoordinate(stringClaim("y"))
		if err != nil || !elliptic.P256().IsOnCurve(x, y) {
			return publicJWK{}, errors.New("auth: invalid elliptic curve point")
		}
		return publicJWK{kid: kid, alg: alg, key: &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}}, nil
	default:
		return publicJWK{}, fmt.Errorf("auth: unsupported JWK key type")
	}
}

func decodeCoordinate(value string) (*big.Int, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(bytes) != 32 {
		return nil, errors.New("auth: invalid elliptic curve coordinate")
	}
	return new(big.Int).SetBytes(bytes), nil
}

func containsString(values []any, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func keyMatchesAlgorithm(key crypto.PublicKey, algorithm string) bool {
	switch algorithm {
	case "RS256":
		_, ok := key.(*rsa.PublicKey)
		return ok
	case "ES256":
		public, ok := key.(*ecdsa.PublicKey)
		return ok && public.Curve == elliptic.P256()
	default:
		return false
	}
}

func verifySignature(key crypto.PublicKey, algorithm string, input, signature []byte) error {
	digest := sha256.Sum256(input)
	switch algorithm {
	case "RS256":
		public, ok := key.(*rsa.PublicKey)
		if !ok || rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature) != nil {
			return errors.New("auth: invalid JWT signature")
		}
		return nil
	case "ES256":
		public, ok := key.(*ecdsa.PublicKey)
		if !ok || len(signature) != 64 {
			return errors.New("auth: invalid JWT signature")
		}
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		if !ecdsa.Verify(public, digest[:], r, s) {
			return errors.New("auth: invalid JWT signature")
		}
		return nil
	default:
		return errors.New("auth: unsupported signature algorithm")
	}
}
