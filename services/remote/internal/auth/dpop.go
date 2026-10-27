package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const maxDPoPBytes = 16 << 10

var errInvalidProof = errors.New("auth: invalid DPoP proof")

type proofClaims struct {
	JKT     string
	JTI     string
	Nonce   string
	Expires time.Time
}

func (auth *Authenticator) verifyDPoP(request *http.Request, accessToken string, principal Principal, compact string) (proofClaims, error) {
	if len(compact) == 0 || len(compact) > maxDPoPBytes {
		return proofClaims{}, errInvalidProof
	}
	header, claims, signingInput, signature, err := parseCompactJWS(compact)
	if err != nil || !strings.EqualFold(stringClaim(header, "typ"), "dpop+jwt") || stringClaim(header, "alg") != "ES256" ||
		header["crit"] != nil || header["jku"] != nil || header["x5u"] != nil {
		return proofClaims{}, errInvalidProof
	}
	jwk, ok := header["jwk"].(map[string]any)
	if !ok {
		return proofClaims{}, errInvalidProof
	}
	key, err := parsePublicJWK(jwk)
	if err != nil || !keyMatchesAlgorithm(key.key, "ES256") || verifySignature(key.key, "ES256", signingInput, signature) != nil {
		return proofClaims{}, errInvalidProof
	}
	jkt, err := JWKThumbprint(jwk)
	if err != nil || subtle.ConstantTimeCompare([]byte(jkt), []byte(principal.ProofKeyJKT)) != 1 {
		return proofClaims{}, errInvalidProof
	}
	if stringClaim(claims, "htm") != request.Method {
		return proofClaims{}, errInvalidProof
	}
	proofURL := stringClaim(claims, "htu")
	wantURL := auth.requestURI(request)
	if !sameDPoPURI(proofURL, wantURL) {
		return proofClaims{}, errInvalidProof
	}
	accessHash := sha256.Sum256([]byte(accessToken))
	wantATH := base64.RawURLEncoding.EncodeToString(accessHash[:])
	if subtle.ConstantTimeCompare([]byte(stringClaim(claims, "ath")), []byte(wantATH)) != 1 {
		return proofClaims{}, errInvalidProof
	}
	jti := stringClaim(claims, "jti")
	if len(jti) < 16 || len(jti) > 256 {
		return proofClaims{}, errInvalidProof
	}
	issuedAt, ok := numericDate(claims["iat"])
	now := auth.clock()
	if !ok || issuedAt.Before(now.Add(-auth.clockSkew)) || issuedAt.After(now.Add(auth.clockSkew)) {
		return proofClaims{}, errInvalidProof
	}
	nonce := stringClaim(claims, "nonce")
	if len(nonce) > 256 {
		return proofClaims{}, errInvalidProof
	}
	return proofClaims{JKT: jkt, JTI: jti, Nonce: nonce, Expires: now.Add(5 * time.Minute)}, nil
}

func stringClaim(object map[string]any, name string) string {
	value, _ := object[name].(string)
	return value
}

// requestURI uses a configured public origin; forwarded headers are never trusted for proof binding.
func (auth *Authenticator) requestURI(request *http.Request) string {
	u := *auth.publicOrigin
	u.Path = request.URL.Path
	u.RawPath = request.URL.RawPath
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	return u.String()
}

func sameDPoPURI(candidate, expected string) bool {
	provided, err := url.Parse(candidate)
	if err != nil || provided.User != nil || provided.RawQuery != "" || provided.Fragment != "" {
		return false
	}
	canonical, err := url.Parse(expected)
	if err != nil {
		return false
	}
	return strings.EqualFold(provided.Scheme, canonical.Scheme) &&
		strings.EqualFold(provided.Host, canonical.Host) && provided.EscapedPath() == canonical.EscapedPath()
}

type ProofStore struct {
	scope   [32]byte
	mu      sync.Mutex
	nonces  map[string]time.Time
	used    map[string]time.Time
	clock   func() time.Time
	maxKeys int
}

func NewProofStore(scope [32]byte) *ProofStore {
	return &ProofStore{scope: scope, nonces: make(map[string]time.Time), used: make(map[string]time.Time), clock: time.Now, maxKeys: 100_000}
}

func (store *ProofStore) Scope() [32]byte { return store.scope }

func (store *ProofStore) Challenge(ctx context.Context, jkt string) (string, error) {
	if ctx.Err() != nil || !ValidProofThumbprint(jkt) {
		return "", ErrProofStateUnavailable
	}
	nonce, err := NewProofNonce()
	if err != nil {
		return "", err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if ctx.Err() != nil {
		return "", ErrProofStateUnavailable
	}
	store.prune()
	if len(store.nonces)+len(store.used) >= store.maxKeys {
		return "", ErrProofStateUnavailable
	}
	store.nonces[jkt+"\x00"+nonce] = store.clock().Add(5 * time.Minute)
	return nonce, nil
}

func (store *ProofStore) ConsumeAndRotate(ctx context.Context, jkt, jti, nonce string, expires time.Time) (ProofResult, error) {
	if ctx.Err() != nil || !ValidProofThumbprint(jkt) || len(jti) < 16 || len(jti) > 256 || len(nonce) > 256 {
		return ProofResult{}, ErrProofStateUnavailable
	}
	next, err := NewProofNonce()
	if err != nil {
		return ProofResult{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if ctx.Err() != nil {
		return ProofResult{}, ErrProofStateUnavailable
	}
	store.prune()
	nonceKey := jkt + "\x00" + nonce
	proofKey := jkt + "\x00" + jti
	now := store.clock()
	nonceExpiry, ok := store.nonces[nonceKey]
	_, replayed := store.used[proofKey]
	accepted := ok && now.Before(nonceExpiry) && expires.After(now) && !replayed
	if len(store.nonces)+len(store.used) >= store.maxKeys {
		return ProofResult{}, ErrProofStateUnavailable
	}
	if accepted {
		delete(store.nonces, nonceKey)
		store.used[proofKey] = expires
	}
	store.nonces[jkt+"\x00"+next] = now.Add(ProofStateLifetime)
	return ProofResult{Accepted: accepted, Nonce: next}, nil
}

func (store *ProofStore) prune() {
	now := store.clock()
	for key, expires := range store.nonces {
		if !expires.After(now) {
			delete(store.nonces, key)
		}
	}
	for key, expires := range store.used {
		if !expires.After(now) {
			delete(store.used, key)
		}
	}
}
