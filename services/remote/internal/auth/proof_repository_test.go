package auth

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

type failingProofRepository struct {
	scope [32]byte
	calls atomic.Int64
}

func (repository *failingProofRepository) Scope() [32]byte { return repository.scope }
func (*failingProofRepository) Challenge(context.Context, string) (string, error) {
	return "", ErrProofStateUnavailable
}
func (repository *failingProofRepository) ConsumeAndRotate(context.Context, string, string, string, time.Time) (ProofResult, error) {
	repository.calls.Add(1)
	return ProofResult{}, ErrProofStateUnavailable
}

func TestProofRepositoryFailureCannotChallengeOrReachProtectedHandler(t *testing.T) {
	keys := newTestKeys(t)
	repository := &failingProofRepository{scope: keys.verifier.proofs.Scope()}
	keys.verifier.proofs = repository
	var reached atomic.Int64
	handler := keys.verifier.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) }))
	token := keys.token(t, nil)
	proof := keys.proofToken(t, token, "GET", "https://api.example.edu/v1/hosts", "proof-storage-outage-0001", "", nil)
	response := sendRequest(t, handler, "/v1/hosts", "GET", token, proof)
	if response.Code != 503 || response.Header().Get("DPoP-Nonce") != "" || reached.Load() != 0 || repository.calls.Load() != 1 {
		t.Fatal("storage failure degraded into a challenge or authority")
	}
	invalid := keys.proofToken(t, token, "POST", "https://api.example.edu/v1/hosts", "proof-invalid-before-storage", "", nil)
	response = sendRequest(t, handler, "/v1/hosts", "GET", token, invalid)
	if response.Code != 401 || repository.calls.Load() != 1 {
		t.Fatal("invalid proof reached shared state")
	}
}

func TestProofRepositoryCannotBindAnotherResourceAndQuotaFailureIsAtomic(t *testing.T) {
	keys := newTestKeys(t)
	scope := keys.verifier.proofs.Scope()
	wrong := &failingProofRepository{}
	if _, err := New(Config{Issuer: keys.issuer, Audience: "urn:dsh-remote", JWKSURL: keys.server.URL, AllowedClients: []string{"android-public-client"}, RequiredScopes: []string{"remote.access"}, PublicOrigin: "https://api.example.edu", MaxTokenLifetime: 15 * time.Minute, Proofs: wrong}); err == nil {
		t.Fatal("foreign resource repository accepted")
	}
	store := NewProofStore(scope)
	store.maxKeys = 1
	nonce, err := store.Challenge(context.Background(), keys.proofJKT)
	if err != nil {
		t.Fatal(err)
	}
	const jti = "proof-quota-no-partial-consumption"
	if result, err := store.ConsumeAndRotate(context.Background(), keys.proofJKT, jti, nonce, time.Now().Add(time.Minute)); err == nil || result.Accepted {
		t.Fatal("full memory gate partially consumed proof")
	}
	store.maxKeys = 2
	if result, err := store.ConsumeAndRotate(context.Background(), keys.proofJKT, jti, nonce, time.Now().Add(time.Minute)); err != nil || !result.Accepted {
		t.Fatal("quota failure spent the original proof", err)
	}
}
