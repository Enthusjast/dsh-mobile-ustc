package auth

import (
	"net/http"
	"strings"
)

// InspectRequestForRouting verifies cryptographic possession without consuming
// the shared nonce/JTI. Its result may select a transport destination only. It
// MUST NOT authorize a handler: the destination runs Middleware and atomically
// consumes the original proof exactly once before any business operation.
func (auth *Authenticator) InspectRequestForRouting(request *http.Request) (Principal, error) {
	if len(request.Header.Values("Authorization")) != 1 || len(request.Header.Values("DPoP")) != 1 {
		return Principal{}, errInvalidProof
	}
	scheme, token, found := strings.Cut(request.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "DPoP") || token == "" || strings.TrimSpace(token) != token {
		return Principal{}, errInvalidProof
	}
	principal, err := auth.VerifyAccessToken(request.Context(), token)
	if err != nil {
		return Principal{}, err
	}
	if _, err := auth.verifyDPoP(request, token, principal, request.Header.Get("DPoP")); err != nil {
		return Principal{}, err
	}
	return principal, nil
}
