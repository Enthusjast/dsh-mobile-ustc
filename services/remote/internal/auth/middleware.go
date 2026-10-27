package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

type contextKey struct{}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(contextKey{}).(Principal)
	return principal, ok
}

func (auth *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if len(request.Header.Values("Authorization")) != 1 {
			auth.writeError(response, http.StatusUnauthorized, "auth.expired")
			return
		}
		authorization := request.Header.Get("Authorization")
		scheme, token, found := strings.Cut(authorization, " ")
		if !found || !strings.EqualFold(scheme, "DPoP") || strings.TrimSpace(token) != token || token == "" {
			auth.writeError(response, http.StatusUnauthorized, "auth.expired")
			return
		}
		principal, err := auth.VerifyAccessToken(request.Context(), token)
		if err != nil {
			auth.writeError(response, http.StatusUnauthorized, "auth.expired")
			return
		}
		proofHeaders := request.Header.Values("DPoP")
		if len(proofHeaders) != 1 {
			auth.writeError(response, http.StatusUnauthorized, "auth.proof_invalid")
			return
		}
		proof, err := auth.verifyDPoP(request, token, principal, proofHeaders[0])
		if err != nil {
			auth.writeError(response, http.StatusUnauthorized, "auth.proof_invalid")
			return
		}
		checked, storeErr := auth.proofs.ConsumeAndRotate(request.Context(), proof.JKT, proof.JTI, proof.Nonce, proof.Expires)
		if storeErr != nil || !ValidProofThumbprint(checked.Nonce) {
			auth.writeError(response, http.StatusServiceUnavailable, "internal")
			return
		}
		if !checked.Accepted {
			response.Header().Set("DPoP-Nonce", checked.Nonce)
			response.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			auth.writeError(response, http.StatusUnauthorized, "auth.proof_invalid")
			return
		}
		response.Header().Set("DPoP-Nonce", checked.Nonce)
		response.Header().Set("Cache-Control", "no-store")
		principal.ProofJTI = proof.JTI
		next.ServeHTTP(response, request.WithContext(context.WithValue(request.Context(), contextKey{}, principal)))
	})
}

func (auth *Authenticator) writeError(response http.ResponseWriter, status int, code string) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(map[string]any{"ok": false, "error": map[string]string{"code": code}})
}

func IsUnauthorized(err error) bool {
	return errors.Is(err, errInvalidToken) || errors.Is(err, errInvalidProof)
}
