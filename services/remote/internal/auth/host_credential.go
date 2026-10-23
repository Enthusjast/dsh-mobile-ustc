package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"
)

const HostCredentialProofAudience = "urn:dsh-mobile-ustc:host-credential"
const hostCredentialProofType = "dsh-host-credential-proof+jwt"
const maxHostCredentialProofBytes = 8 << 10

var errInvalidHostCredentialProof = errors.New("auth: invalid host credential proof")

// VerifyHostCredentialProof validates a one-use installation signature. The
// caller must consume the corresponding challenge in the same transaction as
// issuing a connection credential.
func VerifyHostCredentialProof(compact string, installationPublicJWK []byte, installationID, challengeID, expectedKeyThumbprint string, challengeSHA256 []byte) error {
	if compact == "" || len(compact) > maxHostCredentialProofBytes || len(challengeSHA256) != sha256.Size {
		return errInvalidHostCredentialProof
	}
	publicJWK, err := decodeObject(installationPublicJWK)
	if err != nil {
		return errInvalidHostCredentialProof
	}
	thumbprint, err := PublicP256JWKThumbprint(publicJWK)
	if err != nil || thumbprint != expectedKeyThumbprint {
		return errInvalidHostCredentialProof
	}
	key, err := parsePublicJWK(publicJWK)
	if err != nil || !keyMatchesAlgorithm(key.key, "ES256") {
		return errInvalidHostCredentialProof
	}
	header, claims, signingInput, signature, err := parseCompactJWS(compact)
	if err != nil || stringClaim(header, "typ") != hostCredentialProofType || stringClaim(header, "alg") != "ES256" {
		return errInvalidHostCredentialProof
	}
	for name := range header {
		if name != "typ" && name != "alg" {
			return errInvalidHostCredentialProof
		}
	}
	if verifySignature(key.key, "ES256", signingInput, signature) != nil {
		return errInvalidHostCredentialProof
	}
	allowedClaims := map[string]struct{}{
		"iss": {}, "aud": {}, "challenge_id": {}, "nonce": {}, "iat": {}, "jti": {},
	}
	for name := range claims {
		if _, ok := allowedClaims[name]; !ok {
			return errInvalidHostCredentialProof
		}
	}
	issuedAt, ok := numericDate(claims["iat"])
	proofID := stringClaim(claims, "jti")
	nonce := stringClaim(claims, "nonce")
	nonceBytes, decodeErr := base64.RawURLEncoding.Strict().DecodeString(nonce)
	now := time.Now().UTC()
	if stringClaim(claims, "iss") != installationID ||
		stringClaim(claims, "aud") != HostCredentialProofAudience ||
		stringClaim(claims, "challenge_id") != challengeID ||
		!ok || issuedAt.Before(now.Add(-2*time.Minute)) || issuedAt.After(now.Add(30*time.Second)) ||
		len(proofID) < 16 || len(proofID) > 256 || decodeErr != nil || len(nonceBytes) != 32 ||
		base64.RawURLEncoding.EncodeToString(nonceBytes) != nonce {
		return errInvalidHostCredentialProof
	}
	proofNonceHash := sha256.Sum256([]byte(nonce))
	for index := range nonceBytes {
		nonceBytes[index] = 0
	}
	if subtle.ConstantTimeCompare(proofNonceHash[:], challengeSHA256) != 1 {
		return errInvalidHostCredentialProof
	}
	return nil
}
