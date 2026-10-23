package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

const maxDeviceRegistrationProofBytes = 8 << 10
const deviceRegistrationProofType = "dsh-device-registration-proof+jwt"

// VerifyDeviceRegistrationProof checks approval-key possession and binds it to the
// user, both device keys, display name, and the DPoP proof for this HTTP request.
func (auth *Authenticator) VerifyDeviceRegistrationProof(compact string, approvalJWK []byte, principal Principal, deviceName, proofKeyJKT string) error {
	if len(compact) == 0 || len(compact) > maxDeviceRegistrationProofBytes || principal.ProofJTI == "" {
		return errInvalidDeviceRegistrationProof
	}
	publicJWK, err := decodeObject(approvalJWK)
	if err != nil {
		return errInvalidDeviceRegistrationProof
	}
	approvalKeyJKT, err := PublicP256JWKThumbprint(publicJWK)
	if err != nil {
		return errInvalidDeviceRegistrationProof
	}
	key, err := parsePublicJWK(publicJWK)
	if err != nil || !keyMatchesAlgorithm(key.key, "ES256") {
		return errInvalidDeviceRegistrationProof
	}
	header, claims, signingInput, signature, err := parseCompactJWS(compact)
	if err != nil || stringClaim(header, "typ") != deviceRegistrationProofType || stringClaim(header, "alg") != "ES256" {
		return errInvalidDeviceRegistrationProof
	}
	for name := range header {
		if name != "typ" && name != "alg" {
			return errInvalidDeviceRegistrationProof
		}
	}
	if verifySignature(key.key, "ES256", signingInput, signature) != nil {
		return errInvalidDeviceRegistrationProof
	}
	allowedClaims := map[string]struct{}{
		"iss": {}, "sub": {}, "aud": {}, "iat": {}, "jti": {},
		"approval_key_jkt": {}, "proof_key_jkt": {}, "device_name_sha256": {}, "dpop_jti": {},
	}
	for name := range claims {
		if _, ok := allowedClaims[name]; !ok {
			return errInvalidDeviceRegistrationProof
		}
	}
	issuedAt, ok := numericDate(claims["iat"])
	now := auth.clock()
	proofID := stringClaim(claims, "jti")
	nameHash := sha256.Sum256([]byte(deviceName))
	if stringClaim(claims, "iss") != principal.Issuer ||
		stringClaim(claims, "sub") != principal.Subject ||
		stringClaim(claims, "aud") != "urn:dsh-mobile-ustc:device-registration" ||
		!ok || issuedAt.Before(now.Add(-auth.clockSkew)) || issuedAt.After(now.Add(auth.clockSkew)) ||
		len(proofID) < 16 || len(proofID) > 256 ||
		stringClaim(claims, "approval_key_jkt") != approvalKeyJKT ||
		stringClaim(claims, "proof_key_jkt") != proofKeyJKT ||
		stringClaim(claims, "device_name_sha256") != base64.RawURLEncoding.EncodeToString(nameHash[:]) ||
		stringClaim(claims, "dpop_jti") != principal.ProofJTI {
		return errInvalidDeviceRegistrationProof
	}
	return nil
}

var errInvalidDeviceRegistrationProof = errors.New("auth: invalid device registration proof")
