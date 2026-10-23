package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"
)

const RelayHandshakeAudience = "urn:dsh-mobile-ustc:realtime"
const relayHandshakeProofType = "dsh-relay-handshake-proof+jwt"
const maxRelayHandshakeProofBytes = 8 << 10

var errInvalidRelayHandshakeProof = errors.New("auth: invalid Relay handshake proof")

type RelayHandshakeExpectation struct {
	KeyThumbprint string
	Issuer        string
	ChallengeID   string
	ConnectionID  string
	Nonce         string
	RuntimeID     string
	RuntimeEpoch  string
	HelloSHA256   string
}

// VerifyRelayHandshakeProof checks a signature against the key registered for
// the device or installation and binds it to this socket's fresh challenge.
func VerifyRelayHandshakeProof(compact string, publicJWKBytes []byte, expected RelayHandshakeExpectation) error {
	if compact == "" || len(compact) > maxRelayHandshakeProofBytes ||
		expected.KeyThumbprint == "" || expected.Issuer == "" || expected.ChallengeID == "" ||
		expected.ConnectionID == "" || expected.Nonce == "" || expected.RuntimeID == "" {
		return errInvalidRelayHandshakeProof
	}
	publicJWK, err := decodeObject(publicJWKBytes)
	if err != nil {
		return errInvalidRelayHandshakeProof
	}
	thumbprint, err := PublicP256JWKThumbprint(publicJWK)
	if err != nil || subtle.ConstantTimeCompare([]byte(thumbprint), []byte(expected.KeyThumbprint)) != 1 {
		return errInvalidRelayHandshakeProof
	}
	key, err := parsePublicJWK(publicJWK)
	if err != nil || !keyMatchesAlgorithm(key.key, "ES256") {
		return errInvalidRelayHandshakeProof
	}
	header, claims, signingInput, signature, err := parseCompactJWS(compact)
	if err != nil || stringClaim(header, "typ") != relayHandshakeProofType || stringClaim(header, "alg") != "ES256" {
		return errInvalidRelayHandshakeProof
	}
	for name := range header {
		if name != "typ" && name != "alg" {
			return errInvalidRelayHandshakeProof
		}
	}
	if verifySignature(key.key, "ES256", signingInput, signature) != nil {
		return errInvalidRelayHandshakeProof
	}
	want := map[string]string{
		"iss": expected.Issuer, "aud": RelayHandshakeAudience,
		"challenge_id": expected.ChallengeID, "connection_id": expected.ConnectionID,
		"nonce": expected.Nonce, "runtime_id": expected.RuntimeID,
	}
	if expected.RuntimeEpoch != "" {
		want["runtime_epoch"] = expected.RuntimeEpoch
	}
	if expected.HelloSHA256 != "" {
		want["hello_sha256"] = expected.HelloSHA256
	}
	if len(claims) != len(want)+2 {
		return errInvalidRelayHandshakeProof
	}
	for name, value := range want {
		if stringClaim(claims, name) != value {
			return errInvalidRelayHandshakeProof
		}
	}
	for name := range claims {
		if _, ok := want[name]; !ok && name != "iat" && name != "jti" {
			return errInvalidRelayHandshakeProof
		}
	}
	issuedAt, ok := numericDate(claims["iat"])
	proofID := stringClaim(claims, "jti")
	now := time.Now().UTC()
	if !ok || issuedAt.Before(now.Add(-30*time.Second)) || issuedAt.After(now.Add(30*time.Second)) ||
		len(proofID) < 16 || len(proofID) > 256 {
		return errInvalidRelayHandshakeProof
	}
	return nil
}

// RelayHelloDigest binds normalized hello fields using an unambiguous,
// language-neutral length-prefixed encoding.
func RelayHelloDigest(parts ...string) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("dsh-mobile-ustc/relay-hello/v1\x00"))
	var size [4]byte
	for _, part := range parts {
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		_, _ = hasher.Write(size[:])
		_, _ = hasher.Write([]byte(part))
	}
	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
}
