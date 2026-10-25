package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"time"
)

const FileReadAudience = "urn:dsh-mobile-ustc:file-read"
const FileReadProofType = "dsh-file-read-proof+jwt"

var ErrFileReadProof = errors.New("auth: invalid file read proof")

type FileReadExpectation struct {
	InstallationID, KeyThumbprint         string
	RuntimeID, RuntimeEpoch, ConnectionID string
	HandoffID, FileID, Token              string
}

// A file ticket is sender-constrained to the registered installation key and
// exact GET route/current runtime generation. Database redemption is one-use.
func (auth *Authenticator) VerifyFileReadProof(request *http.Request, compact string, publicJWKBytes []byte, expected FileReadExpectation) error {
	if len(compact) == 0 || len(compact) > 8<<10 || request.Method != "GET" || request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.EscapedPath() != request.URL.Path ||
		request.URL.Path != "/v1/host-files/"+expected.HandoffID+"/content" || len(expected.Token) != 43 {
		return ErrFileReadProof
	}
	public, err := decodeObject(publicJWKBytes)
	if err != nil {
		return ErrFileReadProof
	}
	thumb, err := PublicP256JWKThumbprint(public)
	if err != nil || subtle.ConstantTimeCompare([]byte(thumb), []byte(expected.KeyThumbprint)) != 1 {
		return ErrFileReadProof
	}
	key, err := parsePublicJWK(public)
	if err != nil || !keyMatchesAlgorithm(key.key, "ES256") {
		return ErrFileReadProof
	}
	header, claims, input, signature, err := parseCompactJWS(compact)
	if err != nil || len(header) != 2 || stringClaim(header, "typ") != FileReadProofType || stringClaim(header, "alg") != "ES256" || verifySignature(key.key, "ES256", input, signature) != nil {
		return ErrFileReadProof
	}
	digest := sha256.Sum256([]byte(expected.Token))
	want := map[string]string{"iss": expected.InstallationID, "aud": FileReadAudience, "htm": "GET", "htu": auth.publicOrigin.String() + request.URL.Path,
		"runtime_id": expected.RuntimeID, "runtime_epoch": expected.RuntimeEpoch, "connection_id": expected.ConnectionID, "handoff_id": expected.HandoffID, "file_id": expected.FileID, "ath": base64.RawURLEncoding.EncodeToString(digest[:])}
	if len(claims) != len(want)+2 {
		return ErrFileReadProof
	}
	for name, value := range want {
		if value == "" || stringClaim(claims, name) != value {
			return ErrFileReadProof
		}
	}
	for name := range claims {
		if _, ok := want[name]; !ok && name != "iat" && name != "jti" {
			return ErrFileReadProof
		}
	}
	issued, ok := numericDate(claims["iat"])
	now := auth.clock()
	jti := stringClaim(claims, "jti")
	if !ok || issued.Before(now.Add(-30*time.Second)) || issued.After(now.Add(30*time.Second)) || len(jti) < 16 || len(jti) > 256 {
		return ErrFileReadProof
	}
	return nil
}
