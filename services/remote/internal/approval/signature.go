package approval

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/canonical"
	jose "github.com/go-jose/go-jose/v4"
)

var ErrDecision = errors.New("approval: invalid signed decision")

type RegisteredKey struct {
	UserID         string
	DeviceID       string
	KeyVersion     int64
	ApprovalKeyJKT string
	PublicJWK      []byte
	Active         bool
}
type VerifiedDecision struct {
	Claims           Decision
	CanonicalPayload []byte
	PayloadSHA256    string
}

func KeyID(deviceID string, keyVersion int64) string {
	return "dsh-approval/" + deviceID + "/" + strconv.FormatInt(keyVersion, 10)
}

// VerifyDecision is pure verification: current grant/assurance checks and atomic
// one-use consumption must still precede any approved execution.
func VerifyDecision(compact string, registered RegisteredKey, expectedContext []byte, now time.Time) (VerifiedDecision, error) {
	now = now.UTC().Truncate(time.Millisecond)
	if !registered.Active || !uuid.MatchString(registered.UserID) || !uuid.MatchString(registered.DeviceID) || !version(registered.KeyVersion) || len(compact) == 0 || len(compact) > 16*1024 {
		return VerifiedDecision{}, ErrDecision
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return VerifiedDecision{}, ErrDecision
	}
	decoded := make([][]byte, 3)
	for index, part := range parts {
		var err error
		decoded[index], err = base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil || len(decoded[index]) == 0 || base64.RawURLEncoding.EncodeToString(decoded[index]) != part {
			return VerifiedDecision{}, ErrDecision
		}
	}
	if len(decoded[2]) != 64 {
		return VerifiedDecision{}, ErrDecision
	}
	headerBytes, err := canonical.Object(decoded[0])
	if err != nil || !bytes.Equal(headerBytes, decoded[0]) {
		return VerifiedDecision{}, ErrDecision
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Type      string `json:"typ"`
	}
	if decodeStrict(headerBytes, &header) != nil || header.Algorithm != "ES256" || header.Type != JWSType || header.KeyID != KeyID(registered.DeviceID, registered.KeyVersion) {
		return VerifiedDecision{}, ErrDecision
	}
	thumbprint, err := auth.PublicP256JWKThumbprintJSON(registered.PublicJWK)
	if err != nil || subtle.ConstantTimeCompare([]byte(thumbprint), []byte(registered.ApprovalKeyJKT)) != 1 {
		return VerifiedDecision{}, ErrDecision
	}
	var coordinates struct {
		X string `json:"x"`
		Y string `json:"y"`
	}
	if json.Unmarshal(registered.PublicJWK, &coordinates) != nil {
		return VerifiedDecision{}, ErrDecision
	}
	for _, value := range []string{coordinates.X, coordinates.Y} {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
		if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != value {
			return VerifiedDecision{}, ErrDecision
		}
	}
	var key jose.JSONWebKey
	if json.Unmarshal(registered.PublicJWK, &key) != nil {
		return VerifiedDecision{}, ErrDecision
	}
	signed, err := jose.ParseSignedCompact(compact, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(signed.Signatures) != 1 {
		return VerifiedDecision{}, ErrDecision
	}
	payload, err := signed.Verify(key.Key)
	if err != nil {
		return VerifiedDecision{}, ErrDecision
	}
	canonicalPayload, err := canonical.Object(payload)
	if err != nil || !bytes.Equal(payload, canonicalPayload) {
		return VerifiedDecision{}, ErrDecision
	}
	var decision Decision
	if decodeStrict(payload, &decision) != nil || !decision.valid() {
		return VerifiedDecision{}, ErrDecision
	}
	binding, err := ContextBinding(expectedContext)
	if err != nil || decision.Identity != binding.Context.Identity || decision.PolicyVersion != binding.Context.PolicyVersion || decision.Nonce != binding.Context.Nonce ||
		decision.UserID != registered.UserID || decision.DeviceID != registered.DeviceID || decision.KeyVersion != registered.KeyVersion ||
		subtle.ConstantTimeCompare([]byte(decision.BindingSHA256), []byte(binding.SHA256)) != 1 {
		return VerifiedDecision{}, ErrDecision
	}
	created, _ := utc(binding.Context.CreatedAt)
	deadline, _ := utc(binding.Context.ExpiresAt)
	issued, _ := utc(decision.IssuedAt)
	expires, _ := utc(decision.ExpiresAt)
	if created.After(now.Add(5*time.Second)) || !deadline.After(now) || issued.After(now.Add(5*time.Second)) || issued.Before(now.Add(-30*time.Second)) ||
		issued.Before(created.Add(-5*time.Second)) || !expires.After(now) || !expires.After(issued) || expires.After(deadline) {
		return VerifiedDecision{}, ErrDecision
	}
	digest := sha256.Sum256(canonicalPayload)
	return VerifiedDecision{Claims: decision, CanonicalPayload: canonicalPayload, PayloadSHA256: hex.EncodeToString(digest[:])}, nil
}
