package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"time"
)

const ProofStateLifetime = 5 * time.Minute

var ErrProofStateUnavailable = errors.New("auth: proof state unavailable")

type ProofResult struct {
	Accepted bool
	Nonce    string
}

// A repository belongs to one trusted resource configuration. Rotation and
// consumption must commit together before a protected handler can run.
type ProofRepository interface {
	Scope() [32]byte
	Challenge(context.Context, string) (string, error)
	ConsumeAndRotate(context.Context, string, string, string, time.Time) (ProofResult, error)
}

func ProofScope(issuer, audience, publicOrigin string) ([32]byte, error) {
	var zero [32]byte
	iss, err := parseBaseURL(issuer, "issuer")
	if err != nil {
		return zero, err
	}
	origin, err := parseOrigin(publicOrigin)
	if err != nil || audience == "" {
		return zero, errors.New("auth: invalid proof resource scope")
	}
	origin.Scheme, origin.Host = strings.ToLower(origin.Scheme), strings.ToLower(origin.Host)
	hash := sha256.New()
	_, _ = hash.Write([]byte("dsh-mobile-ustc/dpop-state/v1\x00"))
	for _, part := range []string{iss.String(), audience, origin.String()} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(part))
	}
	copy(zero[:], hash.Sum(nil))
	return zero, nil
}

func NewProofNonce() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", ErrProofStateUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func ValidProofThumbprint(jkt string) bool {
	if len(jkt) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(jkt)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == jkt
}
