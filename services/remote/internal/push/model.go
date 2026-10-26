// Package push owns minimal provider messages, not interaction bodies or execution authority.
package push

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"time"
)

var (
	ErrInvalid     = errors.New("push: invalid input")
	ErrAccess      = errors.New("push: access denied")
	ErrConflict    = errors.New("push: registration conflict")
	ErrExpired     = errors.New("push: expired")
	ErrUnavailable = errors.New("push: unavailable")
	ErrLease       = errors.New("push: retired delivery lease")
	ErrCipher      = errors.New("push: encrypted value unavailable")
)

var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var fid = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

func UUID(value string) bool   { return uuid.MatchString(value) }
func Digest(value string) bool { return digest.MatchString(value) }
func FID(value string) bool    { return fid.MatchString(value) }
func Secret(value string) bool {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == value
}
func SecretHash(value string) string {
	raw := sha256.Sum256([]byte(value))
	return hex.EncodeToString(raw[:])
}

type Actor struct{ Issuer, Subject, DeviceID, ProofKeyJKT string }
type Registration struct {
	BindingID      string `json:"binding_id"`
	OrganizationID string `json:"organization_id"`
	Provider       string `json:"provider"`
	Address        string `json:"address"`
	RevokeSHA256   string `json:"revoke_secret_sha256"`
}

func (Registration) String() string   { return "PushRegistration" }
func (Registration) GoString() string { return "PushRegistration" }
func (input Registration) Valid() bool {
	return UUID(input.BindingID) && UUID(input.OrganizationID) && input.Provider == "fcm" && FID(input.Address) && Digest(input.RevokeSHA256)
}

type Binding struct {
	ID                 string    `json:"binding_id"`
	State              string    `json:"state"`
	ChallengeExpiresAt time.Time `json:"challenge_expires_at"`
	ExpiresAt          time.Time `json:"expires_at"`
}
type Reference struct {
	NotificationID string    `json:"notification_id"`
	BindingID      string    `json:"binding_id"`
	Kind           string    `json:"kind"`
	ReferenceID    string    `json:"reference_id"`
	RuntimeID      string    `json:"runtime_id"`
	RuntimeEpoch   string    `json:"runtime_epoch"`
	SessionID      string    `json:"session_id"`
	State          string    `json:"state"`
	Availability   string    `json:"availability"`
	ExpiresAt      time.Time `json:"expires_at"`
}
type Claim struct {
	ID, LeaseID, BindingID, Kind string
	ExpiresAt                    time.Time
}

func (Claim) String() string { return "PushClaim" }

// Outbound's address and registration nonce must not reach logs or generic JSON encoding.
type Outbound struct {
	Provider, Address                    string
	BindingID, NotificationID, Challenge string
	Kind                                 string
	ExpiresAt                            time.Time
}

func (Outbound) String() string               { return "PushOutbound" }
func (Outbound) GoString() string             { return "PushOutbound" }
func (Outbound) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

type Result struct {
	State, Code, ProviderID string
	RetryAfter              time.Duration
}

const (
	Accepted        = "provider_accepted"
	Retry           = "retry"
	InvalidEndpoint = "invalid_endpoint"
	Failed          = "failed"
	Expired         = "expired"
)

type Sender interface {
	Send(context.Context, Outbound, func(context.Context) error) Result
}
type Repository interface {
	Plan(context.Context) error
	Claim(context.Context) (*Claim, error)
	Authorize(context.Context, Claim) (Outbound, error)
	Recheck(context.Context, Claim) error
	Complete(context.Context, Claim, Result) error
}

// At-least-once transport uses a stable notification UUID; provider acceptance is not phone display.
func Run(ctx context.Context, repository Repository, sender Sender) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for ctx.Err() == nil {
		iteration, cancel := context.WithTimeout(ctx, 15*time.Second)
		if repository.Plan(iteration) == nil {
			for index := 0; index < 16 && iteration.Err() == nil; index++ {
				claim, err := repository.Claim(iteration)
				if err != nil || claim == nil {
					break
				}
				outbound, err := repository.Authorize(iteration, *claim)
				result := Result{State: Expired, Code: "authority_changed"}
				if err == nil {
					result = sender.Send(iteration, outbound, func(check context.Context) error { return repository.Recheck(check, *claim) })
				} else if errors.Is(err, ErrUnavailable) {
					result = Result{State: Retry, Code: "metadata_unavailable", RetryAfter: 5 * time.Second}
				}
				if repository.Complete(iteration, *claim, result) != nil {
					break
				}
			}
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
