package files

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"dsh-mobile-ustc/services/remote/internal/canonical"
)

var ErrAccess = errors.New("files: access denied")
var ErrConflict = errors.New("files: request conflicts")
var ErrQuota = errors.New("files: quota exceeded")
var ErrUnavailable = errors.New("files: metadata unavailable")
var ErrStale = errors.New("files: stale scan lease")

type Actor struct{ Issuer, Subject, DeviceID, ProofKeyJKT string }

func (Actor) String() string   { return "files.Actor" }
func (Actor) GoString() string { return "files.Actor" }

type UploadRegistration struct {
	RequestID string `json:"request_id"`
	RuntimeID string `json:"runtime_id"`
	SessionID string `json:"session_id"`
	Name      string `json:"name"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

func NormalizeRegistration(input UploadRegistration) (string, error) {
	if !objectUUID.MatchString(input.RequestID) || !objectUUID.MatchString(input.RuntimeID) || !objectUUID.MatchString(input.SessionID) ||
		input.SizeBytes < 0 || input.SizeBytes > MaxUploadBytes || len(input.Name) == 0 || len(input.Name) > 512 || !utf8.ValidString(input.Name) ||
		strings.TrimSpace(input.Name) == "" || input.Name == "." || input.Name == ".." || strings.ContainsAny(input.Name, "/\\") || strings.ContainsFunc(input.Name, unicode.IsControl) {
		return "", ErrInvalid
	}
	if _, ok := checksum(input.SHA256); !ok {
		return "", ErrInvalid
	}
	encoded, err := json.Marshal(map[string]any{"type": "file.register", "runtime_id": input.RuntimeID, "session_id": input.SessionID,
		"payload": map[string]any{"name": input.Name, "size_bytes": input.SizeBytes, "sha256": input.SHA256}})
	if err != nil {
		return "", ErrInvalid
	}
	body, err := canonical.Object(encoded)
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

type Limits struct {
	OrganizationBytes, UserBytes, SessionBytes int64
	OrganizationFiles, UserFiles, SessionFiles int64
	UploadURLTTL, AbandonAfter, RetainFor      time.Duration
}

func (limits Limits) Validate() error {
	if limits.SessionBytes <= 0 || limits.UserBytes < limits.SessionBytes || limits.OrganizationBytes < limits.UserBytes || limits.OrganizationBytes > 1<<50 ||
		limits.SessionFiles <= 0 || limits.UserFiles < limits.SessionFiles || limits.OrganizationFiles < limits.UserFiles || limits.OrganizationFiles > 1_000_000 ||
		limits.UploadURLTTL < time.Minute || limits.UploadURLTTL > 15*time.Minute || limits.UploadURLTTL%time.Second != 0 ||
		limits.AbandonAfter < limits.UploadURLTTL || limits.AbandonAfter > 48*time.Hour || limits.RetainFor < limits.AbandonAfter || limits.RetainFor > 90*24*time.Hour {
		return ErrInvalid
	}
	return nil
}

// Record carries private scheduling/authorization data. JSON always uses the
// explicit public status, never object keys, leases or signed capabilities.
type Record struct {
	ID, OrganizationID, RuntimeID, SessionID           string
	UploaderID, DeviceID, ProofKeyJKT                  string
	KeyVersion, GrantVersion                           int64
	RequestID, RequestSHA256                           string
	Name, SHA256, State, ErrorCode                     string
	Direction                                          string
	SizeBytes                                          int64
	QuarantineAttempt                                  string
	CommittedAttempt                                   string
	CreatedAt, UploadExpiresAt, ExpiresAt, RetainUntil time.Time
}

type Status struct {
	Delivery        *Delivery `json:"delivery,omitempty"`
	ID              string    `json:"file_id"`
	RuntimeID       string    `json:"runtime_id"`
	SessionID       string    `json:"session_id"`
	Direction       string    `json:"direction"`
	Name            string    `json:"name"`
	SizeBytes       int64     `json:"size_bytes"`
	SHA256          string    `json:"sha256"`
	State           string    `json:"state"`
	ErrorCode       string    `json:"error_code,omitempty"`
	UploadExpiresAt time.Time `json:"upload_expires_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	CreatedAt       time.Time `json:"created_at"`
}

// Advisory presentation state. Every message still requires atomic admission.
type Delivery struct {
	State        string     `json:"state"`
	RequestID    string     `json:"request_id,omitempty"`
	CommandState string     `json:"command_state,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

func (record Record) Status() Status {
	direction := record.Direction
	if direction == "" {
		direction = "to_host"
	}
	return Status{ID: record.ID, RuntimeID: record.RuntimeID, SessionID: record.SessionID, Direction: direction, Name: record.Name,
		SizeBytes: record.SizeBytes, SHA256: record.SHA256, State: record.State, ErrorCode: record.ErrorCode, UploadExpiresAt: record.UploadExpiresAt, ExpiresAt: record.ExpiresAt, CreatedAt: record.CreatedAt}
}
func (record Record) MarshalJSON() ([]byte, error) { return json.Marshal(record.Status()) }
func (record Record) String() string               { return "files.Record(" + record.ID + ", " + record.State + ")" }
func (record Record) GoString() string             { return record.String() }
func (record Record) SourceKey() (ObjectKey, error) {
	return NewObjectKey(record.OrganizationID, record.SessionID, record.ID, record.QuarantineAttempt, Quarantine)
}
func (record Record) CommittedKey() (ObjectKey, error) {
	return NewObjectKey(record.OrganizationID, record.SessionID, record.ID, record.CommittedAttempt, Committed)
}

type ScanClaim struct {
	File         Record    `json:"-"`
	AttemptID    string    `json:"-"`
	LeaseID      string    `json:"-"`
	PolicySHA256 string    `json:"-"`
	LeaseUntil   time.Time `json:"-"`
}

func (ScanClaim) String() string   { return "files.ScanClaim" }
func (ScanClaim) GoString() string { return "files.ScanClaim" }
func (claim ScanClaim) Key() (ObjectKey, error) {
	return NewObjectKey(claim.File.OrganizationID, claim.File.SessionID, claim.File.ID, claim.AttemptID, Committed)
}

type DeletionClaim struct {
	FileID, OrganizationID, SessionID string
	Kind                              ObjectKind
	AttemptID, LeaseID                string
	LeaseUntil                        time.Time
}

func (DeletionClaim) String() string               { return "files.DeletionClaim" }
func (DeletionClaim) GoString() string             { return "files.DeletionClaim" }
func (DeletionClaim) MarshalJSON() ([]byte, error) { return []byte(`{}`), nil }
func (claim DeletionClaim) Key() (ObjectKey, error) {
	return NewObjectKey(claim.OrganizationID, claim.SessionID, claim.FileID, claim.AttemptID, claim.Kind)
}
