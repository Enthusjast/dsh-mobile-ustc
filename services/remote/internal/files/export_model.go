package files

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"dsh-mobile-ustc/services/remote/internal/canonical"
)

const MaxExportBytes int64 = 2_000_000_000
const ExportCapability = "file.export.v1"

type ExportAccess struct {
	Actor                          Actor
	UserID                         string
	DeviceKeyVersion, GrantVersion int64
	AllowWorkspace                 bool
	LeaseUntil                     time.Time
}

func (ExportAccess) MarshalJSON() ([]byte, error) { return []byte(`{}`), nil }
func (ExportAccess) String() string               { return "files.ExportAccess" }
func (ExportAccess) GoString() string             { return "files.ExportAccess" }

type ExportSelector struct{ RequestID, RuntimeID, SessionID, RuntimeEpoch, SourceID string }

// Host-only manifest from an authorized runtime source. No path or native storage identity is accepted.
type ExportRegistration struct {
	RequestID       string    `json:"request_id"`
	RuntimeID       string    `json:"runtime_id"`
	SessionID       string    `json:"session_id"`
	SourceID        string    `json:"source_id"`
	Origin          string    `json:"origin"`
	Name            string    `json:"name"`
	SizeBytes       int64     `json:"size_bytes"`
	SHA256          string    `json:"sha256"`
	SourceExpiresAt time.Time `json:"source_expires_at"`
}

func NormalizeExport(input ExportRegistration, host HostBinding) (string, error) {
	if !objectUUID.MatchString(input.SourceID) || !objectUUID.MatchString(host.RuntimeEpoch) || input.RuntimeID != host.RuntimeID ||
		input.SizeBytes < 0 || input.SizeBytes > MaxExportBytes || input.SourceExpiresAt.IsZero() || input.Origin != "session_attachment" && input.Origin != "workspace_artifact" {
		return "", ErrInvalid
	}
	// Reuse exact name/UUID/digest validation without widening phone uploads.
	probe := UploadRegistration{RequestID: input.RequestID, RuntimeID: input.RuntimeID, SessionID: input.SessionID, Name: input.Name, SizeBytes: 0, SHA256: input.SHA256}
	if _, err := NormalizeRegistration(probe); err != nil {
		return "", err
	}
	body, err := json.Marshal(map[string]any{"type": "file.export", "runtime_id": input.RuntimeID, "session_id": input.SessionID,
		"payload": map[string]any{"source_id": input.SourceID, "origin": input.Origin, "runtime_epoch": host.RuntimeEpoch, "name": input.Name, "size_bytes": input.SizeBytes, "sha256": input.SHA256}})
	if err != nil {
		return "", ErrInvalid
	}
	normalized, err := canonical.Object(body)
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(normalized)
	return hex.EncodeToString(digest[:]), nil
}

type DownloadPermit struct {
	File                   Record
	AuthorizedGrantVersion int64
	LeaseUntil             time.Time
}

func (DownloadPermit) MarshalJSON() ([]byte, error) { return []byte(`{}`), nil }
func (DownloadPermit) String() string               { return "files.DownloadPermit" }
func (DownloadPermit) GoString() string             { return "files.DownloadPermit" }
