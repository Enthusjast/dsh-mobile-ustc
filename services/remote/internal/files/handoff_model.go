package files

import (
	"context"
	"encoding/json"
	"time"
)

const HandoffCapability = "file.handoff.v1"
const MessageCapability = "message.files.v1"
const ReconcileCapability = "message.files.reconcile.v1"

type HostBinding struct {
	InstallationID                        string
	KeyVersion                            int64
	RuntimeID, RuntimeEpoch, ConnectionID string
	CredentialExpiresAt                   time.Time
}

type Handoff struct {
	ID                    string
	File                  Record
	Host                  HostBinding
	PolicySHA256, State   string
	LeaseUntil, ExpiresAt time.Time
}

func (Handoff) String() string               { return "files.Handoff" }
func (Handoff) GoString() string             { return "files.Handoff" }
func (Handoff) MarshalJSON() ([]byte, error) { return []byte(`{}`), nil }

type FileOffer struct {
	SessionID     string    `json:"-"`
	HandoffID     string    `json:"handoff_id"`
	FileID        string    `json:"file_id"`
	Name          string    `json:"name"`
	SizeBytes     int64     `json:"size_bytes"`
	SHA256        string    `json:"sha256"`
	UserID        string    `json:"user_id"`
	DeviceID      string    `json:"device_id"`
	KeyVersion    int64     `json:"key_version"`
	GrantVersion  int64     `json:"grant_version"`
	DownloadToken string    `json:"download_token"`
	LeaseUntil    time.Time `json:"lease_until"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func (FileOffer) String() string   { return "files.FileOffer" }
func (FileOffer) GoString() string { return "files.FileOffer" }

type ReadPermit struct {
	Handoff       Handoff
	PublicJWK     json.RawMessage
	KeyThumbprint string
}

func (ReadPermit) String() string               { return "files.ReadPermit" }
func (ReadPermit) GoString() string             { return "files.ReadPermit" }
func (ReadPermit) MarshalJSON() ([]byte, error) { return []byte(`{}`), nil }

type HandoffRepository interface {
	FileMessageReference(context.Context, string) (*Delivery, error)
	PendingHandoffFiles(context.Context, HostBinding, string, int) ([]string, error)
	IssueHandoff(context.Context, HostBinding, string, string) (*FileOffer, error)
	RenewHandoff(context.Context, HostBinding, string, string) (Handoff, error)
	RedeemFileRead(context.Context, string, string, string, func(ReadPermit) error) (ReadPermit, error)
	CheckFileRead(context.Context, HostBinding, string, string) (Handoff, error)
	StageHandoff(context.Context, HostBinding, string, string, int64, string, string) error
	EndHandoff(context.Context, HostBinding, string) error
}
