package store

import (
	"context"
	"database/sql"
	"errors"
)

var ErrDeviceRegistrationConflict = errors.New("store: device registration conflicts with existing keys")

type DeviceIdentity struct {
	DeviceID       string `json:"device_id"`
	KeyVersion     int64  `json:"key_version"`
	ApprovalKeyJKT string `json:"approval_key_jkt"`
	ProofKeyJKT    string `json:"proof_key_jkt"`
}

type CurrentDevice struct {
	State  string          `json:"state"`
	Device *DeviceIdentity `json:"device,omitempty"`
}

// CurrentDevice exposes only the device belonging to the verified account and
// current token-bound proof key. Revoked keys can reconcile but gain no access.
func (postgres *Postgres) CurrentDevice(ctx context.Context, identity UserIdentity, proofKeyJKT string) (CurrentDevice, error) {
	var userID string
	var id, approvalJKT, proofJKT sql.NullString
	var version sql.NullInt64
	var revoked sql.NullTime
	err := postgres.DB.QueryRowContext(ctx, `
		select u.id::text, d.id::text, d.key_version, d.approval_key_thumbprint, d.proof_key_thumbprint, d.revoked_at
		from users u
		left join devices d on d.user_id = u.id and d.proof_key_thumbprint = $3
		where u.issuer = $1 and u.subject = $2 and u.status = 'active'`, identity.Issuer, identity.Subject, proofKeyJKT).
		Scan(&userID, &id, &version, &approvalJKT, &proofJKT, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return CurrentDevice{}, ErrIdentityNotProvisioned
	}
	if err != nil {
		return CurrentDevice{}, ErrDatabaseUnavailable
	}
	if !id.Valid {
		return CurrentDevice{State: "unregistered"}, nil
	}
	state := "active"
	if revoked.Valid {
		state = "revoked"
	}
	return CurrentDevice{State: state, Device: &DeviceIdentity{DeviceID: id.String, KeyVersion: version.Int64, ApprovalKeyJKT: approvalJKT.String, ProofKeyJKT: proofJKT.String}}, nil
}
