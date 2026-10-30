package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
)

var ErrDeviceDirectoryInvalid = errors.New("store: invalid device directory request")

type DeviceSummary struct {
	ID         string     `json:"device_id"`
	Name       string     `json:"name"`
	KeyVersion int64      `json:"key_version"`
	State      string     `json:"state"`
	Current    bool       `json:"is_current"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt *time.Time `json:"last_seen_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}
type DeviceDirectory struct {
	Items      []DeviceSummary `json:"items"`
	NextCursor *string         `json:"next_cursor"`
}
type deviceDirectoryCursor struct {
	Version     int       `json:"v"`
	UserID      string    `json:"user_id"`
	ProofKeyJKT string    `json:"proof_key_jkt"`
	Before      time.Time `json:"before_created_at"`
	BeforeID    string    `json:"before_id"`
}

func parseDeviceDirectoryCursor(value string) (deviceDirectoryCursor, error) {
	var cursor deviceDirectoryCursor
	if len(value) > 1024 {
		return cursor, ErrDeviceDirectoryInvalid
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) == 0 || base64.RawURLEncoding.EncodeToString(raw) != value || auth.ValidateJSONObject(raw) != nil {
		return cursor, ErrDeviceDirectoryInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cursor) != nil || cursor.Version != 1 || !grantUUIDPattern.MatchString(cursor.UserID) || !grantUUIDPattern.MatchString(cursor.BeforeID) || !keyThumbprintPattern.MatchString(cursor.ProofKeyJKT) || cursor.Before.IsZero() {
		return cursor, ErrDeviceDirectoryInvalid
	}
	return cursor, nil
}

// ListDevices rechecks the current phone key and account in the same statement
// that reads its bounded page. Cursors locate metadata; they confer no authority.
func (postgres *Postgres) ListDevices(ctx context.Context, identity UserIdentity, currentDeviceID, proofJKT string, limit int, encodedCursor string) (DeviceDirectory, error) {
	page := DeviceDirectory{Items: []DeviceSummary{}}
	if !grantUUIDPattern.MatchString(currentDeviceID) || !keyThumbprintPattern.MatchString(proofJKT) || limit < 1 || limit > 100 {
		return page, ErrDeviceDirectoryInvalid
	}
	var userIDArg, beforeArg, beforeIDArg any
	if encodedCursor != "" {
		cursor, err := parseDeviceDirectoryCursor(encodedCursor)
		if err != nil {
			return page, err
		}
		if cursor.ProofKeyJKT != proofJKT {
			return page, ErrAccessDenied
		}
		userIDArg = cursor.UserID
		beforeArg = cursor.Before
		beforeIDArg = cursor.BeforeID
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var userID string
	var raw []byte
	err := postgres.DB.QueryRowContext(ctx, `
	 with actor as materialized (
	  select u.id,d.id current_device from users u join devices d on d.user_id=u.id
	  where u.issuer=$1 and u.subject=$2 and u.status='active' and d.id=$3
	   and d.proof_key_thumbprint=$7 and d.revoked_at is null
	 )
	 select a.id::text,coalesce((select jsonb_agg(row_to_json(p) order by p.created_at desc,p.device_id desc) from (
	  select d.id device_id,d.name,d.key_version,case when d.revoked_at is null then 'active' else 'revoked' end state,
	   d.id=a.current_device is_current,d.created_at,d.last_seen_at,d.revoked_at
	  from devices d where d.user_id=a.id and ($5::timestamptz is null or (d.created_at,d.id)<($5,$6::uuid))
	  order by d.created_at desc,d.id desc limit $8
	 ) p),'[]'::jsonb) from actor a where $4::uuid is null or a.id=$4`, identity.Issuer, identity.Subject, currentDeviceID, userIDArg, beforeArg, beforeIDArg, proofJKT, limit+1).Scan(&userID, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return page, ErrAccessDenied
	}
	if err != nil {
		return page, ErrDatabaseUnavailable
	}
	if json.Unmarshal(raw, &page.Items) != nil {
		return DeviceDirectory{}, ErrDatabaseUnavailable
	}
	for _, item := range page.Items {
		if !grantUUIDPattern.MatchString(item.ID) || item.KeyVersion < 1 || item.KeyVersion > 9007199254740991 || item.CreatedAt.IsZero() {
			return DeviceDirectory{}, ErrDatabaseUnavailable
		}
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		next, _ := json.Marshal(deviceDirectoryCursor{Version: 1, UserID: userID, ProofKeyJKT: proofJKT, Before: last.CreatedAt.UTC(), BeforeID: last.ID})
		value := base64.RawURLEncoding.EncodeToString(next)
		page.NextCursor = &value
	}
	return page, nil
}
