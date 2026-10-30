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

type InstallationRuntimeSummary struct {
	ID         string     `json:"runtime_id"`
	State      string     `json:"state"`
	LastSeenAt *time.Time `json:"last_seen_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

type InstallationRuntimeDirectory struct {
	InstallationID string                       `json:"installation_id"`
	Items          []InstallationRuntimeSummary `json:"items"`
	NextCursor     *string                      `json:"next_cursor"`
}

type installationRuntimeCursor struct {
	Version        int    `json:"v"`
	Purpose        string `json:"purpose"`
	UserID         string `json:"user_id"`
	ProofKeyJKT    string `json:"proof_key_jkt"`
	InstallationID string `json:"installation_id"`
	AfterRuntimeID string `json:"after_runtime_id"`
}

func parseInstallationRuntimeCursor(encoded string) (installationRuntimeCursor, error) {
	var cursor installationRuntimeCursor
	if len(encoded) > 1024 {
		return cursor, ErrInstallationManagementInvalid
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) == 0 || base64.RawURLEncoding.EncodeToString(raw) != encoded || auth.ValidateJSONObject(raw) != nil {
		return cursor, ErrInstallationManagementInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cursor) != nil || cursor.Version != 1 || cursor.Purpose != "installation-runtimes-v1" ||
		!grantUUIDPattern.MatchString(cursor.UserID) || !keyThumbprintPattern.MatchString(cursor.ProofKeyJKT) ||
		!grantUUIDPattern.MatchString(cursor.InstallationID) || !grantUUIDPattern.MatchString(cursor.AfterRuntimeID) {
		return cursor, ErrInstallationManagementInvalid
	}
	return cursor, nil
}

// This is installation management metadata. A runtime grant, even owner, does
// not authorize inspection or retirement of another user's installation identity.
func (postgres *Postgres) ListInstallationRuntimes(ctx context.Context, identity UserIdentity, deviceID, proofJKT, installationID string, limit int, encoded string) (InstallationRuntimeDirectory, error) {
	page := InstallationRuntimeDirectory{InstallationID: installationID, Items: []InstallationRuntimeSummary{}}
	if !grantUUIDPattern.MatchString(deviceID) || !grantUUIDPattern.MatchString(installationID) || !keyThumbprintPattern.MatchString(proofJKT) || limit < 1 || limit > 100 {
		return page, ErrInstallationManagementInvalid
	}
	var cursorUser, after any
	if encoded != "" {
		cursor, err := parseInstallationRuntimeCursor(encoded)
		if err != nil {
			return page, err
		}
		if cursor.ProofKeyJKT != proofJKT || cursor.InstallationID != installationID {
			return page, ErrAccessDenied
		}
		cursorUser, after = cursor.UserID, cursor.AfterRuntimeID
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var actor string
	var raw []byte
	err := postgres.DB.QueryRowContext(ctx, `with manager as materialized (
	 select u.id,i.revoked_at installation_revoked,h.state host_state from users u join devices d on d.user_id=u.id
	 join installations i on i.id=$5 join hosts h on h.id=i.host_id
	 join org_memberships m on m.org_id=h.org_id and m.user_id=u.id
	 where u.issuer=$1 and u.subject=$2 and u.status='active' and d.id=$3 and d.proof_key_thumbprint=$4 and d.revoked_at is null
	 and (i.owner_user_id=u.id or m.role='admin') and ($6::uuid is null or u.id=$6)
	)
	select a.id::text,coalesce((select jsonb_agg(row_to_json(p) order by p.runtime_id) from (
	 select r.id runtime_id,r.last_seen_at,r.revoked_at,
	 case when r.revoked_at is not null or a.installation_revoked is not null or a.host_state='revoked' then 'revoked'
	 when a.host_state='active' and `+runtimeEnrollmentApprovedSQL+` then 'active' else 'pending' end state
	 from runtimes r where r.installation_id=$5 and ($7::uuid is null or r.id>$7)
	 order by r.id limit $8) p),'[]'::jsonb) from manager a`, identity.Issuer, identity.Subject, deviceID, proofJKT, installationID, cursorUser, after, limit+1).Scan(&actor, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return page, ErrAccessDenied
	}
	if err != nil {
		return page, ErrDatabaseUnavailable
	}
	if json.Unmarshal(raw, &page.Items) != nil {
		return InstallationRuntimeDirectory{}, ErrDatabaseUnavailable
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		raw, _ := json.Marshal(installationRuntimeCursor{Version: 1, Purpose: "installation-runtimes-v1", UserID: actor, ProofKeyJKT: proofJKT, InstallationID: installationID, AfterRuntimeID: page.Items[len(page.Items)-1].ID})
		next := base64.RawURLEncoding.EncodeToString(raw)
		page.NextCursor = &next
	}
	return page, nil
}

func (postgres *Postgres) RevokeInstallationRuntime(ctx context.Context, identity UserIdentity, deviceID, proofJKT, installationID, runtimeID string) error {
	if !grantUUIDPattern.MatchString(deviceID) || !grantUUIDPattern.MatchString(installationID) || !grantUUIDPattern.MatchString(runtimeID) || !keyThumbprintPattern.MatchString(proofJKT) {
		return ErrInstallationManagementInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, err := retrySerializable(ctx, func() (bool, error) {
		return postgres.revokeInstallationOnce(ctx, identity, deviceID, proofJKT, installationID, runtimeID)
	})
	return err
}
