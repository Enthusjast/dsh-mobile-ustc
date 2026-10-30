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

var ErrGrantDirectoryInvalid = errors.New("store: invalid grant directory request")

type RuntimeGrantSummary struct {
	UserID    string     `json:"user_id"`
	Role      string     `json:"role"`
	Scope     GrantScope `json:"scope"`
	Version   int64      `json:"grant_version"`
	GrantedBy string     `json:"granted_by"`
	ExpiresAt *time.Time `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at"`
	State     string     `json:"state"`
}

type RuntimeGrantDirectory struct {
	RuntimeID  string                `json:"runtime_id"`
	Items      []RuntimeGrantSummary `json:"items"`
	NextCursor *string               `json:"next_cursor"`
}

type grantDirectoryCursor struct {
	Version     int    `json:"v"`
	Purpose     string `json:"purpose"`
	UserID      string `json:"user_id"`
	ProofKeyJKT string `json:"proof_key_jkt"`
	RuntimeID   string `json:"runtime_id"`
	AfterUserID string `json:"after_user_id"`
}

func parseGrantDirectoryCursor(encoded string) (grantDirectoryCursor, error) {
	var cursor grantDirectoryCursor
	if len(encoded) > 1024 {
		return cursor, ErrGrantDirectoryInvalid
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) == 0 || base64.RawURLEncoding.EncodeToString(raw) != encoded || auth.ValidateJSONObject(raw) != nil {
		return cursor, ErrGrantDirectoryInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cursor) != nil || cursor.Version != 1 || cursor.Purpose != "runtime-grants-v1" ||
		!grantUUIDPattern.MatchString(cursor.UserID) || !grantUUIDPattern.MatchString(cursor.RuntimeID) ||
		!grantUUIDPattern.MatchString(cursor.AfterUserID) || !keyThumbprintPattern.MatchString(cursor.ProofKeyJKT) {
		return cursor, ErrGrantDirectoryInvalid
	}
	return cursor, nil
}

// ListRuntimeGrants uses the same manager authority as grant mutation. Authorization
// and the bounded page share one statement snapshot; a cursor carries no authority.
func (postgres *Postgres) ListRuntimeGrants(ctx context.Context, identity UserIdentity, deviceID, proofJKT, runtimeID string, limit int, encoded string) (RuntimeGrantDirectory, error) {
	page := RuntimeGrantDirectory{RuntimeID: runtimeID, Items: []RuntimeGrantSummary{}}
	if !grantUUIDPattern.MatchString(deviceID) || !grantUUIDPattern.MatchString(runtimeID) || !keyThumbprintPattern.MatchString(proofJKT) || limit < 1 || limit > 100 {
		return page, ErrGrantDirectoryInvalid
	}
	var cursorUser, after any
	if encoded != "" {
		cursor, err := parseGrantDirectoryCursor(encoded)
		if err != nil {
			return page, err
		}
		if cursor.ProofKeyJKT != proofJKT || cursor.RuntimeID != runtimeID {
			return page, ErrAccessDenied
		}
		cursorUser, after = cursor.UserID, cursor.AfterUserID
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var actorID string
	var raw []byte
	err := postgres.DB.QueryRowContext(ctx, `with actor as materialized (
	 select u.id from users u join devices d on d.user_id=u.id
	 where u.issuer=$1 and u.subject=$2 and u.status='active'
	 and d.id=$3 and d.proof_key_thumbprint=$4 and d.revoked_at is null
	 and ($6::uuid is null or u.id=$6)
	), manager as materialized (
	 select a.id,h.org_id from actor a join runtimes r on r.id=$5 and r.revoked_at is null
	 join installations i on i.id=r.installation_id and i.revoked_at is null
	 join hosts h on h.id=i.host_id and h.state='active'
	 join org_memberships m on m.org_id=h.org_id and m.user_id=a.id
	 left join runtime_grants own on own.runtime_id=r.id and own.user_id=a.id
	 where `+runtimeEnrollmentApprovedSQL+` and (m.role='admin' or
	 (own.role='owner' and own.scope->'actions' ? 'grant.manage' and own.revoked_at is null
	 and (own.expires_at is null or own.expires_at>statement_timestamp())))
	)
	select a.id::text,coalesce((select jsonb_agg(row_to_json(p) order by p.user_id) from (
	 select g.user_id,g.role,g.scope,g.grant_version,g.granted_by,g.expires_at,g.revoked_at,
	 case when g.revoked_at is not null then 'revoked'
	 when g.expires_at<=statement_timestamp() then 'expired'
	 when u.status<>'active' or m.user_id is null then 'inactive' else 'active' end state
	 from runtime_grants g join users u on u.id=g.user_id
	 left join org_memberships m on m.user_id=u.id and m.org_id=a.org_id
	 where g.runtime_id=$5 and ($7::uuid is null or g.user_id>$7)
	 order by g.user_id limit $8) p),'[]'::jsonb) from manager a`,
		identity.Issuer, identity.Subject, deviceID, proofJKT, runtimeID, cursorUser, after, limit+1).Scan(&actorID, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return page, ErrAccessDenied
	}
	if err != nil {
		return page, ErrDatabaseUnavailable
	}
	if json.Unmarshal(raw, &page.Items) != nil {
		return RuntimeGrantDirectory{}, ErrDatabaseUnavailable
	}
	for _, item := range page.Items {
		if item.Version < 1 || item.Version > 9007199254740991 {
			return RuntimeGrantDirectory{}, ErrDatabaseUnavailable
		}
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		raw, _ := json.Marshal(grantDirectoryCursor{Version: 1, Purpose: "runtime-grants-v1", UserID: actorID, ProofKeyJKT: proofJKT, RuntimeID: runtimeID, AfterUserID: last.UserID})
		next := base64.RawURLEncoding.EncodeToString(raw)
		page.NextCursor = &next
	}
	return page, nil
}
