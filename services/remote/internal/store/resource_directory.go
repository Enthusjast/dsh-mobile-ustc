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

var ErrResourceDirectoryInvalid = errors.New("store: invalid resource directory request")

// Shared eligibility for legacy and paged host/runtime discovery. Read-only
// session authority alone never grants directory enumeration.
const runtimeDirectoryEligibilitySQL = `g.revoked_at is null and (g.expires_at is null or g.expires_at > now())
 and (g.scope->'actions' ? 'host.list' or (g.scope->'actions' ? 'session.list' and exists (
 select 1 from sessions s where s.runtime_id=r.id and (
 coalesce(g.scope->'sessions','[]'::jsonb) @> jsonb_build_array(s.id::text) or
 (s.workspace_id is not null and coalesce(g.scope->'workspaces','[]'::jsonb) @> jsonb_build_array(s.workspace_id::text))))))`

const resourceDirectoryActorSQL = `with actor as materialized (
 select u.id from users u join devices d on d.user_id=u.id
 where u.issuer=$1 and u.subject=$2 and u.status='active' and d.id=$3
 and d.proof_key_thumbprint=$4 and d.revoked_at is null and ($5::uuid is null or u.id=$5)) `

const visibleDirectoryRuntimeSQL = `from runtime_grants g
 join runtimes r on r.id=g.runtime_id and r.revoked_at is null
 join installations i on i.id=r.installation_id and i.revoked_at is null
 join hosts h on h.id=i.host_id and h.state='active'
 join org_memberships m on m.org_id=h.org_id and m.user_id=a.id
 where g.user_id=a.id and ` + runtimeEnrollmentApprovedSQL + ` and ` + runtimeDirectoryEligibilitySQL

type HostDirectory struct {
	Items      []Host  `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

type RuntimeDirectory struct {
	Items      []Runtime `json:"items"`
	NextCursor *string   `json:"next_cursor"`
}

type resourceDirectoryCursor struct {
	Version     int    `json:"v"`
	Purpose     string `json:"purpose"`
	UserID      string `json:"user_id"`
	ProofKeyJKT string `json:"proof_key_jkt"`
	AfterID     string `json:"after_id"`
}

func parseResourceDirectoryCursor(encoded, purpose string) (resourceDirectoryCursor, error) {
	var cursor resourceDirectoryCursor
	if len(encoded) > 1024 || (purpose != "host-directory-v1" && purpose != "runtime-directory-v1") {
		return cursor, ErrResourceDirectoryInvalid
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) == 0 || base64.RawURLEncoding.EncodeToString(raw) != encoded || auth.ValidateJSONObject(raw) != nil {
		return cursor, ErrResourceDirectoryInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cursor) != nil || cursor.Version != 1 || cursor.Purpose != purpose ||
		!grantUUIDPattern.MatchString(cursor.UserID) || !keyThumbprintPattern.MatchString(cursor.ProofKeyJKT) || !grantUUIDPattern.MatchString(cursor.AfterID) {
		return cursor, ErrResourceDirectoryInvalid
	}
	return cursor, nil
}

func resourceDirectoryArgs(device, proof string, limit int, encoded, purpose string) (any, any, error) {
	if !grantUUIDPattern.MatchString(device) || !keyThumbprintPattern.MatchString(proof) || limit < 1 || limit > 100 {
		return nil, nil, ErrResourceDirectoryInvalid
	}
	if encoded == "" {
		return nil, nil, nil
	}
	cursor, err := parseResourceDirectoryCursor(encoded, purpose)
	if err != nil {
		return nil, nil, err
	}
	if cursor.ProofKeyJKT != proof {
		return nil, nil, ErrAccessDenied
	}
	return cursor.UserID, cursor.AfterID, nil
}

func resourceDirectoryNext(actor, proof, after, purpose string) *string {
	raw, _ := json.Marshal(resourceDirectoryCursor{Version: 1, Purpose: purpose, UserID: actor, ProofKeyJKT: proof, AfterID: after})
	next := base64.RawURLEncoding.EncodeToString(raw)
	return &next
}

func (postgres *Postgres) HostDirectory(ctx context.Context, identity UserIdentity, device, proof string, limit int, encoded string) (HostDirectory, error) {
	page := HostDirectory{Items: []Host{}}
	actorArg, after, err := resourceDirectoryArgs(device, proof, limit, encoded, "host-directory-v1")
	if err != nil {
		return page, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var actor string
	var raw []byte
	err = postgres.DB.QueryRowContext(ctx, resourceDirectoryActorSQL+`
 select a.id::text,coalesce((select jsonb_agg(row_to_json(p) order by p.id) from (
 select distinct h.id,h.alias,h.state `+visibleDirectoryRuntimeSQL+`
 and ($6::uuid is null or h.id>$6) order by h.id limit $7) p),'[]'::jsonb) from actor a`,
		identity.Issuer, identity.Subject, device, proof, actorArg, after, limit+1).Scan(&actor, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return page, ErrAccessDenied
	}
	if err != nil || json.Unmarshal(raw, &page.Items) != nil {
		return HostDirectory{}, ErrDatabaseUnavailable
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		page.NextCursor = resourceDirectoryNext(actor, proof, page.Items[len(page.Items)-1].ID, "host-directory-v1")
	}
	return page, nil
}

func (postgres *Postgres) RuntimeDirectory(ctx context.Context, identity UserIdentity, device, proof string, limit int, encoded string) (RuntimeDirectory, error) {
	page := RuntimeDirectory{Items: []Runtime{}}
	actorArg, after, err := resourceDirectoryArgs(device, proof, limit, encoded, "runtime-directory-v1")
	if err != nil {
		return page, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var actor string
	var raw []byte
	err = postgres.DB.QueryRowContext(ctx, resourceDirectoryActorSQL+`
 select a.id::text,coalesce((select jsonb_agg(row_to_json(p) order by p.id) from (
 select r.id,h.id host_id,h.org_id organization_id,coalesce(r.dsh_version,'') dsh_version,
 coalesce(r.application_version,'') application_version,coalesce(r.plugin_version,'') plugin_version,r.protocol_version,r.last_seen_at,
 jsonb_build_object('role',g.role,'grant_version',g.grant_version,'scope',g.scope,'expires_at',g.expires_at) access
 `+visibleDirectoryRuntimeSQL+` and ($6::uuid is null or r.id>$6) order by r.id limit $7) p),'[]'::jsonb) from actor a`,
		identity.Issuer, identity.Subject, device, proof, actorArg, after, limit+1).Scan(&actor, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return page, ErrAccessDenied
	}
	if err != nil || json.Unmarshal(raw, &page.Items) != nil {
		return RuntimeDirectory{}, ErrDatabaseUnavailable
	}
	for _, item := range page.Items {
		if item.Access == nil || item.Access.GrantVersion < 1 || item.Access.GrantVersion > 9007199254740991 {
			return RuntimeDirectory{}, ErrDatabaseUnavailable
		}
		normalized, err := NormalizeRuntimeGrantInput(RuntimeGrantInput{Role: item.Access.Role, Scope: item.Access.Scope}, time.Time{})
		if err != nil {
			return RuntimeDirectory{}, ErrDatabaseUnavailable
		}
		item.Access.Scope = normalized.Scope
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		page.NextCursor = resourceDirectoryNext(actor, proof, page.Items[len(page.Items)-1].ID, "runtime-directory-v1")
	}
	return page, nil
}
