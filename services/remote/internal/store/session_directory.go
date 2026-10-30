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

var ErrSessionDirectoryInvalid = errors.New("store: invalid session directory request")

type SessionDirectory struct {
	RuntimeID  string    `json:"runtime_id"`
	Items      []Session `json:"items"`
	NextCursor *string   `json:"next_cursor"`
}

type sessionDirectoryCursor struct {
	Version        int    `json:"v"`
	Purpose        string `json:"purpose"`
	UserID         string `json:"user_id"`
	ProofKeyJKT    string `json:"proof_key_jkt"`
	RuntimeID      string `json:"runtime_id"`
	AfterSessionID string `json:"after_session_id"`
}

func parseSessionDirectoryCursor(encoded string) (sessionDirectoryCursor, error) {
	var cursor sessionDirectoryCursor
	if len(encoded) > 1024 {
		return cursor, ErrSessionDirectoryInvalid
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) == 0 || base64.RawURLEncoding.EncodeToString(raw) != encoded || auth.ValidateJSONObject(raw) != nil {
		return cursor, ErrSessionDirectoryInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cursor) != nil || cursor.Version != 1 || cursor.Purpose != "session-directory-v1" ||
		!grantUUIDPattern.MatchString(cursor.UserID) || !keyThumbprintPattern.MatchString(cursor.ProofKeyJKT) ||
		!grantUUIDPattern.MatchString(cursor.RuntimeID) || !grantUUIDPattern.MatchString(cursor.AfterSessionID) {
		return cursor, ErrSessionDirectoryInvalid
	}
	return cursor, nil
}

// SessionDirectory pages only metadata under the current phone and explicit
// session.list resource scope. Stable UUID order is independent of activity updates.
func (postgres *Postgres) SessionDirectory(ctx context.Context, identity UserIdentity, deviceID, proofJKT, runtimeID string, limit int, encoded string) (SessionDirectory, error) {
	page := SessionDirectory{RuntimeID: runtimeID, Items: []Session{}}
	if !grantUUIDPattern.MatchString(deviceID) || !grantUUIDPattern.MatchString(runtimeID) || !keyThumbprintPattern.MatchString(proofJKT) || limit < 1 || limit > 100 {
		return page, ErrSessionDirectoryInvalid
	}
	var cursorUser, after any
	if encoded != "" {
		cursor, err := parseSessionDirectoryCursor(encoded)
		if err != nil {
			return page, err
		}
		if cursor.ProofKeyJKT != proofJKT || cursor.RuntimeID != runtimeID {
			return page, ErrAccessDenied
		}
		cursorUser, after = cursor.UserID, cursor.AfterSessionID
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var actor string
	var raw []byte
	err := postgres.DB.QueryRowContext(ctx, `with access as materialized (
	 select u.id,g.scope from users u join devices d on d.user_id=u.id
	 join runtimes r on r.id=$5 and r.revoked_at is null
	 join installations i on i.id=r.installation_id and i.revoked_at is null
	 join hosts h on h.id=i.host_id and h.state='active'
	 join org_memberships m on m.user_id=u.id and m.org_id=h.org_id
	 join runtime_grants g on g.user_id=u.id and g.runtime_id=r.id
	 where u.issuer=$1 and u.subject=$2 and u.status='active' and d.id=$3 and d.proof_key_thumbprint=$4 and d.revoked_at is null
	 and ($6::uuid is null or u.id=$6) and `+runtimeEnrollmentApprovedSQL+`
	 and g.revoked_at is null and (g.expires_at is null or g.expires_at>statement_timestamp()) and g.scope->'actions' ? 'session.list'
	)
	select a.id::text,coalesce((select jsonb_agg(row_to_json(p) order by p.session_id) from (
	 select s.id session_id,s.runtime_id,s.workspace_id,s.state,s.last_persisted_seq,s.updated_at
	 from sessions s where s.runtime_id=$5 and ($7::uuid is null or s.id>$7) and (
	 coalesce(a.scope->'sessions','[]'::jsonb) @> jsonb_build_array(s.id::text) or
	 (s.workspace_id is not null and coalesce(a.scope->'workspaces','[]'::jsonb) @> jsonb_build_array(s.workspace_id::text)))
	 order by s.id limit $8) p),'[]'::jsonb) from access a`, identity.Issuer, identity.Subject, deviceID, proofJKT, runtimeID, cursorUser, after, limit+1).Scan(&actor, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return page, ErrAccessDenied
	}
	if err != nil {
		return page, ErrDatabaseUnavailable
	}
	if json.Unmarshal(raw, &page.Items) != nil {
		return SessionDirectory{}, ErrDatabaseUnavailable
	}
	for index, item := range page.Items {
		page.Items[index].RuntimeID = runtimeID
		if item.LastPersistedSeq < -1 || item.LastPersistedSeq > 9007199254740991 || item.UpdatedAt.IsZero() {
			return SessionDirectory{}, ErrDatabaseUnavailable
		}
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		raw, _ := json.Marshal(sessionDirectoryCursor{Version: 1, Purpose: "session-directory-v1", UserID: actor, ProofKeyJKT: proofJKT, RuntimeID: runtimeID, AfterSessionID: page.Items[len(page.Items)-1].ID})
		next := base64.RawURLEncoding.EncodeToString(raw)
		page.NextCursor = &next
	}
	return page, nil
}
