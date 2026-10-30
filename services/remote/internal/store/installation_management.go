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

var ErrInstallationManagementInvalid = errors.New("store: invalid installation management request")

type InstallationSummary struct {
	ID             string     `json:"installation_id"`
	HostID         string     `json:"host_id"`
	OrganizationID string     `json:"organization_id"`
	HostAlias      string     `json:"host_alias"`
	OwnerUserID    string     `json:"owner_user_id"`
	IsOwner        bool       `json:"is_owner"`
	KeyVersion     int64      `json:"key_version"`
	RuntimeCount   int64      `json:"runtime_count"`
	State          string     `json:"state"`
	CreatedAt      time.Time  `json:"created_at"`
	RevokedAt      *time.Time `json:"revoked_at"`
}
type InstallationDirectory struct {
	Items      []InstallationSummary `json:"items"`
	NextCursor *string               `json:"next_cursor"`
}
type installationDirectoryCursor struct {
	Version     int       `json:"v"`
	Purpose     string    `json:"purpose"`
	UserID      string    `json:"user_id"`
	ProofKeyJKT string    `json:"proof_key_jkt"`
	Before      time.Time `json:"before_created_at"`
	BeforeID    string    `json:"before_id"`
}

func parseInstallationDirectoryCursor(encoded string) (installationDirectoryCursor, error) {
	var cursor installationDirectoryCursor
	if len(encoded) > 1024 {
		return cursor, ErrInstallationManagementInvalid
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) == 0 || base64.RawURLEncoding.EncodeToString(raw) != encoded || auth.ValidateJSONObject(raw) != nil {
		return cursor, ErrInstallationManagementInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cursor) != nil || cursor.Version != 1 || cursor.Purpose != "installation-directory-v1" || !grantUUIDPattern.MatchString(cursor.UserID) || !keyThumbprintPattern.MatchString(cursor.ProofKeyJKT) || !grantUUIDPattern.MatchString(cursor.BeforeID) || cursor.Before.IsZero() {
		return cursor, ErrInstallationManagementInvalid
	}
	return cursor, nil
}

// ListInstallations exposes only owned installations or installations in an
// organization the current phone user still administers. Every page rechecks membership.
func (postgres *Postgres) ListInstallations(ctx context.Context, identity UserIdentity, deviceID, proofJKT string, limit int, cursorValue string) (InstallationDirectory, error) {
	page := InstallationDirectory{Items: []InstallationSummary{}}
	if !grantUUIDPattern.MatchString(deviceID) || !keyThumbprintPattern.MatchString(proofJKT) || limit < 1 || limit > 100 {
		return page, ErrInstallationManagementInvalid
	}
	var userArg, beforeArg, idArg any
	if cursorValue != "" {
		cursor, err := parseInstallationDirectoryCursor(cursorValue)
		if err != nil {
			return page, err
		}
		if cursor.ProofKeyJKT != proofJKT {
			return page, ErrAccessDenied
		}
		userArg = cursor.UserID
		beforeArg = cursor.Before
		idArg = cursor.BeforeID
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var actorID string
	var raw []byte
	err := postgres.DB.QueryRowContext(ctx, `with actor as materialized(
	 select u.id from users u join devices d on d.user_id=u.id where u.issuer=$1 and u.subject=$2 and u.status='active'
	 and d.id=$3 and d.proof_key_thumbprint=$7 and d.revoked_at is null)
	 select a.id::text,coalesce((select jsonb_agg(row_to_json(p) order by p.created_at desc,p.installation_id desc) from (
	 select i.id installation_id,h.id host_id,h.org_id organization_id,h.alias host_alias,i.owner_user_id,i.owner_user_id=a.id is_owner,
	 i.key_version,(select count(*) from runtimes owned_runtime where owned_runtime.installation_id=i.id) runtime_count,
	 case when i.revoked_at is not null or h.state='revoked' then 'revoked'
	 when h.state='active' and `+installationHasApprovedRuntimeSQL+` then 'active' else 'pending' end state,i.created_at,i.revoked_at
	 from installations i join hosts h on h.id=i.host_id join org_memberships m on m.org_id=h.org_id and m.user_id=a.id
	 where (i.owner_user_id=a.id or m.role='admin') and ($5::timestamptz is null or (i.created_at,i.id)<($5,$6::uuid))
	 order by i.created_at desc,i.id desc limit $8) p),'[]'::jsonb) from actor a where $4::uuid is null or a.id=$4`, identity.Issuer, identity.Subject, deviceID, userArg, beforeArg, idArg, proofJKT, limit+1).Scan(&actorID, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return page, ErrAccessDenied
	}
	if err != nil {
		return page, ErrDatabaseUnavailable
	}
	if json.Unmarshal(raw, &page.Items) != nil {
		return InstallationDirectory{}, ErrDatabaseUnavailable
	}
	for _, item := range page.Items {
		if !grantUUIDPattern.MatchString(item.ID) || item.KeyVersion < 1 || item.KeyVersion > 9007199254740991 || item.RuntimeCount < 0 || item.RuntimeCount > 9007199254740991 || item.CreatedAt.IsZero() {
			return InstallationDirectory{}, ErrDatabaseUnavailable
		}
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		raw, _ := json.Marshal(installationDirectoryCursor{Version: 1, Purpose: "installation-directory-v1", UserID: actorID, ProofKeyJKT: proofJKT, Before: last.CreatedAt.UTC(), BeforeID: last.ID})
		next := base64.RawURLEncoding.EncodeToString(raw)
		page.NextCursor = &next
	}
	return page, nil
}

func (postgres *Postgres) RevokeInstallation(ctx context.Context, identity UserIdentity, deviceID, proofJKT, installationID string) error {
	if !grantUUIDPattern.MatchString(deviceID) || !grantUUIDPattern.MatchString(installationID) || !keyThumbprintPattern.MatchString(proofJKT) {
		return ErrInstallationManagementInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, err := retrySerializable(ctx, func() (bool, error) {
		return postgres.revokeInstallationOnce(ctx, identity, deviceID, proofJKT, installationID)
	})
	return err
}

func (postgres *Postgres) revokeInstallationOnce(ctx context.Context, identity UserIdentity, deviceID, proofJKT, installationID string) (bool, error) {
	// The installation lock fences enrollment, grants and credential minting.
	// Fresh statement snapshots include anything committed while waiting for it.
	tx, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return false, transactionFailure(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `set local lock_timeout='2s'`); err != nil {
		return false, transactionFailure(err)
	}
	if _, err = lockRecoveryReady(ctx, tx, ""); err != nil {
		return false, err
	}
	actor, err := postgres.userIDForSerializable(ctx, tx, identity.Issuer, identity.Subject)
	if err != nil {
		return false, err
	}
	var current string
	if err = tx.QueryRowContext(ctx, `select id::text from devices where id=$1 and user_id=$2 and proof_key_thumbprint=$3 and revoked_at is null for share`, deviceID, actor, proofJKT).Scan(&current); errors.Is(err, sql.ErrNoRows) {
		return false, ErrAccessDenied
	} else if err != nil {
		return false, transactionFailure(err)
	}
	var hostID, orgID string
	var revoked *time.Time
	err = tx.QueryRowContext(ctx, `select h.id::text,h.org_id::text,i.revoked_at from installations i join hosts h on h.id=i.host_id
	 join org_memberships m on m.org_id=h.org_id and m.user_id=$2
	 where i.id=$1 and (i.owner_user_id=$2 or m.role='admin')
	 for update of i,h for share of m /* installation_revoke_fence */`, installationID, actor).Scan(&hostID, &orgID, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrAccessDenied
	}
	if err != nil {
		return false, transactionFailure(err)
	}
	if revoked != nil {
		return true, nil
	}
	queries := []string{
		`update installations set revoked_at=clock_timestamp() where id=$1`,
		`update runtimes set revoked_at=coalesce(revoked_at,clock_timestamp()) where installation_id=$1`,
		`update host_connection_credentials set revoked_at=clock_timestamp() where installation_id=$1 and revoked_at is null`,
		`update installation_challenges set consumed_at=clock_timestamp() where installation_id=$1 and consumed_at is null`,
		`update realtime_tickets set consumed_at=clock_timestamp() where consumed_at is null and runtime_id in(select id from runtimes where installation_id=$1)`,
		`update enrollments set state='cancelled',decided_at=clock_timestamp() where installation_id=$1 and state in('pending','user_confirmed')`,
		`update sessions set state='unavailable',updated_at=clock_timestamp() where runtime_id in(select id from runtimes where installation_id=$1) and state in('available','running')`,
		`update file_handoffs set state='invalidated',staged_name=null,ended_at=clock_timestamp() where runtime_id in(select id from runtimes where installation_id=$1) and state in('offered','downloading','staged')`,
	}
	for _, query := range queries {
		if _, err = tx.ExecContext(ctx, query, installationID); err != nil {
			return false, transactionFailure(err)
		}
	}
	_, err = tx.ExecContext(ctx, `with retired as(
	 update runtime_grants g set revoked_at=clock_timestamp(),grant_version=g.grant_version+1 from runtimes r
	 where r.id=g.runtime_id and r.installation_id=$1 and g.revoked_at is null returning g.runtime_id,g.user_id,g.grant_version),
	 notified as(insert into control_outbox(org_id,topic,payload) select $2::uuid,'runtime_grant.revoked',jsonb_build_object('runtime_id',runtime_id::text,'user_id',user_id::text,'grant_version',grant_version) from retired returning id)
	 insert into audit_log(org_id,actor_type,actor_id,device_id,runtime_id,action,result,metadata)
	 select $2::uuid,'user',$3::text,$4::uuid,runtime_id,'runtime_grant.revoke','success',jsonb_build_object('installation_id',$1::uuid::text,'user_id',user_id::text,'grant_version',grant_version) from retired`, installationID, orgID, actor, deviceID)
	if err != nil {
		return false, transactionFailure(err)
	}
	if _, err = tx.ExecContext(ctx, `insert into control_outbox(org_id,topic,payload) select $2::uuid,'runtime.revoked',jsonb_build_object('runtime_id',id::text) from runtimes where installation_id=$1`, installationID, orgID); err != nil {
		return false, transactionFailure(err)
	}
	if _, err = tx.ExecContext(ctx, `insert into audit_log(org_id,actor_type,actor_id,device_id,action,result,metadata) values($1,'user',$2,$3,'installation.revoke','success',jsonb_build_object('installation_id',$4::uuid::text,'host_id',$5::uuid::text))`, orgID, actor, deviceID, installationID, hostID); err != nil {
		return false, transactionFailure(err)
	}
	if err = tx.Commit(); err != nil {
		return false, transactionFailure(err)
	}
	return true, nil
}
