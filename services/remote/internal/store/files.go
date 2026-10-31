package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
)

type FileStore struct {
	database *Postgres
	limits   files.Limits
}

var fileProofKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func NewFileStore(database *Postgres, limits files.Limits) (*FileStore, error) {
	if database == nil || database.DB == nil || limits.Validate() != nil {
		return nil, files.ErrInvalid
	}
	return &FileStore{database: database, limits: limits}, nil
}

type fileAuthority struct {
	scope                    GrantScope
	workspace                sql.NullString
	org, user                string
	keyVersion, grantVersion int64
	grantExpires             sql.NullTime
	sessionState             string
}

func databaseTime(ctx context.Context, transaction *sql.Tx) (time.Time, error) {
	var now time.Time
	if err := transaction.QueryRowContext(ctx, `select clock_timestamp()`).Scan(&now); err != nil {
		return time.Time{}, files.ErrUnavailable
	}
	return now.UTC(), nil
}

func fileAuthorityTime(ctx context.Context, tx *sql.Tx, authority fileAuthority) (time.Time, error) {
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return time.Time{}, err
	}
	if authority.grantExpires.Valid && !authority.grantExpires.Time.After(now) {
		return time.Time{}, files.ErrAccess
	}
	return now, nil
}

func fileWindow(record files.Record, now time.Time) error {
	if !record.ExpiresAt.After(now) || !record.RetainUntil.After(now) {
		return files.ErrAccess
	}
	return nil
}

func authorizeFile(ctx context.Context, transaction *sql.Tx, actor files.Actor, runtimeID, sessionID string, mutate bool) (fileAuthority, error) {
	return authorizeFileAction(ctx, transaction, actor, runtimeID, sessionID, "file.upload", mutate)
}

func authorizeFileAction(ctx context.Context, transaction *sql.Tx, actor files.Actor, runtimeID, sessionID, action string, unarchived bool) (fileAuthority, error) {
	if actor.Issuer == "" || actor.Subject == "" || !grantUUIDPattern.MatchString(actor.DeviceID) || !fileProofKeyPattern.MatchString(actor.ProofKeyJKT) ||
		!grantUUIDPattern.MatchString(runtimeID) || !grantUUIDPattern.MatchString(sessionID) {
		return fileAuthority{}, files.ErrAccess
	}
	var authority fileAuthority
	var role string
	var encoded []byte
	var workspace sql.NullString
	err := transaction.QueryRowContext(ctx, `
		select h.org_id::text, u.id::text, d.key_version, g.grant_version, g.expires_at, g.role, g.scope, s.workspace_id::text, s.state
		from users u
		join devices d on d.user_id=u.id and d.id=$3 and d.proof_key_thumbprint=$4 and d.revoked_at is null
		join org_memberships m on m.user_id=u.id
		join hosts h on h.org_id=m.org_id and h.state='active'
		join installations i on i.host_id=h.id and i.revoked_at is null
		join runtimes r on r.installation_id=i.id and r.id=$5 and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+`
		join runtime_grants g on g.runtime_id=r.id and g.user_id=u.id and g.revoked_at is null
		join sessions s on s.runtime_id=r.id and s.id=$6
		where u.issuer=$1 and u.subject=$2 and u.status='active'
		for share of u,d,m,h,i,r,g,s`, actor.Issuer, actor.Subject, actor.DeviceID, actor.ProofKeyJKT, runtimeID, sessionID).
		Scan(&authority.org, &authority.user, &authority.keyVersion, &authority.grantVersion, &authority.grantExpires, &role, &encoded, &workspace, &authority.sessionState)
	if errors.Is(err, sql.ErrNoRows) {
		return authority, files.ErrAccess
	}
	if err != nil {
		return authority, files.ErrUnavailable
	}
	var scope GrantScope
	if json.Unmarshal(encoded, &scope) != nil {
		return authority, files.ErrUnavailable
	}
	now, err := databaseTime(ctx, transaction)
	if err != nil {
		return authority, err
	}
	if role != "owner" && role != "operator" || !slices.Contains(scope.Actions, action) || action == "file.download" && !slices.Contains(scope.Actions, "session.read") || !scopeIncludesSession(scope, sessionID, workspace) ||
		authority.grantExpires.Valid && !authority.grantExpires.Time.After(now) || unarchived && authority.sessionState == "archived" {
		return authority, files.ErrAccess
	}
	authority.scope, authority.workspace = scope, workspace
	return authority, nil
}

const fileColumns = `f.id::text,t.org_id::text,t.runtime_id::text,f.session_id::text,f.uploader_id::text,t.uploader_device_id::text,t.proof_key_jkt,
 t.device_key_version,t.grant_version,t.request_id::text,t.request_sha256,f.name,f.sha256,f.state,coalesce(t.error_code,''),f.size_bytes,
 t.quarantine_attempt_id::text,coalesce(t.committed_attempt_id::text,''),f.created_at,t.upload_expires_at,f.expires_at,t.retain_until,f.direction`

type fileScanner interface{ Scan(...any) error }

func scanFile(row fileScanner) (files.Record, error) {
	var record files.Record
	err := row.Scan(&record.ID, &record.OrganizationID, &record.RuntimeID, &record.SessionID, &record.UploaderID, &record.DeviceID, &record.ProofKeyJKT,
		&record.KeyVersion, &record.GrantVersion, &record.RequestID, &record.RequestSHA256, &record.Name, &record.SHA256, &record.State, &record.ErrorCode, &record.SizeBytes,
		&record.QuarantineAttempt, &record.CommittedAttempt, &record.CreatedAt, &record.UploadExpiresAt, &record.ExpiresAt, &record.RetainUntil, &record.Direction)
	return record, err
}

func loadFile(ctx context.Context, transaction *sql.Tx, id string, lock string) (files.Record, error) {
	return scanFile(transaction.QueryRowContext(ctx, `select `+fileColumns+` from files f join file_transfers t on t.file_id=f.id where f.id=$1 `+lock, id))
}

func verifyFileOwner(record files.Record, authority fileAuthority, actor files.Actor, original bool) error {
	if record.UploaderID != authority.user || record.DeviceID != actor.DeviceID || record.OrganizationID != authority.org ||
		original && (record.KeyVersion != authority.keyVersion || record.GrantVersion != authority.grantVersion || record.ProofKeyJKT != actor.ProofKeyJKT) {
		return files.ErrAccess
	}
	return nil
}

type fileQuota struct {
	kind, id                         string
	bytes, count, maxBytes, maxCount int64
}

func (repository *FileStore) lockQuotas(ctx context.Context, transaction *sql.Tx, authority fileAuthority, session string) ([]fileQuota, error) {
	// Every quota transaction uses organization/session/user order. File row
	// lookups during registration remain read-only so GC can lock file -> quota.
	quotas := []fileQuota{{kind: "organization", id: authority.org, maxBytes: repository.limits.OrganizationBytes, maxCount: repository.limits.OrganizationFiles},
		{kind: "session", id: session, maxBytes: repository.limits.SessionBytes, maxCount: repository.limits.SessionFiles},
		{kind: "user", id: authority.user, maxBytes: repository.limits.UserBytes, maxCount: repository.limits.UserFiles}}
	for index := range quotas {
		quota := &quotas[index]
		if _, err := transaction.ExecContext(ctx, `insert into file_quota_usage(org_id,kind,bucket_id) values($1,$2,$3) on conflict do nothing`, authority.org, quota.kind, quota.id); err != nil {
			return nil, files.ErrUnavailable
		}
		if err := transaction.QueryRowContext(ctx, `select reserved_bytes,reserved_files from file_quota_usage where org_id=$1 and kind=$2 and bucket_id=$3 for update`, authority.org, quota.kind, quota.id).Scan(&quota.bytes, &quota.count); err != nil {
			return nil, files.ErrUnavailable
		}
	}
	return quotas, nil
}

func fileUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", files.ErrUnavailable
	}
	value[6], value[8] = value[6]&15|64, value[8]&63|128
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[:4], value[4:6], value[6:8], value[8:10], value[10:]), nil
}

func fileAudit(ctx context.Context, transaction *sql.Tx, record files.Record, action, result string) error {
	metadata, _ := json.Marshal(map[string]any{"file_id": record.ID, "request_id": record.RequestID, "size_bytes": record.SizeBytes, "sha256": record.SHA256, "state": record.State})
	return fileSingleWrite(transaction.ExecContext(ctx, `insert into audit_log(org_id,actor_type,actor_id,device_id,runtime_id,session_id,action,result,metadata)
		values($1,'device',$2::uuid::text,$2,$3,$4,$5,$6,$7::jsonb)`, record.OrganizationID, record.DeviceID, record.RuntimeID, record.SessionID, action, result, string(metadata)))
}

func (repository *FileStore) RegisterUpload(ctx context.Context, actor files.Actor, input files.UploadRegistration) (files.Record, error) {
	digest, err := files.NormalizeRegistration(input)
	if err != nil {
		return files.Record{}, err
	}
	transaction, err := repository.database.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	defer transaction.Rollback()
	authority, err := authorizeFile(ctx, transaction, actor, input.RuntimeID, input.SessionID, true)
	if err != nil {
		return files.Record{}, err
	}
	quotas, err := repository.lockQuotas(ctx, transaction, authority, input.SessionID)
	if err != nil {
		return files.Record{}, err
	}
	now, err := databaseTime(ctx, transaction)
	if err != nil {
		return files.Record{}, err
	}
	if authority.grantExpires.Valid && !authority.grantExpires.Time.After(now) {
		return files.Record{}, files.ErrAccess
	}
	existing, err := scanFile(transaction.QueryRowContext(ctx, `select `+fileColumns+` from files f join file_transfers t on t.file_id=f.id where t.uploader_device_id=$1 and t.request_id=$2`, actor.DeviceID, input.RequestID))
	if err == nil {
		if existing.Direction != "to_host" || existing.UploaderID != authority.user || existing.RuntimeID != input.RuntimeID || existing.SessionID != input.SessionID || existing.RequestSHA256 != digest {
			return files.Record{}, files.ErrConflict
		}
		if _, err := fileAuthorityTime(ctx, transaction, authority); err != nil {
			return files.Record{}, err
		}
		if err := transaction.Commit(); err != nil {
			return files.Record{}, files.ErrUnavailable
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return files.Record{}, files.ErrUnavailable
	}
	for _, quota := range quotas {
		if quota.bytes > quota.maxBytes || input.SizeBytes > quota.maxBytes-quota.bytes || quota.count >= quota.maxCount {
			return files.Record{}, files.ErrQuota
		}
	}
	id, err := fileUUID()
	if err != nil {
		return files.Record{}, err
	}
	attempt, err := fileUUID()
	if err != nil {
		return files.Record{}, err
	}
	record := files.Record{ID: id, OrganizationID: authority.org, RuntimeID: input.RuntimeID, SessionID: input.SessionID, UploaderID: authority.user,
		DeviceID: actor.DeviceID, ProofKeyJKT: actor.ProofKeyJKT, KeyVersion: authority.keyVersion, GrantVersion: authority.grantVersion,
		RequestID: input.RequestID, RequestSHA256: digest, Name: input.Name, SizeBytes: input.SizeBytes, SHA256: input.SHA256, Direction: "to_host", State: "uploading", QuarantineAttempt: attempt,
		CreatedAt: now, UploadExpiresAt: now.Add(repository.limits.UploadURLTTL), ExpiresAt: now.Add(repository.limits.AbandonAfter), RetainUntil: now.Add(repository.limits.RetainFor)}
	key, err := record.SourceKey()
	if err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	if err := fileSingleWrite(transaction.ExecContext(ctx, `insert into files(id,session_id,uploader_id,direction,name,size_bytes,sha256,object_key,state,expires_at,created_at)
		values($1,$2,$3,'to_host',$4,$5,$6,$7,'uploading',$8,$9)`, id, input.SessionID, authority.user, input.Name, input.SizeBytes, input.SHA256, key.StorageKey(), record.ExpiresAt, now)); err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	var inserted string
	err = transaction.QueryRowContext(ctx, `insert into file_transfers(file_id,org_id,runtime_id,uploader_device_id,device_key_version,proof_key_jkt,grant_version,request_id,request_sha256,quarantine_attempt_id,upload_expires_at,retain_until)
		values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) on conflict(uploader_device_id,request_id) do nothing returning file_id::text`, id, authority.org, input.RuntimeID, actor.DeviceID, authority.keyVersion, actor.ProofKeyJKT, authority.grantVersion,
		input.RequestID, digest, attempt, record.UploadExpiresAt, record.RetainUntil).Scan(&inserted)
	if errors.Is(err, sql.ErrNoRows) {
		return files.Record{}, files.ErrConflict
	}
	if err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	if err := fileSingleWrite(transaction.ExecContext(ctx, `insert into file_objects(file_id,kind,attempt_id,object_key,cleanup_after) values($1,'quarantine',$2,$3,$4)`, id, attempt, key.StorageKey(), record.ExpiresAt)); err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	for _, quota := range quotas {
		if err := fileSingleWrite(transaction.ExecContext(ctx, `update file_quota_usage set reserved_bytes=reserved_bytes+$4,reserved_files=reserved_files+1 where org_id=$1 and kind=$2 and bucket_id=$3`, authority.org, quota.kind, quota.id, input.SizeBytes)); err != nil {
			return files.Record{}, files.ErrUnavailable
		}
	}
	if err := fileAudit(ctx, transaction, record, "file.registered", "success"); err != nil {
		return files.Record{}, err
	}
	record, err = loadFile(ctx, transaction, id, "")
	if err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	now, err = fileAuthorityTime(ctx, transaction, authority)
	if err != nil {
		return files.Record{}, err
	}
	if err := fileWindow(record, now); err != nil {
		return files.Record{}, err
	}
	if !record.UploadExpiresAt.After(now) {
		return files.Record{}, files.ErrStale
	}
	if err := transaction.Commit(); err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	return record, nil
}

func (repository *FileStore) Status(ctx context.Context, actor files.Actor, id string) (files.Record, error) {
	if !grantUUIDPattern.MatchString(id) {
		return files.Record{}, files.ErrAccess
	}
	transaction, err := repository.database.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	defer transaction.Rollback()
	record, err := loadFile(ctx, transaction, id, "for share of f,t")
	if errors.Is(err, sql.ErrNoRows) {
		return files.Record{}, files.ErrAccess
	}
	if err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	action := "file.upload"
	if record.Direction == "from_host" {
		action = "file.download"
	}
	authority, err := authorizeFileAction(ctx, transaction, actor, record.RuntimeID, record.SessionID, action, false)
	if err != nil {
		return files.Record{}, err
	}
	if err := verifyFileOwner(record, authority, actor, false); err != nil {
		return files.Record{}, err
	}
	now, err := fileAuthorityTime(ctx, transaction, authority)
	if err != nil {
		return files.Record{}, err
	}
	if !record.ExpiresAt.After(now) || !record.RetainUntil.After(now) {
		record.State, record.ErrorCode = "expired", "expired"
	}
	if err := transaction.Commit(); err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	return record, nil
}

func (repository *FileStore) AuthorizeUpload(ctx context.Context, actor files.Actor, id string) (files.Record, error) {
	return repository.uploadOperation(ctx, actor, id, false)
}

func (repository *FileStore) BeginScan(ctx context.Context, actor files.Actor, id string) (files.Record, error) {
	return repository.uploadOperation(ctx, actor, id, true)
}

func (repository *FileStore) uploadOperation(ctx context.Context, actor files.Actor, id string, commit bool) (files.Record, error) {
	if !grantUUIDPattern.MatchString(id) {
		return files.Record{}, files.ErrAccess
	}
	transaction, err := repository.database.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	defer transaction.Rollback()
	record, err := loadFile(ctx, transaction, id, "for update of f,t")
	if errors.Is(err, sql.ErrNoRows) {
		return files.Record{}, files.ErrAccess
	}
	if err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	if record.Direction != "to_host" {
		return files.Record{}, files.ErrAccess
	}
	authority, err := authorizeFile(ctx, transaction, actor, record.RuntimeID, record.SessionID, record.State == "uploading")
	if err != nil {
		return files.Record{}, err
	}
	if err := verifyFileOwner(record, authority, actor, record.State == "uploading"); err != nil {
		return files.Record{}, err
	}
	now, err := databaseTime(ctx, transaction)
	if err != nil {
		return files.Record{}, err
	}
	if !record.ExpiresAt.After(now) {
		return files.Record{}, files.ErrAccess
	}
	if !commit && (record.State != "uploading" || !record.UploadExpiresAt.After(now)) {
		return files.Record{}, files.ErrStale
	}
	if commit && record.State == "uploading" {
		if err := fileSingleWrite(transaction.ExecContext(ctx, `update files set state='scanning' where id=$1;`, id)); err != nil {
			return files.Record{}, files.ErrUnavailable
		}
		record.State = "scanning"
		if err := fileSingleWrite(transaction.ExecContext(ctx, `update file_transfers set scan_ready_at=clock_timestamp(),error_code=null where file_id=$1`, id)); err != nil {
			return files.Record{}, files.ErrUnavailable
		}
		if err := fileAudit(ctx, transaction, record, "file.scan_requested", "success"); err != nil {
			return files.Record{}, err
		}
	}
	now, err = fileAuthorityTime(ctx, transaction, authority)
	if err != nil {
		return files.Record{}, err
	}
	if err := fileWindow(record, now); err != nil {
		return files.Record{}, err
	}
	// The PUT URL deadline only controls URL issuance. An already uploaded
	// object can still be committed within its current file window.
	if !commit && !record.UploadExpiresAt.After(now) {
		return files.Record{}, files.ErrStale
	}
	if err := transaction.Commit(); err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	return record, nil
}
