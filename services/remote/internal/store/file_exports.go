package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
)

type exportOrigin struct {
	source   string
	host     files.HostBinding
	expires  time.Time
	uploaded sql.NullTime
}

func (repository *FileStore) ExportStatusByRequest(ctx context.Context, actor files.Actor, request string) (files.Record, error) {
	if !grantUUIDPattern.MatchString(request) || !grantUUIDPattern.MatchString(actor.DeviceID) {
		return files.Record{}, files.ErrAccess
	}
	var id string
	err := repository.database.DB.QueryRowContext(ctx, `select f.id::text from files f join file_transfers t on t.file_id=f.id
	 where t.uploader_device_id=$1 and t.request_id=$2 and f.direction='from_host'`, actor.DeviceID, request).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return files.Record{}, files.ErrAccess
	}
	if err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	return repository.Status(ctx, actor, id)
}

var exportReadID = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (repository *FileStore) AuditExportDownload(ctx context.Context, actor files.Actor, permit files.DownloadPermit, request, outcome string) error {
	if !exportReadID.MatchString(request) || !grantUUIDPattern.MatchString(permit.File.ID) || permit.File.Direction != "from_host" ||
		outcome != "opened" && outcome != "served" && outcome != "cancelled" && outcome != "failed" {
		return files.ErrInvalid
	}
	tx, err := repository.database.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return files.ErrUnavailable
	}
	defer tx.Rollback()
	record, err := loadFile(ctx, tx, permit.File.ID, "for share of f,t")
	if err != nil {
		return files.ErrUnavailable
	}
	if record.RequestSHA256 != permit.File.RequestSHA256 || record.Direction != "from_host" || record.DeviceID != actor.DeviceID || record.UploaderID != permit.File.UploaderID || record.ProofKeyJKT != actor.ProofKeyJKT {
		return files.ErrAccess
	}
	if outcome == "opened" {
		authority, err := authorizeExportOwner(ctx, tx, actor, record, false)
		if err != nil {
			return err
		}
		now, err := databaseTime(ctx, tx)
		if err != nil {
			return err
		}
		if authority.grantVersion != permit.AuthorizedGrantVersion || !permit.LeaseUntil.After(now) || record.State != "clean" {
			return files.ErrAccess
		}
	}
	metadata, _ := json.Marshal(map[string]any{"file_id": record.ID, "download_id": request, "sha256": record.SHA256, "size_bytes": record.SizeBytes})
	if _, err := tx.ExecContext(ctx, `insert into audit_log(org_id,actor_type,actor_id,device_id,runtime_id,session_id,action,result,metadata)
	 values($1,'system','file-service',$2,$3,$4,'file.export_download',$5,$6::jsonb)`, record.OrganizationID, record.DeviceID, record.RuntimeID, record.SessionID, outcome, string(metadata)); err != nil {
		return files.ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return files.ErrUnavailable
	}
	return nil
}

func loadExportOrigin(ctx context.Context, tx *sql.Tx, file files.Record) (exportOrigin, error) {
	var origin exportOrigin
	origin.host.RuntimeID = file.RuntimeID
	err := tx.QueryRowContext(ctx, `select source_id::text,installation_id::text,installation_key_version,runtime_epoch::text,connection_id::text,
	 credential_expires_at,source_expires_at,uploaded_at from file_exports where file_id=$1`, file.ID).
		Scan(&origin.source, &origin.host.InstallationID, &origin.host.KeyVersion, &origin.host.RuntimeEpoch, &origin.host.ConnectionID,
			&origin.host.CredentialExpiresAt, &origin.expires, &origin.uploaded)
	if errors.Is(err, sql.ErrNoRows) {
		return origin, files.ErrAccess
	}
	if err != nil {
		return origin, files.ErrUnavailable
	}
	return origin, nil
}

func authorizeExportOwner(ctx context.Context, tx *sql.Tx, actor files.Actor, record files.Record, original bool) (fileAuthority, error) {
	if record.Direction != "from_host" {
		return fileAuthority{}, files.ErrAccess
	}
	authority, err := authorizeFileAction(ctx, tx, actor, record.RuntimeID, record.SessionID, "file.download", false)
	if err != nil {
		return authority, err
	}
	if err := verifyFileOwner(record, authority, actor, original); err != nil {
		return authority, err
	}
	if record.KeyVersion != authority.keyVersion || record.ProofKeyJKT != actor.ProofKeyJKT {
		return authority, files.ErrAccess
	}
	return authority, nil
}

func authorizeBoundExport(ctx context.Context, tx *sql.Tx, record files.Record) (fileAuthority, error) {
	origin, err := loadExportOrigin(ctx, tx, record)
	if err != nil {
		return fileAuthority{}, err
	}
	if !origin.uploaded.Valid {
		return fileAuthority{}, files.ErrAccess
	}
	var actor files.Actor
	if err := tx.QueryRowContext(ctx, `select issuer,subject from users where id=$1`, record.UploaderID).Scan(&actor.Issuer, &actor.Subject); err != nil {
		return fileAuthority{}, files.ErrUnavailable
	}
	actor.DeviceID, actor.ProofKeyJKT = record.DeviceID, record.ProofKeyJKT
	return authorizeExportOwner(ctx, tx, actor, record, true)
}

// RegisterExport is called only after an authenticated Host has prepared an
// authorized source for the authenticated requesting device. Quota, immutable
// manifest, provenance and every object key commit in the same transaction.
func (repository *FileStore) RegisterExport(ctx context.Context, actor files.Actor, host files.HostBinding, input files.ExportRegistration) (files.Record, error) {
	digest, err := files.NormalizeExport(input, host)
	if err != nil {
		return files.Record{}, err
	}
	tx, err := repository.database.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	defer tx.Rollback()
	authority, err := authorizeFileAction(ctx, tx, actor, input.RuntimeID, input.SessionID, "file.download", false)
	if err != nil {
		return files.Record{}, err
	}
	if authority.sessionState != "available" && authority.sessionState != "running" && authority.sessionState != "archived" {
		return files.Record{}, files.ErrAccess
	}
	if _, _, err := hostFileBinding(ctx, tx, host); err != nil {
		return files.Record{}, err
	}
	quotas, err := repository.lockQuotas(ctx, tx, authority, input.SessionID)
	if err != nil {
		return files.Record{}, err
	}
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return files.Record{}, err
	}
	if !host.CredentialExpiresAt.After(now) || authority.grantExpires.Valid && !authority.grantExpires.Time.After(now) {
		return files.Record{}, files.ErrAccess
	}
	existing, err := scanFile(tx.QueryRowContext(ctx, `select `+fileColumns+` from files f join file_transfers t on t.file_id=f.id where t.uploader_device_id=$1 and t.request_id=$2`, actor.DeviceID, input.RequestID))
	if err == nil {
		if existing.Direction != "from_host" || existing.UploaderID != authority.user || existing.RuntimeID != input.RuntimeID || existing.SessionID != input.SessionID || existing.RequestSHA256 != digest {
			return files.Record{}, files.ErrConflict
		}
		origin, err := loadExportOrigin(ctx, tx, existing)
		if err != nil {
			return files.Record{}, err
		}
		if !sameFileHost(origin.host, host) || origin.source != input.SourceID {
			return files.Record{}, files.ErrAccess
		}
		if err := verifyFileOwner(existing, authority, actor, true); err != nil {
			return files.Record{}, err
		}
		if err := tx.Commit(); err != nil {
			return files.Record{}, files.ErrUnavailable
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return files.Record{}, files.ErrUnavailable
	}
	until := input.SourceExpiresAt.UTC().Truncate(time.Microsecond)
	if !until.After(now) || until.After(now.Add(5*time.Minute+30*time.Second)) {
		return files.Record{}, files.ErrStale
	}
	until = minTime(until, now.Add(5*time.Minute), host.CredentialExpiresAt)
	if authority.grantExpires.Valid {
		until = minTime(until, authority.grantExpires.Time)
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
		RequestID: input.RequestID, RequestSHA256: digest, Direction: "from_host", Name: input.Name, SizeBytes: input.SizeBytes, SHA256: input.SHA256,
		State: "uploading", QuarantineAttempt: attempt, CreatedAt: now, UploadExpiresAt: until, ExpiresAt: until, RetainUntil: now.Add(repository.limits.RetainFor)}
	key, err := record.SourceKey()
	if err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, `insert into files(id,session_id,uploader_id,direction,name,size_bytes,sha256,object_key,state,expires_at,created_at)
	 values($1,$2,$3,'from_host',$4,$5,$6,$7,'uploading',$8,$9)`, id, input.SessionID, authority.user, input.Name, input.SizeBytes, input.SHA256, key.StorageKey(), until, now); err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, `insert into file_transfers(file_id,org_id,runtime_id,uploader_device_id,device_key_version,proof_key_jkt,grant_version,request_id,request_sha256,quarantine_attempt_id,upload_expires_at,retain_until)
	 values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, id, authority.org, input.RuntimeID, actor.DeviceID, authority.keyVersion, actor.ProofKeyJKT, authority.grantVersion, input.RequestID, digest, attempt, until, record.RetainUntil); err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, `insert into file_exports(file_id,source_id,installation_id,installation_key_version,runtime_epoch,connection_id,credential_expires_at,source_expires_at)
	 values($1,$2,$3,$4,$5,$6,$7,$8)`, id, input.SourceID, host.InstallationID, host.KeyVersion, host.RuntimeEpoch, host.ConnectionID, host.CredentialExpiresAt, until); err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, `insert into file_objects(file_id,kind,attempt_id,object_key,cleanup_after) values($1,'quarantine',$2,$3,$4)`, id, attempt, key.StorageKey(), until.Add(fileCleanupGrace)); err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	for _, quota := range quotas {
		if _, err := tx.ExecContext(ctx, `update file_quota_usage set reserved_bytes=reserved_bytes+$4,reserved_files=reserved_files+1 where org_id=$1 and kind=$2 and bucket_id=$3`, authority.org, quota.kind, quota.id, input.SizeBytes); err != nil {
			return files.Record{}, files.ErrUnavailable
		}
	}
	if err := fileAudit(ctx, tx, record, "file.export_registered", "success"); err != nil {
		return files.Record{}, err
	}
	if _, err := tx.ExecContext(ctx, `insert into audit_log(org_id,actor_type,actor_id,device_id,runtime_id,session_id,action,result,metadata)
	 values($1,'installation',$2,$3,$4,$5,'file.export_source','success',jsonb_build_object('file_id',$6::text,'source_id',$7::text,'runtime_epoch',$8::text,'connection_id',$9::text))`,
		record.OrganizationID, host.InstallationID, record.DeviceID, record.RuntimeID, record.SessionID, id, input.SourceID, host.RuntimeEpoch, host.ConnectionID); err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	return record, nil
}

func minTime(first time.Time, rest ...time.Time) time.Time {
	for _, value := range rest {
		if value.Before(first) {
			first = value
		}
	}
	return first
}

func (repository *FileStore) AuthorizeExportUpload(ctx context.Context, actor files.Actor, host files.HostBinding, id string) (files.Record, error) {
	return repository.exportUpload(ctx, actor, host, id, false)
}
func (repository *FileStore) BeginExportScan(ctx context.Context, actor files.Actor, host files.HostBinding, id string) (files.Record, error) {
	return repository.exportUpload(ctx, actor, host, id, true)
}

func (repository *FileStore) exportUpload(ctx context.Context, actor files.Actor, host files.HostBinding, id string, commit bool) (files.Record, error) {
	if !grantUUIDPattern.MatchString(id) {
		return files.Record{}, files.ErrAccess
	}
	tx, err := repository.database.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	defer tx.Rollback()
	record, err := loadFile(ctx, tx, id, "for update of f,t")
	if errors.Is(err, sql.ErrNoRows) {
		return files.Record{}, files.ErrAccess
	}
	if err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	if _, err := authorizeExportOwner(ctx, tx, actor, record, true); err != nil {
		return files.Record{}, err
	}
	origin, err := loadExportOrigin(ctx, tx, record)
	if err != nil {
		return files.Record{}, err
	}
	if !sameFileHost(origin.host, host) {
		return files.Record{}, files.ErrAccess
	}
	if _, _, err := hostFileBinding(ctx, tx, origin.host); err != nil {
		return files.Record{}, err
	}
	if commit && origin.uploaded.Valid {
		if err := tx.Commit(); err != nil {
			return files.Record{}, files.ErrUnavailable
		}
		return record, nil
	}
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return files.Record{}, err
	}
	if record.State != "uploading" || !origin.expires.After(now) || !record.UploadExpiresAt.After(now) || !record.ExpiresAt.After(now) {
		return files.Record{}, files.ErrStale
	}
	if commit {
		// The current Host's durable attestation ends source admission. Scanning
		// may finish while the Host is offline; current device/grant authority is
		// still rechecked for every worker lease and final publication.
		record.State, record.ExpiresAt = "scanning", minTime(record.RetainUntil, now.Add(repository.limits.AbandonAfter))
		if _, err := tx.ExecContext(ctx, `update files set state='scanning',expires_at=$2 where id=$1`, id, record.ExpiresAt); err != nil {
			return files.Record{}, files.ErrUnavailable
		}
		if _, err := tx.ExecContext(ctx, `update file_exports set uploaded_at=clock_timestamp() where file_id=$1`, id); err != nil {
			return files.Record{}, files.ErrUnavailable
		}
		if _, err := tx.ExecContext(ctx, `update file_transfers set scan_ready_at=clock_timestamp(),error_code=null where file_id=$1`, id); err != nil {
			return files.Record{}, files.ErrUnavailable
		}
		if err := fileAudit(ctx, tx, record, "file.export_scan_requested", "success"); err != nil {
			return files.Record{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return files.Record{}, files.ErrUnavailable
	}
	return record, nil
}

// AuthorizeExportDownload never returns a public object URL. Its short lease
// is renewed only while current scope, device proof and scanner policy hold.
func (repository *FileStore) AuthorizeExportDownload(ctx context.Context, actor files.Actor, id, policy string) (files.DownloadPermit, error) {
	if !grantUUIDPattern.MatchString(id) || !validSHA256Hex(policy) {
		return files.DownloadPermit{}, files.ErrAccess
	}
	tx, err := repository.database.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return files.DownloadPermit{}, files.ErrUnavailable
	}
	defer tx.Rollback()
	record, err := loadFile(ctx, tx, id, "for share of f,t")
	if errors.Is(err, sql.ErrNoRows) {
		return files.DownloadPermit{}, files.ErrAccess
	}
	if err != nil {
		return files.DownloadPermit{}, files.ErrUnavailable
	}
	authority, err := authorizeExportOwner(ctx, tx, actor, record, false)
	if err != nil {
		return files.DownloadPermit{}, err
	}
	origin, err := loadExportOrigin(ctx, tx, record)
	if err != nil || !origin.uploaded.Valid {
		if err == nil {
			err = files.ErrAccess
		}
		return files.DownloadPermit{}, err
	}
	if record.State != "clean" || record.CommittedAttempt == "" {
		return files.DownloadPermit{}, files.ErrAccess
	}
	var actual, stored string
	if err := tx.QueryRowContext(ctx, `select t.scanner_policy_sha256,f.object_key from file_transfers t join files f on f.id=t.file_id where f.id=$1`, id).Scan(&actual, &stored); err != nil {
		return files.DownloadPermit{}, files.ErrUnavailable
	}
	key, err := record.CommittedKey()
	if err != nil || actual != policy || stored != key.StorageKey() {
		return files.DownloadPermit{}, files.ErrAccess
	}
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return files.DownloadPermit{}, err
	}
	if !record.ExpiresAt.After(now) {
		return files.DownloadPermit{}, files.ErrAccess
	}
	until := minTime(now.Add(5*time.Second), record.ExpiresAt)
	if authority.grantExpires.Valid {
		until = minTime(until, authority.grantExpires.Time)
	}
	if err := tx.Commit(); err != nil {
		return files.DownloadPermit{}, files.ErrUnavailable
	}
	return files.DownloadPermit{File: record, AuthorizedGrantVersion: authority.grantVersion, LeaseUntil: until}, nil
}
