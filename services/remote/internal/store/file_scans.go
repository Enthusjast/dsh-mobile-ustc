package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
)

const fileScanLease = 30 * time.Second
const fileScanMaxAttempts = 3
const fileCleanupGrace = 15 * time.Minute

func fileSingleWrite(result sql.Result, err error) error {
	if err != nil {
		return files.ErrUnavailable
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return files.ErrUnavailable
	}
	return nil
}

// Caller holds the file, attempt and authority rows. Their versions cannot
// change, but their deadlines can elapse during later writes and audit waits.
func checkScanDeadlines(ctx context.Context, tx *sql.Tx, record files.Record, grant sql.NullTime, deadlines ...time.Time) error {
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return err
	}
	if grant.Valid && !grant.Time.After(now) {
		return files.ErrAccess
	}
	if !record.ExpiresAt.After(now) || !record.RetainUntil.After(now) {
		return files.ErrStale
	}
	for _, deadline := range deadlines {
		if !deadline.After(now) {
			return files.ErrStale
		}
	}
	return nil
}

func authorizeBoundFile(ctx context.Context, transaction *sql.Tx, record files.Record) (fileAuthority, error) {
	if record.Direction == "from_host" {
		return authorizeBoundExport(ctx, transaction, record)
	}
	var issuer, subject string
	if err := transaction.QueryRowContext(ctx, `select issuer,subject from users where id=$1`, record.UploaderID).Scan(&issuer, &subject); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fileAuthority{}, files.ErrAccess
		}
		return fileAuthority{}, files.ErrUnavailable
	}
	actor := files.Actor{Issuer: issuer, Subject: subject, DeviceID: record.DeviceID, ProofKeyJKT: record.ProofKeyJKT}
	authority, err := authorizeFile(ctx, transaction, actor, record.RuntimeID, record.SessionID, true)
	if err != nil {
		return authority, err
	}
	return authority, verifyFileOwner(record, authority, actor, true)
}

func fileSystemAudit(ctx context.Context, transaction *sql.Tx, record files.Record, action, result string) error {
	metadata, _ := json.Marshal(map[string]any{"file_id": record.ID, "size_bytes": record.SizeBytes, "sha256": record.SHA256, "state": record.State, "error_code": record.ErrorCode})
	return fileSingleWrite(transaction.ExecContext(ctx, `insert into audit_log(org_id,actor_type,actor_id,device_id,runtime_id,session_id,action,result,metadata)
	 values($1,'system','file-service',$2,$3,$4,$5,$6,$7::jsonb)`, record.OrganizationID, record.DeviceID, record.RuntimeID, record.SessionID, action, result, string(metadata)))
}

func terminalFile(ctx context.Context, transaction *sql.Tx, record files.Record, code string) error {
	record.State, record.ErrorCode = "rejected", code
	if err := fileSingleWrite(transaction.ExecContext(ctx, `update files set state='rejected' where id=$1`, record.ID)); err != nil {
		return files.ErrUnavailable
	}
	if err := fileSingleWrite(transaction.ExecContext(ctx, `update file_transfers set error_code=$2 where file_id=$1`, record.ID, code)); err != nil {
		return files.ErrUnavailable
	}
	if _, err := transaction.ExecContext(ctx, `update file_scan_attempts set state='abandoned',finished_at=clock_timestamp() where file_id=$1 and state='active'`, record.ID); err != nil {
		return files.ErrUnavailable
	}
	if _, err := transaction.ExecContext(ctx, `update file_objects set cleanup_after=least(cleanup_after,greatest(clock_timestamp()+interval '15 minutes',$2::timestamptz+interval '15 minutes')) where file_id=$1`, record.ID, record.UploadExpiresAt); err != nil {
		return files.ErrUnavailable
	}
	return fileSystemAudit(ctx, transaction, record, "file.scan_rejected", "denied")
}

// ClaimScan serializes on the file, retires expired attempts and records the
// unique candidate key before any network write. A crash cannot lose its GC key.
func (repository *FileStore) ClaimScan(ctx context.Context, policy string) (*files.ScanClaim, error) {
	if !validSHA256Hex(policy) {
		return nil, files.ErrInvalid
	}
	transaction, err := repository.database.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, files.ErrUnavailable
	}
	defer transaction.Rollback()
	record, err := scanFile(transaction.QueryRowContext(ctx, `select `+fileColumns+` from files f join file_transfers t on t.file_id=f.id
	 where f.state='scanning' and f.direction in ('to_host','from_host') and f.expires_at>clock_timestamp() and t.scan_ready_at<=clock_timestamp()
	 and not exists(select 1 from file_scan_attempts a where a.file_id=f.id and a.state='active' and a.lease_until>clock_timestamp())
	 order by t.scan_ready_at,f.id limit 1 for update of f,t skip locked`))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, files.ErrUnavailable
	}
	now, err := databaseTime(ctx, transaction)
	if err != nil {
		return nil, err
	}
	var active sql.NullTime
	if err := transaction.QueryRowContext(ctx, `select max(lease_until) from file_scan_attempts where file_id=$1 and state='active'`, record.ID).Scan(&active); err != nil {
		return nil, files.ErrUnavailable
	}
	if active.Valid && active.Time.After(now) {
		return nil, nil
	}
	var attempts int
	if err := transaction.QueryRowContext(ctx, `select scan_attempts from file_transfers where file_id=$1`, record.ID).Scan(&attempts); err != nil {
		return nil, files.ErrUnavailable
	}
	authority, err := authorizeBoundFile(ctx, transaction, record)
	if err != nil && !errors.Is(err, files.ErrAccess) {
		return nil, err
	}
	if errors.Is(err, files.ErrAccess) || attempts >= fileScanMaxAttempts {
		code := "scan_unavailable"
		if errors.Is(err, files.ErrAccess) {
			code = "access_revoked"
		}
		if err := terminalFile(ctx, transaction, record, code); err != nil {
			return nil, err
		}
		if err := transaction.Commit(); err != nil {
			return nil, files.ErrUnavailable
		}
		return nil, nil
	}
	now, err = databaseTime(ctx, transaction)
	if err != nil {
		return nil, err
	}
	if !record.ExpiresAt.After(now) || !record.RetainUntil.After(now) {
		return nil, files.ErrStale
	}
	until := now.Add(fileScanLease)
	if record.ExpiresAt.Before(until) {
		until = record.ExpiresAt
	}
	if record.RetainUntil.Before(until) {
		until = record.RetainUntil
	}
	if authority.grantExpires.Valid && authority.grantExpires.Time.Before(until) {
		until = authority.grantExpires.Time
	}
	if !until.After(now) {
		return nil, files.ErrAccess
	}
	if _, err := transaction.ExecContext(ctx, `update file_objects set cleanup_after=least(cleanup_after,clock_timestamp()+interval '15 minutes')
	 where file_id=$1 and kind='objects' and attempt_id in(select id from file_scan_attempts where file_id=$1 and state='active')`, record.ID); err != nil {
		return nil, files.ErrUnavailable
	}
	if _, err := transaction.ExecContext(ctx, `update file_scan_attempts set state='abandoned',finished_at=clock_timestamp() where file_id=$1 and state='active'`, record.ID); err != nil {
		return nil, files.ErrUnavailable
	}
	attempt, err := fileUUID()
	if err != nil {
		return nil, err
	}
	lease, err := fileUUID()
	if err != nil {
		return nil, err
	}
	claim := files.ScanClaim{File: record, AttemptID: attempt, LeaseID: lease, PolicySHA256: policy, LeaseUntil: until}
	key, err := claim.Key()
	if err != nil {
		return nil, files.ErrUnavailable
	}
	if err := transaction.QueryRowContext(ctx, `insert into file_scan_attempts(id,file_id,lease_id,lease_until,scanner_policy_sha256,state) values($1,$2,$3,$4,$5,'active') returning lease_until`, attempt, record.ID, lease, until, policy).Scan(&claim.LeaseUntil); err != nil {
		return nil, files.ErrUnavailable
	}
	if err := fileSingleWrite(transaction.ExecContext(ctx, `insert into file_objects(file_id,kind,attempt_id,object_key,cleanup_after) values($1,'objects',$2,$3,$4)`, record.ID, attempt, key.StorageKey(), record.ExpiresAt)); err != nil {
		return nil, files.ErrUnavailable
	}
	if err := fileSingleWrite(transaction.ExecContext(ctx, `update file_transfers set scan_attempts=scan_attempts+1,error_code=null where file_id=$1`, record.ID)); err != nil {
		return nil, files.ErrUnavailable
	}
	if err := checkScanDeadlines(ctx, transaction, record, authority.grantExpires, claim.LeaseUntil); err != nil {
		return nil, err
	}
	if err := transaction.Commit(); err != nil {
		return nil, files.ErrUnavailable
	}
	return &claim, nil
}

func lockScan(ctx context.Context, transaction *sql.Tx, claim files.ScanClaim) (files.Record, time.Time, string, error) {
	if !grantUUIDPattern.MatchString(claim.File.ID) || !grantUUIDPattern.MatchString(claim.AttemptID) || !grantUUIDPattern.MatchString(claim.LeaseID) || !validSHA256Hex(claim.PolicySHA256) {
		return files.Record{}, time.Time{}, "", files.ErrStale
	}
	record, err := loadFile(ctx, transaction, claim.File.ID, "for update of f,t")
	if errors.Is(err, sql.ErrNoRows) {
		return record, time.Time{}, "", files.ErrStale
	}
	if err != nil {
		return record, time.Time{}, "", files.ErrUnavailable
	}
	var until time.Time
	var state string
	err = transaction.QueryRowContext(ctx, `select lease_until,state from file_scan_attempts where id=$1 and file_id=$2 and lease_id=$3 and scanner_policy_sha256=$4 for update`, claim.AttemptID, record.ID, claim.LeaseID, claim.PolicySHA256).Scan(&until, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return record, until, state, files.ErrStale
	}
	if err != nil {
		return record, until, state, files.ErrUnavailable
	}
	if claim.File.Direction != record.Direction || claim.File.RequestSHA256 != record.RequestSHA256 || claim.File.OrganizationID != record.OrganizationID || claim.File.SessionID != record.SessionID || claim.File.RuntimeID != record.RuntimeID {
		return record, until, state, files.ErrStale
	}
	return record, until, state, nil
}

func activeScan(ctx context.Context, transaction *sql.Tx, record files.Record, until time.Time, state string) (time.Time, error) {
	now, err := databaseTime(ctx, transaction)
	if err != nil {
		return now, err
	}
	if record.State != "scanning" || state != "active" || !until.After(now) || !record.ExpiresAt.After(now) || !record.RetainUntil.After(now) {
		return now, files.ErrStale
	}
	return now, nil
}

func (repository *FileStore) RenewScan(ctx context.Context, claim files.ScanClaim) (time.Time, error) {
	transaction, err := repository.database.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return time.Time{}, files.ErrUnavailable
	}
	defer transaction.Rollback()
	record, until, state, err := lockScan(ctx, transaction, claim)
	if err != nil {
		return time.Time{}, err
	}
	authority, err := authorizeBoundFile(ctx, transaction, record)
	if err != nil {
		return time.Time{}, err
	}
	now, err := activeScan(ctx, transaction, record, until, state)
	if err != nil {
		return time.Time{}, err
	}
	previousLease := until
	until = now.Add(fileScanLease)
	if record.ExpiresAt.Before(until) {
		until = record.ExpiresAt
	}
	if record.RetainUntil.Before(until) {
		until = record.RetainUntil
	}
	if authority.grantExpires.Valid && authority.grantExpires.Time.Before(until) {
		until = authority.grantExpires.Time
	}
	if err := transaction.QueryRowContext(ctx, `update file_scan_attempts set lease_until=$2 where id=$1 returning lease_until`, claim.AttemptID, until).Scan(&until); err != nil {
		return time.Time{}, files.ErrUnavailable
	}
	if err := checkScanDeadlines(ctx, transaction, record, authority.grantExpires, previousLease, until); err != nil {
		return time.Time{}, err
	}
	if err := transaction.Commit(); err != nil {
		return time.Time{}, files.ErrUnavailable
	}
	return until, nil
}

func (repository *FileStore) CompleteScan(ctx context.Context, claim files.ScanClaim) error {
	transaction, err := repository.database.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return files.ErrUnavailable
	}
	defer transaction.Rollback()
	record, until, state, err := lockScan(ctx, transaction, claim)
	if err != nil {
		return err
	}
	if record.State == "clean" && record.CommittedAttempt == claim.AttemptID && state == "clean" {
		if err := transaction.Commit(); err != nil {
			return files.ErrUnavailable
		}
		return nil
	}
	authority, err := authorizeBoundFile(ctx, transaction, record)
	if err != nil {
		return err
	}
	if _, err := activeScan(ctx, transaction, record, until, state); err != nil {
		return err
	}
	actual := claim
	actual.File = record
	key, err := actual.Key()
	if err != nil {
		return files.ErrUnavailable
	}
	if err := fileSingleWrite(transaction.ExecContext(ctx, `update files set state='clean',object_key=$2,expires_at=$3 where id=$1`, record.ID, key.StorageKey(), record.RetainUntil)); err != nil {
		return files.ErrUnavailable
	}
	if err := fileSingleWrite(transaction.ExecContext(ctx, `update file_transfers set committed_attempt_id=$2,scanner_policy_sha256=$3,error_code=null where file_id=$1`, record.ID, claim.AttemptID, claim.PolicySHA256)); err != nil {
		return files.ErrUnavailable
	}
	if err := fileSingleWrite(transaction.ExecContext(ctx, `update file_scan_attempts set state='clean',finished_at=clock_timestamp() where id=$1`, claim.AttemptID)); err != nil {
		return files.ErrUnavailable
	}
	if err := fileSingleWrite(transaction.ExecContext(ctx, `update file_objects set cleanup_after=$3 where file_id=$1 and kind='objects' and attempt_id=$2`, record.ID, claim.AttemptID, record.RetainUntil)); err != nil {
		return files.ErrUnavailable
	}
	if _, err := transaction.ExecContext(ctx, `update file_objects set cleanup_after=least(cleanup_after,$2::timestamptz+interval '15 minutes') where file_id=$1 and kind='quarantine'`, record.ID, record.UploadExpiresAt); err != nil {
		return files.ErrUnavailable
	}
	record.State = "clean"
	if err := fileSystemAudit(ctx, transaction, record, "file.scan_clean", "success"); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"file_id": record.ID, "runtime_id": record.RuntimeID, "session_id": record.SessionID})
	// Kept pending until the file-capable Relay consumer is configured. The
	// generic control worker filters its own topics and cannot discard this.
	topic := "file.clean"
	if record.Direction == "from_host" {
		topic = "file.export.clean"
	}
	if err := fileSingleWrite(transaction.ExecContext(ctx, `insert into control_outbox(topic,payload) values($1,$2::jsonb)`, topic, string(payload))); err != nil {
		return files.ErrUnavailable
	}
	// record.ExpiresAt is the original scanning deadline, even though the
	// UPDATE now carries the longer retention deadline. Do not revive a scan.
	if err := checkScanDeadlines(ctx, transaction, record, authority.grantExpires, until); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return files.ErrUnavailable
	}
	return nil
}

func (repository *FileStore) FailScan(ctx context.Context, claim files.ScanClaim, code string, retry bool) error {
	if code != "integrity_mismatch" && code != "content_rejected" && code != "scan_unavailable" && code != "storage_unavailable" && code != "access_revoked" {
		return files.ErrInvalid
	}
	transaction, err := repository.database.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return files.ErrUnavailable
	}
	defer transaction.Rollback()
	record, until, state, err := lockScan(ctx, transaction, claim)
	if err != nil {
		return err
	}
	if _, err := activeScan(ctx, transaction, record, until, state); err != nil {
		return err
	}
	var attempts int
	if err := transaction.QueryRowContext(ctx, `select scan_attempts from file_transfers where file_id=$1`, record.ID).Scan(&attempts); err != nil {
		return files.ErrUnavailable
	}
	if err := fileSingleWrite(transaction.ExecContext(ctx, `update file_scan_attempts set state='failed',finished_at=clock_timestamp() where id=$1`, claim.AttemptID)); err != nil {
		return files.ErrUnavailable
	}
	if err := fileSingleWrite(transaction.ExecContext(ctx, `update file_objects set cleanup_after=least(cleanup_after,clock_timestamp()+interval '15 minutes') where file_id=$1 and kind='objects' and attempt_id=$2`, record.ID, claim.AttemptID)); err != nil {
		return files.ErrUnavailable
	}
	if retry && attempts < fileScanMaxAttempts {
		if err := fileSingleWrite(transaction.ExecContext(ctx, `update file_transfers set error_code=$2,scan_ready_at=clock_timestamp()+($3::bigint*interval '5 seconds') where file_id=$1`, record.ID, code, attempts)); err != nil {
			return files.ErrUnavailable
		}
		record.ErrorCode = code
		if err := fileSystemAudit(ctx, transaction, record, "file.scan_deferred", "unavailable"); err != nil {
			return err
		}
	} else {
		if err := terminalFile(ctx, transaction, record, code); err != nil {
			return err
		}
	}
	// Failure reports may record access_revoked; they do not need a live grant.
	// They still belong to the original, unexpired scan lease and file window.
	if err := checkScanDeadlines(ctx, transaction, record, sql.NullTime{}, until); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return files.ErrUnavailable
	}
	return nil
}
