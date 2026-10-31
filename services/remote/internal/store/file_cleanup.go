package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
)

func (repository *FileStore) Expire(ctx context.Context, limit int) (int, error) {
	if limit < 1 || limit > 128 {
		return 0, files.ErrInvalid
	}
	transaction, err := repository.database.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return 0, files.ErrUnavailable
	}
	defer transaction.Rollback()
	rows, err := transaction.QueryContext(ctx, `select `+fileColumns+` from files f join file_transfers t on t.file_id=f.id where f.state<>'expired' and f.expires_at<=clock_timestamp()
	 order by f.expires_at,f.id limit $1 for update of f,t skip locked`, limit)
	if err != nil {
		return 0, files.ErrUnavailable
	}
	var records []files.Record
	for rows.Next() {
		record, err := scanFile(rows)
		if err != nil {
			rows.Close()
			return 0, files.ErrUnavailable
		}
		records = append(records, record)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, files.ErrUnavailable
	}
	for _, record := range records {
		if err := fileSingleWrite(transaction.ExecContext(ctx, `update files set state='expired' where id=$1`, record.ID)); err != nil {
			return 0, files.ErrUnavailable
		}
		if err := fileSingleWrite(transaction.ExecContext(ctx, `update file_transfers set error_code='expired' where file_id=$1`, record.ID)); err != nil {
			return 0, files.ErrUnavailable
		}
		if _, err := transaction.ExecContext(ctx, `update file_scan_attempts set state='abandoned',finished_at=clock_timestamp() where file_id=$1 and state='active'`, record.ID); err != nil {
			return 0, files.ErrUnavailable
		}
		if _, err := transaction.ExecContext(ctx, `update file_objects set cleanup_after=least(cleanup_after,greatest(clock_timestamp()+interval '15 minutes',$2::timestamptz+interval '15 minutes')) where file_id=$1`, record.ID, record.UploadExpiresAt); err != nil {
			return 0, files.ErrUnavailable
		}
		record.State, record.ErrorCode = "expired", "expired"
		if err := fileSystemAudit(ctx, transaction, record, "file.expired", "success"); err != nil {
			return 0, err
		}
	}
	if err := transaction.Commit(); err != nil {
		return 0, files.ErrUnavailable
	}
	return len(records), nil
}

const deletionEligibilitySQL = `o.cleanup_after<=clock_timestamp() and (o.lease_until is null or o.lease_until<=clock_timestamp())
 and (f.state in ('expired','rejected') or o.kind='quarantine'
 or (o.attempt_id is distinct from t.committed_attempt_id and not exists(
 select 1 from file_scan_attempts a where a.id=o.attempt_id and a.state='active' and a.lease_until>clock_timestamp())))`

func checkDeletionDeadline(ctx context.Context, tx *sql.Tx, until time.Time) error {
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return err
	}
	if !until.After(now) {
		return files.ErrStale
	}
	return nil
}

func (repository *FileStore) ClaimDeletion(ctx context.Context) (*files.DeletionClaim, error) {
	transaction, err := repository.database.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, files.ErrUnavailable
	}
	defer transaction.Rollback()
	// Pin the file before the object, matching scan and acknowledgement lock
	// order. An old snapshot must not turn a valid, still-committing renewal's
	// candidate into deletion authority.
	var fileID string
	err = transaction.QueryRowContext(ctx, `select f.id::text from files f
	 join file_transfers t on t.file_id=f.id join file_objects o on o.file_id=f.id
	 where `+deletionEligibilitySQL+` order by o.cleanup_after,o.file_id,o.kind,o.attempt_id limit 1
	 for update of f,t skip locked`).Scan(&fileID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, files.ErrUnavailable
	}
	var claim files.DeletionClaim
	var stored string
	// This separate READ COMMITTED statement sees changes committed while the
	// file claim was selected. Normal producers now cannot change eligibility
	// until this transaction releases the file.
	err = transaction.QueryRowContext(ctx, `select f.id::text,t.org_id::text,f.session_id::text,o.kind,o.attempt_id::text,o.object_key
	 from file_objects o join files f on f.id=o.file_id join file_transfers t on t.file_id=f.id
	 where f.id=$1 and `+deletionEligibilitySQL+`
	 order by o.cleanup_after,o.file_id,o.kind,o.attempt_id limit 1 for update of o skip locked`, fileID).Scan(&claim.FileID, &claim.OrganizationID, &claim.SessionID, &claim.Kind, &claim.AttemptID, &stored)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, files.ErrUnavailable
	}
	key, err := claim.Key()
	if err != nil || key.StorageKey() != stored {
		return nil, files.ErrUnavailable
	}
	claim.LeaseID, err = fileUUID()
	if err != nil {
		return nil, err
	}
	now, err := databaseTime(ctx, transaction)
	if err != nil {
		return nil, err
	}
	claim.LeaseUntil = now.Add(fileScanLease)
	if err := transaction.QueryRowContext(ctx, `update file_objects set lease_id=$4,lease_until=$5 where file_id=$1 and kind=$2 and attempt_id=$3 returning lease_until`, claim.FileID, claim.Kind, claim.AttemptID, claim.LeaseID, claim.LeaseUntil).Scan(&claim.LeaseUntil); err != nil {
		return nil, files.ErrUnavailable
	}
	if err := checkDeletionDeadline(ctx, transaction, claim.LeaseUntil); err != nil {
		return nil, err
	}
	if err := transaction.Commit(); err != nil {
		return nil, files.ErrUnavailable
	}
	return &claim, nil
}

// Cleanup acknowledgements follow actual object-service deletion. Expiry alone
// does not free quota. Completed keys remain scheduled for daily reconciliation
// because an old quarantine PUT capability can outlive an earlier delete.
func (repository *FileStore) CompleteDeletion(ctx context.Context, claim files.DeletionClaim, success bool) error {
	key, err := claim.Key()
	if err != nil || !grantUUIDPattern.MatchString(claim.LeaseID) {
		return files.ErrStale
	}
	transaction, err := repository.database.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return files.ErrUnavailable
	}
	defer transaction.Rollback()
	record, err := loadFile(ctx, transaction, claim.FileID, "for update of f,t")
	if errors.Is(err, sql.ErrNoRows) {
		return files.ErrStale
	}
	if err != nil {
		return files.ErrUnavailable
	}
	if record.OrganizationID != claim.OrganizationID || record.SessionID != claim.SessionID {
		return files.ErrStale
	}
	var stored string
	var until time.Time
	err = transaction.QueryRowContext(ctx, `select object_key,lease_until from file_objects where file_id=$1 and kind=$2 and attempt_id=$3 and lease_id=$4 for update`, claim.FileID, claim.Kind, claim.AttemptID, claim.LeaseID).Scan(&stored, &until)
	if errors.Is(err, sql.ErrNoRows) {
		return files.ErrStale
	}
	if err != nil {
		return files.ErrUnavailable
	}
	now, err := databaseTime(ctx, transaction)
	if err != nil {
		return err
	}
	if !until.After(now) || stored != key.StorageKey() {
		return files.ErrStale
	}
	if !success {
		if err := fileSingleWrite(transaction.ExecContext(ctx, `update file_objects set lease_id=null,lease_until=null,deleted_at=null,cleanup_after=clock_timestamp()+interval '1 minute' where file_id=$1 and kind=$2 and attempt_id=$3`, claim.FileID, claim.Kind, claim.AttemptID)); err != nil {
			return files.ErrUnavailable
		}
	} else {
		if err := fileSingleWrite(transaction.ExecContext(ctx, `update file_objects set lease_id=null,lease_until=null,deleted_at=clock_timestamp(),cleanup_after=clock_timestamp()+interval '1 day' where file_id=$1 and kind=$2 and attempt_id=$3`, claim.FileID, claim.Kind, claim.AttemptID)); err != nil {
			return files.ErrUnavailable
		}
		if record.State == "expired" || record.State == "rejected" {
			var released sql.NullTime
			var pending bool
			if err := transaction.QueryRowContext(ctx, `select quota_released_at,exists(select 1 from file_objects o where o.file_id=$1 and o.deleted_at is null) from file_transfers where file_id=$1`, record.ID).Scan(&released, &pending); err != nil {
				return files.ErrUnavailable
			}
			if !released.Valid && !pending {
				quotas, err := repository.lockQuotas(ctx, transaction, fileAuthority{org: record.OrganizationID, user: record.UploaderID}, record.SessionID)
				if err != nil {
					return err
				}
				for _, quota := range quotas {
					if quota.bytes < record.SizeBytes || quota.count < 1 {
						return files.ErrUnavailable
					}
					if err := fileSingleWrite(transaction.ExecContext(ctx, `update file_quota_usage set reserved_bytes=reserved_bytes-$4,reserved_files=reserved_files-1 where org_id=$1 and kind=$2 and bucket_id=$3`, record.OrganizationID, quota.kind, quota.id, record.SizeBytes)); err != nil {
						return files.ErrUnavailable
					}
				}
				if err := fileSingleWrite(transaction.ExecContext(ctx, `update file_transfers set quota_released_at=clock_timestamp() where file_id=$1`, record.ID)); err != nil {
					return files.ErrUnavailable
				}
				if err := fileSystemAudit(ctx, transaction, record, "file.quota_released", "success"); err != nil {
					return err
				}
			}
		}
	}
	if err := checkDeletionDeadline(ctx, transaction, until); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return files.ErrUnavailable
	}
	return nil
}
