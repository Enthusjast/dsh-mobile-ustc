package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var ErrApprovalRetentionInvalid = errors.New("store: invalid approval evidence retention request")
var ErrApprovalRetentionConflict = errors.New("store: approval evidence retention operation conflicts")

type ApprovalEvidenceRetentionRequest struct {
	OperationID, ApprovalID, DatabaseEpoch string
	RetentionYears                         int
}

func (request ApprovalEvidenceRetentionRequest) Valid() bool {
	return grantUUIDPattern.MatchString(request.OperationID) && grantUUIDPattern.MatchString(request.ApprovalID) &&
		grantUUIDPattern.MatchString(request.DatabaseEpoch) && request.RetentionYears >= 2 && request.RetentionYears <= 10
}

type ApprovalEvidenceRetentionResult struct {
	OperationID         string    `json:"operation_id"`
	ApprovalID          string    `json:"approval_id"`
	CurrentEpoch        string    `json:"current_epoch"`
	SourceEpoch         string    `json:"source_epoch"`
	RetentionYears      int       `json:"retention_years"`
	PreviousRetainUntil time.Time `json:"previous_retain_until"`
	RetainUntil         time.Time `json:"retain_until"`
	RecordedAt          time.Time `json:"recorded_at"`
}

const evidenceRetentionColumns = `id::text,approval_id::text,operation_epoch::text,source_epoch::text,retention_years,previous_retain_until,retain_until,recorded_at`

func scanEvidenceRetention(row *sql.Row) (ApprovalEvidenceRetentionResult, error) {
	var result ApprovalEvidenceRetentionResult
	err := row.Scan(&result.OperationID, &result.ApprovalID, &result.CurrentEpoch, &result.SourceEpoch, &result.RetentionYears,
		&result.PreviousRetainUntil, &result.RetainUntil, &result.RecordedAt)
	result.PreviousRetainUntil, result.RetainUntil, result.RecordedAt = result.PreviousRetainUntil.UTC(), result.RetainUntil.UTC(), result.RecordedAt.UTC()
	return result, err
}

// ExtendApprovalEvidenceRetention is an offline administrative operation. It
// never rewrites a signed binding, recreates material, or grants execution.
func (postgres *Postgres) ExtendApprovalEvidenceRetention(ctx context.Context, request ApprovalEvidenceRetentionRequest) (ApprovalEvidenceRetentionResult, error) {
	if !request.Valid() {
		return ApprovalEvidenceRetentionResult{}, ErrApprovalRetentionInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return ApprovalEvidenceRetentionResult{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `select pg_advisory_xact_lock(hashtextextended('dsh-evidence-retention:'||$1::text,0))`, request.OperationID); err != nil {
		return ApprovalEvidenceRetentionResult{}, ErrDatabaseUnavailable
	}
	if _, err := lockRecoveryReady(ctx, tx, request.DatabaseEpoch); err != nil {
		return ApprovalEvidenceRetentionResult{}, err
	}
	previous, err := scanEvidenceRetention(tx.QueryRowContext(ctx, `select `+evidenceRetentionColumns+` from approval_evidence_retention_extensions where id=$1`, request.OperationID))
	if err == nil {
		if previous.ApprovalID != request.ApprovalID || previous.CurrentEpoch != request.DatabaseEpoch || previous.RetentionYears != request.RetentionYears {
			return ApprovalEvidenceRetentionResult{}, ErrApprovalRetentionConflict
		}
		if tx.Commit() != nil {
			return ApprovalEvidenceRetentionResult{}, ErrDatabaseUnavailable
		}
		return previous, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ApprovalEvidenceRetentionResult{}, ErrDatabaseUnavailable
	}
	var id string
	err = tx.QueryRowContext(ctx, `select approval_id::text from approval_decision_evidence_material where approval_id=$1 for update`, request.ApprovalID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return ApprovalEvidenceRetentionResult{}, ErrApprovalEvidenceUnavailable
	}
	if err != nil {
		return ApprovalEvidenceRetentionResult{}, ErrDatabaseUnavailable
	}
	var source string
	var extends bool
	// A fresh snapshot after the material lock observes every prior extension.
	err = tx.QueryRowContext(ctx, `select e.database_epoch::text,
        (((e.decided_at at time zone 'UTC')+make_interval(years=>$2)) at time zone 'UTC')>
            greatest(e.retain_until,coalesce((select max(retain_until) from approval_evidence_retention_extensions where approval_id=e.approval_id),e.retain_until),clock_timestamp())
        from approval_decision_evidence e where e.approval_id=$1`, request.ApprovalID, request.RetentionYears).Scan(&source, &extends)
	if err != nil {
		return ApprovalEvidenceRetentionResult{}, ErrDatabaseUnavailable
	}
	if err := checkExportRecoveryPath(ctx, tx, source, request.DatabaseEpoch); err != nil {
		return ApprovalEvidenceRetentionResult{}, err
	}
	if !extends {
		return ApprovalEvidenceRetentionResult{}, ErrApprovalRetentionConflict
	}
	result, err := scanEvidenceRetention(tx.QueryRowContext(ctx, `insert into approval_evidence_retention_extensions(id,approval_id,operation_epoch,retention_years)
        values($1,$2,$3,$4) returning `+evidenceRetentionColumns, request.OperationID, request.ApprovalID, request.DatabaseEpoch, request.RetentionYears))
	if err != nil {
		return ApprovalEvidenceRetentionResult{}, ErrDatabaseUnavailable
	}
	if result.OperationID != request.OperationID || result.ApprovalID != request.ApprovalID || result.CurrentEpoch != request.DatabaseEpoch ||
		result.SourceEpoch != source || result.RetentionYears != request.RetentionYears || !result.RetainUntil.After(result.PreviousRetainUntil) {
		return ApprovalEvidenceRetentionResult{}, ErrDatabaseUnavailable
	}
	if tx.Commit() != nil {
		return ApprovalEvidenceRetentionResult{}, ErrDatabaseUnavailable
	}
	return result, nil
}
