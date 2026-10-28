package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"dsh-mobile-ustc/services/remote/internal/approval"
	"dsh-mobile-ustc/services/remote/internal/coldarchive"
)

var ErrApprovalEvidenceInvalid = errors.New("store: retained approval evidence failed verification")
var ErrApprovalEvidenceUnavailable = errors.New("store: retained approval evidence is unavailable")

type ApprovalEvidenceResult struct {
	ApprovalID        string    `json:"approval_id"`
	SourceEpoch       string    `json:"source_epoch"`
	CurrentEpoch      string    `json:"current_epoch"`
	Decision          string    `json:"decision"`
	DecidedAt         time.Time `json:"decided_at"`
	VerifiedAt        time.Time `json:"verified_at"`
	Verification      string    `json:"verification"`
	FingerprintSource string    `json:"fingerprint_source"`
}

func approvalEvidenceAudit(ctx context.Context, tx *sql.Tx, id, current, source, result string) (time.Time, error) {
	metadata, _ := json.Marshal(map[string]string{"approval_id": id, "current_epoch": current, "source_epoch": source})
	var recorded time.Time
	if err := tx.QueryRowContext(ctx, `insert into audit_log(actor_type,actor_id,action,result,metadata)
	 values('system',current_user,'approval.evidence.verify',$1,$2::jsonb||jsonb_build_object('db_session_user',session_user)) returning ts`, result, string(metadata)).Scan(&recorded); err != nil {
		return time.Time{}, ErrDatabaseUnavailable
	}
	return recorded.UTC(), nil
}

// VerifyApprovalEvidence is a local administrative read, never an execution
// authorization. Successful, invalid and unavailable results are audited.
func (postgres *Postgres) VerifyApprovalEvidence(ctx context.Context, id, currentEpoch string) (ApprovalEvidenceResult, error) {
	if !grantUUIDPattern.MatchString(id) || !grantUUIDPattern.MatchString(currentEpoch) {
		return ApprovalEvidenceResult{}, ErrApprovalEvidenceInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return ApprovalEvidenceResult{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if _, err := lockRecoveryReady(ctx, tx, currentEpoch); err != nil {
		return ApprovalEvidenceResult{}, err
	}
	result := ApprovalEvidenceResult{ApprovalID: id, CurrentEpoch: currentEpoch, Verification: "signature_and_record"}
	var record approval.HistoricalDecisionEvidence
	var fingerprint, provenance sql.NullString
	err = tx.QueryRowContext(ctx, `select e.database_epoch::text,e.runtime_id::text,e.runtime_epoch::text,e.session_id::text,e.execution_id::text,e.user_id::text,e.device_id::text,
	 e.key_version,e.approval_key_jkt,e.decision,e.binding_sha256,e.payload_sha256,e.decided_at,f.jws_sha256,f.provenance
	 from approval_decision_evidence e left join approval_evidence_fingerprints f on f.approval_id=e.approval_id where e.approval_id=$1`, id).
		Scan(&result.SourceEpoch, &record.RuntimeID, &record.RuntimeEpoch, &record.SessionID, &record.ExecutionID, &record.UserID, &record.DeviceID,
			&record.KeyVersion, &record.ApprovalKeyJKT, &record.Decision, &record.BindingSHA256, &record.PayloadSHA256, &result.DecidedAt, &fingerprint, &provenance)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := approvalEvidenceAudit(ctx, tx, id, currentEpoch, "", "unavailable"); err != nil {
			return ApprovalEvidenceResult{}, err
		}
		if tx.Commit() != nil {
			return ApprovalEvidenceResult{}, ErrDatabaseUnavailable
		}
		return ApprovalEvidenceResult{}, ErrApprovalEvidenceUnavailable
	}
	if err != nil {
		return ApprovalEvidenceResult{}, ErrDatabaseUnavailable
	}
	if err := checkExportRecoveryPath(ctx, tx, result.SourceEpoch, currentEpoch); err != nil {
		if !errors.Is(err, ErrRecoveryUnavailable) {
			return ApprovalEvidenceResult{}, err
		}
		if _, auditErr := approvalEvidenceAudit(ctx, tx, id, currentEpoch, result.SourceEpoch, "lineage_denied"); auditErr != nil {
			return ApprovalEvidenceResult{}, auditErr
		}
		if tx.Commit() != nil {
			return ApprovalEvidenceResult{}, ErrDatabaseUnavailable
		}
		return ApprovalEvidenceResult{}, ErrRecoveryUnavailable
	}
	if !fingerprint.Valid || !provenance.Valid {
		if _, err := approvalEvidenceAudit(ctx, tx, id, currentEpoch, result.SourceEpoch, "unavailable"); err != nil {
			return ApprovalEvidenceResult{}, err
		}
		if tx.Commit() != nil {
			return ApprovalEvidenceResult{}, ErrDatabaseUnavailable
		}
		return ApprovalEvidenceResult{}, ErrApprovalEvidenceUnavailable
	}
	var compact string
	if err := tx.QueryRowContext(ctx, `select decision_jws,public_jwk::text from approval_decision_evidence_material where approval_id=$1 for share`, id).
		Scan(&compact, &record.PublicJWK); errors.Is(err, sql.ErrNoRows) {
		if _, auditErr := approvalEvidenceAudit(ctx, tx, id, currentEpoch, result.SourceEpoch, "unavailable"); auditErr != nil {
			return ApprovalEvidenceResult{}, auditErr
		}
		if tx.Commit() != nil {
			return ApprovalEvidenceResult{}, ErrDatabaseUnavailable
		}
		return ApprovalEvidenceResult{}, ErrApprovalEvidenceUnavailable
	} else if err != nil {
		return ApprovalEvidenceResult{}, ErrDatabaseUnavailable
	}
	record.ApprovalID = id
	status := "success"
	jwsDigest := sha256.Sum256([]byte(compact))
	if !coldarchive.EqualDigest(hex.EncodeToString(jwsDigest[:]), fingerprint.String) || approval.VerifyHistoricalDecision(compact, record) != nil {
		status = "failure"
	}
	result.Decision, result.DecidedAt = record.Decision, result.DecidedAt.UTC()
	result.FingerprintSource = provenance.String
	result.VerifiedAt, err = approvalEvidenceAudit(ctx, tx, id, currentEpoch, result.SourceEpoch, status)
	if err != nil {
		return ApprovalEvidenceResult{}, err
	}
	if tx.Commit() != nil {
		return ApprovalEvidenceResult{}, ErrDatabaseUnavailable
	}
	if status != "success" {
		return ApprovalEvidenceResult{}, ErrApprovalEvidenceInvalid
	}
	return result, nil
}
