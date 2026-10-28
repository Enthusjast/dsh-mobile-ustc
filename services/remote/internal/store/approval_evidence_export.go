package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"dsh-mobile-ustc/services/remote/internal/coldarchive"
	"dsh-mobile-ustc/services/remote/internal/evidencearchive"
)

var ErrEvidenceExportInvalid = errors.New("store: invalid approval evidence export")
var ErrEvidenceExportConflict = errors.New("store: approval evidence export conflicts")
var ErrEvidenceExportNotFound = errors.New("store: approval evidence export not found")

type EvidenceExportRequest struct {
	ExportID, DomainID, DatabaseEpoch, ApprovalID string
	DestinationFingerprint                        string
	Key                                           *coldarchive.Key
}

func (request EvidenceExportRequest) valid(destination bool) bool {
	return coldarchive.UUID(request.ExportID) && coldarchive.UUID(request.DomainID) && coldarchive.UUID(request.DatabaseEpoch) && coldarchive.UUID(request.ApprovalID) && request.Key != nil && (!destination || validSHA256Hex(request.DestinationFingerprint))
}

type EvidenceExportState struct {
	ExportID               string     `json:"export_id"`
	DomainID               string     `json:"domain_id"`
	OperationEpoch         string     `json:"operation_epoch"`
	ApprovalID             string     `json:"approval_id"`
	KeyID                  string     `json:"key_id"`
	KeyFingerprint         string     `json:"-"`
	DestinationFingerprint string     `json:"-"`
	Salt                   [32]byte   `json:"-"`
	Nonce                  [12]byte   `json:"-"`
	PayloadSHA256          string     `json:"-"`
	ArtifactSHA256         string     `json:"artifact_sha256"`
	ArtifactSize           int        `json:"artifact_size"`
	PreparedAt             time.Time  `json:"prepared_at"`
	State                  string     `json:"state"`
	CompletedAt            *time.Time `json:"completed_at,omitempty"`
}

func (EvidenceExportState) String() string   { return "store.EvidenceExportState" }
func (EvidenceExportState) GoString() string { return "store.EvidenceExportState" }

func lockEvidenceExport(ctx context.Context, tx *sql.Tx, id string) error {
	if _, err := tx.ExecContext(ctx, `select pg_advisory_xact_lock(hashtextextended('dsh-evidence-export:'||$1::text,0))`, id); err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}

func readEvidenceExport(ctx context.Context, tx *sql.Tx, id string) (EvidenceExportState, error) {
	var result EvidenceExportState
	var salt, nonce []byte
	err := tx.QueryRowContext(ctx, `select id::text,domain_id::text,operation_epoch::text,approval_id::text,key_id,key_fingerprint,destination_fingerprint,salt,nonce,
	 payload_sha256,artifact_sha256,artifact_size,prepared_at,state,completed_at from approval_evidence_exports where id=$1`, id).
		Scan(&result.ExportID, &result.DomainID, &result.OperationEpoch, &result.ApprovalID, &result.KeyID, &result.KeyFingerprint, &result.DestinationFingerprint,
			&salt, &nonce, &result.PayloadSHA256, &result.ArtifactSHA256, &result.ArtifactSize, &result.PreparedAt, &result.State, &result.CompletedAt)
	if err != nil {
		return result, err
	}
	if len(salt) != len(result.Salt) || len(nonce) != len(result.Nonce) {
		return EvidenceExportState{}, ErrDatabaseUnavailable
	}
	copy(result.Salt[:], salt)
	copy(result.Nonce[:], nonce)
	result.PreparedAt = result.PreparedAt.UTC()
	if result.CompletedAt != nil {
		value := result.CompletedAt.UTC()
		result.CompletedAt = &value
	}
	return result, nil
}

func checkEvidenceExportBinding(result EvidenceExportState, request EvidenceExportRequest, destination, epoch bool) error {
	fingerprint, err := request.Key.Fingerprint()
	if err != nil {
		return ErrEvidenceExportInvalid
	}
	if result.ExportID != request.ExportID || result.DomainID != request.DomainID || result.ApprovalID != request.ApprovalID || result.KeyID != request.Key.ID() || !coldarchive.EqualDigest(result.KeyFingerprint, fingerprint) ||
		(destination && !coldarchive.EqualDigest(result.DestinationFingerprint, request.DestinationFingerprint)) || (epoch && result.OperationEpoch != request.DatabaseEpoch) {
		return ErrEvidenceExportConflict
	}
	return nil
}

func evidenceExportAudit(ctx context.Context, tx *sql.Tx, action, status string, result EvidenceExportState, currentEpoch string, location ...string) error {
	metadata := map[string]any{"export_id": result.ExportID, "domain_id": result.DomainID, "approval_id": result.ApprovalID, "operation_epoch": result.OperationEpoch,
		"current_epoch": currentEpoch, "key_id": result.KeyID, "artifact_sha256": result.ArtifactSHA256, "artifact_size": result.ArtifactSize}
	if len(location) > 0 {
		metadata["access_location_fingerprint"] = location[0]
	}
	raw, _ := json.Marshal(metadata)
	if _, err := tx.ExecContext(ctx, `insert into audit_log(actor_type,actor_id,action,result,metadata)
	 values('system',current_user,$1,$2,$3::jsonb||jsonb_build_object('db_session_user',session_user))`, action, status, string(raw)); err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}

func evidenceExportSnapshot(ctx context.Context, tx *sql.Tx, request EvidenceExportRequest, prepared time.Time) (evidencearchive.Payload, error) {
	result := evidencearchive.Payload{Format: "dsh-approval-evidence", Version: 1, DomainID: request.DomainID, ExportID: request.ExportID, OperationEpoch: request.DatabaseEpoch,
		KeyID: request.Key.ID(), PreparedAt: prepared.UTC(), Recoveries: []coldarchive.Recovery{}}
	p := &result.Proof
	var fingerprint, provenance sql.NullString
	err := tx.QueryRowContext(ctx, `select e.approval_id::text,e.database_epoch::text,e.runtime_id::text,e.runtime_epoch::text,e.session_id::text,e.execution_id::text,
	 e.user_id::text,e.device_id::text,e.key_version,e.approval_key_jkt,e.decision,e.binding_sha256,e.payload_sha256,e.decided_at,e.retain_until,f.jws_sha256,f.provenance
	 from approval_decision_evidence e left join approval_evidence_fingerprints f on f.approval_id=e.approval_id where e.approval_id=$1`, request.ApprovalID).
		Scan(&p.ApprovalID, &p.SourceEpoch, &p.RuntimeID, &p.RuntimeEpoch, &p.SessionID, &p.ExecutionID, &p.UserID, &p.DeviceID, &p.KeyVersion, &p.ApprovalKeyJKT,
			&p.Decision, &p.BindingSHA256, &p.PayloadSHA256, &p.DecidedAt, &p.RetainUntil, &fingerprint, &provenance)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (!fingerprint.Valid || !provenance.Valid) {
		return evidencearchive.Payload{}, ErrApprovalEvidenceUnavailable
	}
	if err != nil {
		return evidencearchive.Payload{}, ErrDatabaseUnavailable
	}
	if err := checkExportRecoveryPath(ctx, tx, p.SourceEpoch, request.DatabaseEpoch); err != nil {
		return evidencearchive.Payload{}, err
	}
	var publicJWK []byte
	if err := tx.QueryRowContext(ctx, `select decision_jws,public_jwk::text from approval_decision_evidence_material where approval_id=$1 for share`, request.ApprovalID).
		Scan(&p.DecisionJWS, &publicJWK); errors.Is(err, sql.ErrNoRows) {
		return evidencearchive.Payload{}, ErrApprovalEvidenceUnavailable
	} else if err != nil {
		return evidencearchive.Payload{}, ErrDatabaseUnavailable
	}
	p.PublicJWK = json.RawMessage(publicJWK)
	p.JWSSHA256, p.FingerprintSource = fingerprint.String, provenance.String
	p.DecidedAt, p.RetainUntil = p.DecidedAt.UTC(), p.RetainUntil.UTC()
	if p.SourceEpoch != request.DatabaseEpoch {
		rows, err := tx.QueryContext(ctx, `select id::text,source_epoch::text,target_epoch::text,prepared_at,released_at,authority_sha256,
		 case when octet_length(counts::text)<=$1 then counts::text end from remote_recovery_runs where phase='ready' order by id limit 257`, coldarchive.MaxPlaintext)
		if err != nil {
			return evidencearchive.Payload{}, ErrDatabaseUnavailable
		}
		budget := 0
		for rows.Next() {
			var item coldarchive.Recovery
			var raw sql.NullString
			if rows.Scan(&item.ID, &item.SourceEpoch, &item.TargetEpoch, &item.PreparedAt, &item.ReleasedAt, &item.AuthoritySHA256, &raw) != nil {
				_ = rows.Close()
				return evidencearchive.Payload{}, ErrDatabaseUnavailable
			}
			budget += len(raw.String) + 256
			if !raw.Valid || len(result.Recoveries) >= coldarchive.MaxRecoveries || budget > coldarchive.MaxPlaintext {
				_ = rows.Close()
				return evidencearchive.Payload{}, ErrApprovalEvidenceUnavailable
			}
			item.PreparedAt, item.ReleasedAt = item.PreparedAt.UTC(), item.ReleasedAt.UTC()
			item.Counts = json.RawMessage(raw.String)
			result.Recoveries = append(result.Recoveries, item)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return evidencearchive.Payload{}, ErrDatabaseUnavailable
		}
		if err := rows.Close(); err != nil {
			return evidencearchive.Payload{}, ErrDatabaseUnavailable
		}
	}
	evidencearchive.Sort(&result)
	if result.Validate() != nil {
		return evidencearchive.Payload{}, ErrApprovalEvidenceInvalid
	}
	return result, nil
}

func evidenceExportRejected(ctx context.Context, tx *sql.Tx, request EvidenceExportRequest, reason error) error {
	status := "failure"
	if errors.Is(reason, ErrApprovalEvidenceUnavailable) {
		status = "unavailable"
	} else if errors.Is(reason, ErrRecoveryUnavailable) {
		status = "lineage_denied"
	} else if errors.Is(reason, ErrEvidenceExportConflict) {
		status = "conflict"
	} else if !errors.Is(reason, ErrApprovalEvidenceInvalid) {
		return reason
	}
	result := EvidenceExportState{ExportID: request.ExportID, DomainID: request.DomainID, OperationEpoch: request.DatabaseEpoch, ApprovalID: request.ApprovalID, KeyID: request.Key.ID()}
	if err := evidenceExportAudit(ctx, tx, "approval.evidence.export.prepare", status, result, request.DatabaseEpoch, request.DestinationFingerprint); err != nil {
		return err
	}
	if tx.Commit() != nil {
		return ErrDatabaseUnavailable
	}
	return reason
}

// PrepareEvidenceExport authenticates and pins the immutable source before
// returning a single encrypted artifact for durable publication.
func (postgres *Postgres) PrepareEvidenceExport(ctx context.Context, request EvidenceExportRequest) (EvidenceExportState, []byte, error) {
	if !request.valid(true) {
		return EvidenceExportState{}, nil, ErrEvidenceExportInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return EvidenceExportState{}, nil, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if err := lockEvidenceExport(ctx, tx, request.ExportID); err != nil {
		return EvidenceExportState{}, nil, err
	}
	if _, err := lockRecoveryReady(ctx, tx, request.DatabaseEpoch); err != nil {
		return EvidenceExportState{}, nil, err
	}
	previous, err := readEvidenceExport(ctx, tx, request.ExportID)
	if err == nil {
		if err := checkEvidenceExportBinding(previous, request, true, true); err != nil {
			return EvidenceExportState{}, nil, err
		}
		if previous.State == "aborted" {
			return EvidenceExportState{}, nil, ErrEvidenceExportConflict
		}
		if tx.Commit() != nil {
			return EvidenceExportState{}, nil, ErrDatabaseUnavailable
		}
		return previous, nil, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return EvidenceExportState{}, nil, ErrDatabaseUnavailable
	}
	var prepared time.Time
	if err := tx.QueryRowContext(ctx, `select clock_timestamp()`).Scan(&prepared); err != nil {
		return EvidenceExportState{}, nil, ErrDatabaseUnavailable
	}
	prepared = prepared.UTC()
	payload, err := evidenceExportSnapshot(ctx, tx, request, prepared)
	if err != nil {
		return EvidenceExportState{}, nil, evidenceExportRejected(ctx, tx, request, err)
	}
	plain, err := evidencearchive.Encode(payload)
	if err != nil {
		return EvidenceExportState{}, nil, evidenceExportRejected(ctx, tx, request, ErrApprovalEvidenceInvalid)
	}
	defer clear(plain)
	salt, nonce, err := coldarchive.Material()
	if err != nil {
		return EvidenceExportState{}, nil, ErrDatabaseUnavailable
	}
	artifact, err := coldarchive.SealEncoded(request.Key, plain, salt, nonce)
	if err != nil {
		return EvidenceExportState{}, nil, ErrEvidenceExportInvalid
	}
	fingerprint, err := request.Key.Fingerprint()
	if err != nil {
		clear(artifact)
		return EvidenceExportState{}, nil, ErrEvidenceExportInvalid
	}
	result := EvidenceExportState{ExportID: request.ExportID, DomainID: request.DomainID, OperationEpoch: request.DatabaseEpoch, ApprovalID: request.ApprovalID, KeyID: request.Key.ID(),
		KeyFingerprint: fingerprint, DestinationFingerprint: request.DestinationFingerprint, Salt: salt, Nonce: nonce, PayloadSHA256: coldarchive.Digest(plain),
		ArtifactSHA256: coldarchive.Digest(artifact), ArtifactSize: len(artifact), PreparedAt: prepared, State: "prepared"}
	if _, err := tx.ExecContext(ctx, `insert into approval_evidence_exports(id,domain_id,operation_epoch,approval_id,key_id,key_fingerprint,destination_fingerprint,salt,nonce,payload_sha256,artifact_sha256,artifact_size,prepared_at,state)
	 values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'prepared')`, result.ExportID, result.DomainID, result.OperationEpoch, result.ApprovalID, result.KeyID, result.KeyFingerprint,
		result.DestinationFingerprint, result.Salt[:], result.Nonce[:], result.PayloadSHA256, result.ArtifactSHA256, result.ArtifactSize, result.PreparedAt); err != nil {
		clear(artifact)
		return EvidenceExportState{}, nil, ErrDatabaseUnavailable
	}
	if err := evidenceExportAudit(ctx, tx, "approval.evidence.export.prepared", "success", result, request.DatabaseEpoch, request.DestinationFingerprint); err != nil {
		clear(artifact)
		return EvidenceExportState{}, nil, err
	}
	if tx.Commit() != nil {
		clear(artifact)
		return EvidenceExportState{}, nil, ErrDatabaseUnavailable
	}
	return result, artifact, nil
}

func (postgres *Postgres) RebuildEvidenceExport(ctx context.Context, request EvidenceExportRequest) (EvidenceExportState, []byte, error) {
	if !request.valid(true) {
		return EvidenceExportState{}, nil, ErrEvidenceExportInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return EvidenceExportState{}, nil, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if err := lockEvidenceExport(ctx, tx, request.ExportID); err != nil {
		return EvidenceExportState{}, nil, err
	}
	if _, err := lockRecoveryReady(ctx, tx, request.DatabaseEpoch); err != nil {
		return EvidenceExportState{}, nil, err
	}
	result, err := readEvidenceExport(ctx, tx, request.ExportID)
	if errors.Is(err, sql.ErrNoRows) {
		return EvidenceExportState{}, nil, ErrEvidenceExportNotFound
	}
	if err != nil {
		return EvidenceExportState{}, nil, ErrDatabaseUnavailable
	}
	if err := checkEvidenceExportBinding(result, request, true, true); err != nil {
		return EvidenceExportState{}, nil, err
	}
	if result.State == "aborted" {
		return EvidenceExportState{}, nil, ErrEvidenceExportConflict
	}
	payload, err := evidenceExportSnapshot(ctx, tx, request, result.PreparedAt)
	if err != nil {
		return EvidenceExportState{}, nil, evidenceExportRejected(ctx, tx, request, err)
	}
	plain, err := evidencearchive.Encode(payload)
	if err != nil {
		return EvidenceExportState{}, nil, evidenceExportRejected(ctx, tx, request, ErrApprovalEvidenceInvalid)
	}
	defer clear(plain)
	if !coldarchive.EqualDigest(coldarchive.Digest(plain), result.PayloadSHA256) {
		return EvidenceExportState{}, nil, evidenceExportRejected(ctx, tx, request, ErrEvidenceExportConflict)
	}
	artifact, err := coldarchive.SealEncoded(request.Key, plain, result.Salt, result.Nonce)
	if err != nil {
		return EvidenceExportState{}, nil, ErrEvidenceExportInvalid
	}
	if len(artifact) != result.ArtifactSize || !coldarchive.EqualDigest(coldarchive.Digest(artifact), result.ArtifactSHA256) {
		clear(artifact)
		return EvidenceExportState{}, nil, ErrEvidenceExportConflict
	}
	if tx.Commit() != nil {
		clear(artifact)
		return EvidenceExportState{}, nil, ErrDatabaseUnavailable
	}
	return result, artifact, nil
}

// EvidenceExportForVerification may inspect a protected copy in another
// directory or an explicitly released successor epoch, but cannot publish it.
func (postgres *Postgres) EvidenceExportForVerification(ctx context.Context, request EvidenceExportRequest) (EvidenceExportState, error) {
	if !request.valid(true) {
		return EvidenceExportState{}, ErrEvidenceExportInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return EvidenceExportState{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if _, err := lockRecoveryReady(ctx, tx, request.DatabaseEpoch); err != nil {
		return EvidenceExportState{}, err
	}
	result, err := readEvidenceExport(ctx, tx, request.ExportID)
	if errors.Is(err, sql.ErrNoRows) {
		return EvidenceExportState{}, ErrEvidenceExportNotFound
	}
	if err != nil {
		return EvidenceExportState{}, ErrDatabaseUnavailable
	}
	if err := checkEvidenceExportBinding(result, request, false, false); err != nil {
		return EvidenceExportState{}, err
	}
	if err := checkExportRecoveryPath(ctx, tx, result.OperationEpoch, request.DatabaseEpoch); err != nil {
		return EvidenceExportState{}, err
	}
	if tx.Commit() != nil {
		return EvidenceExportState{}, ErrDatabaseUnavailable
	}
	return result, nil
}

func (postgres *Postgres) FinishEvidenceExport(ctx context.Context, request EvidenceExportRequest, artifactSHA256 string, size int) (EvidenceExportState, error) {
	if !request.valid(true) || !validSHA256Hex(artifactSHA256) || size < 0 {
		return EvidenceExportState{}, ErrEvidenceExportInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return EvidenceExportState{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if err := lockEvidenceExport(ctx, tx, request.ExportID); err != nil {
		return EvidenceExportState{}, err
	}
	if _, err := lockRecoveryReady(ctx, tx, request.DatabaseEpoch); err != nil {
		return EvidenceExportState{}, err
	}
	result, err := readEvidenceExport(ctx, tx, request.ExportID)
	if errors.Is(err, sql.ErrNoRows) {
		return EvidenceExportState{}, ErrEvidenceExportNotFound
	}
	if err != nil {
		return EvidenceExportState{}, ErrDatabaseUnavailable
	}
	if err := checkEvidenceExportBinding(result, request, true, true); err != nil {
		return EvidenceExportState{}, err
	}
	if result.State == "aborted" || result.ArtifactSize != size || !coldarchive.EqualDigest(result.ArtifactSHA256, artifactSHA256) {
		return EvidenceExportState{}, ErrEvidenceExportConflict
	}
	if result.State == "published" {
		if tx.Commit() != nil {
			return EvidenceExportState{}, ErrDatabaseUnavailable
		}
		return result, nil
	}
	var completed time.Time
	if err := tx.QueryRowContext(ctx, `update approval_evidence_exports set state='published',completed_at=clock_timestamp() where id=$1 and state='prepared' returning completed_at`, request.ExportID).Scan(&completed); err != nil {
		return EvidenceExportState{}, ErrDatabaseUnavailable
	}
	completed = completed.UTC()
	result.State, result.CompletedAt = "published", &completed
	if err := evidenceExportAudit(ctx, tx, "approval.evidence.export.published", "success", result, request.DatabaseEpoch, request.DestinationFingerprint); err != nil {
		return EvidenceExportState{}, err
	}
	if tx.Commit() != nil {
		return EvidenceExportState{}, ErrDatabaseUnavailable
	}
	return result, nil
}

// AbortEvidenceExport requires the same domain/key but not the original
// directory. A released successor may retire an ancestor's pending operation.
func (postgres *Postgres) AbortEvidenceExport(ctx context.Context, request EvidenceExportRequest) (EvidenceExportState, error) {
	if !request.valid(false) {
		return EvidenceExportState{}, ErrEvidenceExportInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return EvidenceExportState{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if err := lockEvidenceExport(ctx, tx, request.ExportID); err != nil {
		return EvidenceExportState{}, err
	}
	if _, err := lockRecoveryReady(ctx, tx, request.DatabaseEpoch); err != nil {
		return EvidenceExportState{}, err
	}
	result, err := readEvidenceExport(ctx, tx, request.ExportID)
	if errors.Is(err, sql.ErrNoRows) {
		return EvidenceExportState{}, ErrEvidenceExportNotFound
	}
	if err != nil {
		return EvidenceExportState{}, ErrDatabaseUnavailable
	}
	if err := checkEvidenceExportBinding(result, request, false, false); err != nil {
		return EvidenceExportState{}, err
	}
	if err := checkExportRecoveryPath(ctx, tx, result.OperationEpoch, request.DatabaseEpoch); err != nil {
		return EvidenceExportState{}, err
	}
	if result.State == "published" {
		return EvidenceExportState{}, ErrEvidenceExportConflict
	}
	if result.State == "aborted" {
		if tx.Commit() != nil {
			return EvidenceExportState{}, ErrDatabaseUnavailable
		}
		return result, nil
	}
	var completed time.Time
	if err := tx.QueryRowContext(ctx, `update approval_evidence_exports set state='aborted',completed_at=clock_timestamp() where id=$1 and state='prepared' returning completed_at`, request.ExportID).Scan(&completed); err != nil {
		return EvidenceExportState{}, ErrDatabaseUnavailable
	}
	completed = completed.UTC()
	result.State, result.CompletedAt = "aborted", &completed
	if err := evidenceExportAudit(ctx, tx, "approval.evidence.export.aborted", "success", result, request.DatabaseEpoch); err != nil {
		return EvidenceExportState{}, err
	}
	if tx.Commit() != nil {
		return EvidenceExportState{}, ErrDatabaseUnavailable
	}
	return result, nil
}

func (postgres *Postgres) StartEvidenceExportRepair(ctx context.Context, request EvidenceExportRequest, artifactSHA256 string, size int) error {
	return postgres.recordEvidenceExportAccess(ctx, request, artifactSHA256, size, "approval.evidence.export.repair_started", true)
}

// RecordEvidenceExportAccess requires callers to authenticate the complete
// artifact before requesting an audited verification or repair record.
func (postgres *Postgres) RecordEvidenceExportAccess(ctx context.Context, request EvidenceExportRequest, artifactSHA256 string, size int, repaired bool) error {
	action := "approval.evidence.export.verified"
	if repaired {
		action = "approval.evidence.export.repaired"
	}
	return postgres.recordEvidenceExportAccess(ctx, request, artifactSHA256, size, action, false)
}

func (postgres *Postgres) recordEvidenceExportAccess(ctx context.Context, request EvidenceExportRequest, artifactSHA256 string, size int, action string, repairIntent bool) error {
	if !request.valid(true) || !validSHA256Hex(artifactSHA256) || size < 0 {
		return ErrEvidenceExportInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if err := lockEvidenceExport(ctx, tx, request.ExportID); err != nil {
		return err
	}
	if _, err := lockRecoveryReady(ctx, tx, request.DatabaseEpoch); err != nil {
		return err
	}
	result, err := readEvidenceExport(ctx, tx, request.ExportID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrEvidenceExportNotFound
	}
	if err != nil {
		return ErrDatabaseUnavailable
	}
	if err := checkEvidenceExportBinding(result, request, repairIntent, repairIntent); err != nil {
		return err
	}
	if err := checkExportRecoveryPath(ctx, tx, result.OperationEpoch, request.DatabaseEpoch); err != nil {
		return err
	}
	if result.State != "published" || result.ArtifactSize != size || !coldarchive.EqualDigest(result.ArtifactSHA256, artifactSHA256) {
		return ErrEvidenceExportConflict
	}
	if err := evidenceExportAudit(ctx, tx, action, "success", result, request.DatabaseEpoch, request.DestinationFingerprint); err != nil {
		return err
	}
	if tx.Commit() != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}
