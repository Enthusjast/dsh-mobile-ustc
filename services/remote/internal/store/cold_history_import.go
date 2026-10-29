package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auditarchive"
	"dsh-mobile-ustc/services/remote/internal/coldarchive"
	"dsh-mobile-ustc/services/remote/internal/evidencearchive"
)

var ErrColdHistoryImportInvalid = errors.New("store: invalid cold history import")
var ErrColdHistoryImportConflict = errors.New("store: cold history import conflicts")
var ErrColdHistoryImportExpired = errors.New("store: imported cold history is no longer retained")

type ColdHistoryImportRequest struct {
	Kind, ImportID, ExportID, DomainID, DatabaseEpoch string
	AccessFingerprint                                 string
	Key                                               *coldarchive.Key
}

func (request ColdHistoryImportRequest) valid() bool {
	return (request.Kind == "audit" || request.Kind == "approval") && coldarchive.UUID(request.ImportID) && coldarchive.UUID(request.ExportID) &&
		coldarchive.UUID(request.DomainID) && coldarchive.UUID(request.DatabaseEpoch) && validSHA256Hex(request.AccessFingerprint) && request.Key != nil
}

type ColdHistoryImportResult struct {
	Kind           string    `json:"kind"`
	ImportID       string    `json:"import_id"`
	ExportID       string    `json:"export_id"`
	DomainID       string    `json:"domain_id"`
	ObjectID       string    `json:"object_id"`
	SourceEpoch    string    `json:"source_epoch"`
	OperationEpoch string    `json:"operation_epoch"`
	TargetEpoch    string    `json:"target_epoch"`
	KeyID          string    `json:"key_id"`
	ArtifactSHA256 string    `json:"artifact_sha256"`
	ArtifactSize   int       `json:"artifact_size"`
	Entries        int       `json:"entries"`
	RetainUntil    time.Time `json:"retain_until"`
	ImportedAt     time.Time `json:"imported_at"`
}

type coldHistoryImportRecord struct {
	ColdHistoryImportResult
	KeyFingerprint string
	PayloadSHA256  string
}

func readColdHistoryImport(ctx context.Context, tx *sql.Tx, id string) (coldHistoryImportRecord, error) {
	var record coldHistoryImportRecord
	err := tx.QueryRowContext(ctx, `select kind,id::text,export_id::text,domain_id::text,object_id::text,source_epoch::text,operation_epoch::text,target_epoch::text,
	 key_id,artifact_sha256,artifact_size,entry_count,retain_until,imported_at,key_fingerprint,payload_sha256 from cold_history_imports where id=$1`, id).
		Scan(&record.Kind, &record.ImportID, &record.ExportID, &record.DomainID, &record.ObjectID, &record.SourceEpoch, &record.OperationEpoch, &record.TargetEpoch,
			&record.KeyID, &record.ArtifactSHA256, &record.ArtifactSize, &record.Entries, &record.RetainUntil, &record.ImportedAt, &record.KeyFingerprint, &record.PayloadSHA256)
	record.RetainUntil, record.ImportedAt = record.RetainUntil.UTC(), record.ImportedAt.UTC()
	return record, err
}

func coldHistoryImportAudit(ctx context.Context, tx *sql.Tx, action, status string, result ColdHistoryImportResult, currentEpoch, accessFingerprint string) error {
	fields := map[string]any{"kind": result.Kind, "import_id": result.ImportID, "export_id": result.ExportID, "domain_id": result.DomainID,
		"object_id": result.ObjectID, "source_epoch": result.SourceEpoch, "operation_epoch": result.OperationEpoch, "target_epoch": result.TargetEpoch, "current_epoch": currentEpoch,
		"key_id": result.KeyID, "artifact_sha256": result.ArtifactSHA256, "artifact_size": result.ArtifactSize, "entries": result.Entries,
		"access_location_fingerprint": accessFingerprint}
	metadata, _ := json.Marshal(fields)
	if _, err := tx.ExecContext(ctx, `insert into audit_log(actor_type,actor_id,action,result,metadata)
	 values('system',current_user,$1,$2,$3::jsonb||jsonb_build_object('db_session_user',session_user))`, action, status, string(metadata)); err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}

// decodeColdHistory authenticates the specific file type and builds its inert
// database representation. Its returned plaintext belongs to the caller.
func decodeColdHistory(request ColdHistoryImportRequest, artifact []byte) (ColdHistoryImportResult, []byte, error) {
	result := ColdHistoryImportResult{Kind: request.Kind, ImportID: request.ImportID, ExportID: request.ExportID, DomainID: request.DomainID,
		TargetEpoch: request.DatabaseEpoch, KeyID: request.Key.ID(), ArtifactSHA256: coldarchive.Digest(artifact), ArtifactSize: len(artifact)}
	if request.Kind == "audit" {
		payload, err := auditarchive.Open(request.Key, artifact, request.DomainID, request.ExportID)
		if err != nil {
			return ColdHistoryImportResult{}, nil, ErrColdHistoryImportInvalid
		}
		defer auditarchive.Clear(&payload)
		plain, err := auditarchive.Encode(payload)
		if err != nil {
			return ColdHistoryImportResult{}, nil, ErrColdHistoryImportInvalid
		}
		result.ObjectID, result.SourceEpoch, result.OperationEpoch = payload.Batch.ID, payload.Batch.DatabaseEpoch, payload.OperationEpoch
		result.Entries, result.RetainUntil = len(payload.Entries), payload.Batch.RetainUntil.UTC()
		return result, plain, nil
	}
	payload, err := evidencearchive.Open(request.Key, artifact, request.DomainID, request.ExportID)
	if err != nil {
		return ColdHistoryImportResult{}, nil, ErrColdHistoryImportInvalid
	}
	plain, err := evidencearchive.Encode(payload)
	if err != nil {
		return ColdHistoryImportResult{}, nil, ErrColdHistoryImportInvalid
	}
	result.ObjectID, result.SourceEpoch, result.OperationEpoch = payload.Proof.ApprovalID, payload.Proof.SourceEpoch, payload.OperationEpoch
	result.Entries, result.RetainUntil = 1, payload.Proof.RetainUntil.UTC()
	return result, plain, nil
}

// ImportColdHistory writes a separately protected document and its admin audit.
// It never restores source audit rows, approvals, grants or recovery records.
func (postgres *Postgres) ImportColdHistory(ctx context.Context, request ColdHistoryImportRequest, artifact []byte) (ColdHistoryImportResult, error) {
	if !request.valid() {
		return ColdHistoryImportResult{}, ErrColdHistoryImportInvalid
	}
	result, plain, err := decodeColdHistory(request, artifact)
	if err != nil {
		return ColdHistoryImportResult{}, err
	}
	defer clear(plain)
	fingerprint, err := request.Key.Fingerprint()
	if err != nil {
		return ColdHistoryImportResult{}, ErrColdHistoryImportInvalid
	}
	payloadSHA := coldarchive.Digest(plain)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return ColdHistoryImportResult{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `select pg_advisory_xact_lock(hashtextextended('dsh-cold-history-artifact:'||$1::text||':'||$2::text||':'||$3::text,0))`, request.Kind, request.DomainID, request.ExportID); err != nil {
		return ColdHistoryImportResult{}, ErrDatabaseUnavailable
	}
	if _, err := tx.ExecContext(ctx, `select pg_advisory_xact_lock(hashtextextended('dsh-cold-history-import:'||$1::text,0))`, request.ImportID); err != nil {
		return ColdHistoryImportResult{}, ErrDatabaseUnavailable
	}
	if _, err := lockRecoveryReady(ctx, tx, request.DatabaseEpoch); err != nil {
		return ColdHistoryImportResult{}, err
	}
	reject := func(action string, record ColdHistoryImportResult, reason error) (ColdHistoryImportResult, error) {
		if err := coldHistoryImportAudit(ctx, tx, action, "failure", record, request.DatabaseEpoch, request.AccessFingerprint); err != nil {
			return ColdHistoryImportResult{}, err
		}
		if tx.Commit() != nil {
			return ColdHistoryImportResult{}, ErrDatabaseUnavailable
		}
		return ColdHistoryImportResult{}, reason
	}
	previous, err := readColdHistoryImport(ctx, tx, request.ImportID)
	if err == nil {
		if previous.Kind != result.Kind || previous.DomainID != result.DomainID || previous.ExportID != result.ExportID || previous.ObjectID != result.ObjectID || previous.SourceEpoch != result.SourceEpoch ||
			previous.OperationEpoch != result.OperationEpoch || previous.TargetEpoch != result.TargetEpoch || previous.KeyID != result.KeyID || previous.ArtifactSize != result.ArtifactSize ||
			previous.Entries != result.Entries || !previous.RetainUntil.Equal(result.RetainUntil) || !coldarchive.EqualDigest(previous.KeyFingerprint, fingerprint) ||
			!coldarchive.EqualDigest(previous.ArtifactSHA256, result.ArtifactSHA256) || !coldarchive.EqualDigest(previous.PayloadSHA256, payloadSHA) {
			return reject("cold.history.import.conflict", previous.ColdHistoryImportResult, ErrColdHistoryImportConflict)
		}
		var same bool
		if err := tx.QueryRowContext(ctx, `select payload=$2::jsonb from cold_history_import_payloads where import_id=$1 for share`, request.ImportID, string(plain)).Scan(&same); errors.Is(err, sql.ErrNoRows) {
			return reject("cold.history.import.expired", previous.ColdHistoryImportResult, ErrColdHistoryImportExpired)
		} else if err != nil {
			return ColdHistoryImportResult{}, ErrDatabaseUnavailable
		}
		if !same {
			return reject("cold.history.import.conflict", previous.ColdHistoryImportResult, ErrColdHistoryImportConflict)
		}
		if err := coldHistoryImportAudit(ctx, tx, "cold.history.import.verified", "success", previous.ColdHistoryImportResult, request.DatabaseEpoch, request.AccessFingerprint); err != nil {
			return ColdHistoryImportResult{}, err
		}
		if tx.Commit() != nil {
			return ColdHistoryImportResult{}, ErrDatabaseUnavailable
		}
		return previous.ColdHistoryImportResult, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ColdHistoryImportResult{}, ErrDatabaseUnavailable
	}
	var claimed bool
	if err := tx.QueryRowContext(ctx, `select exists(select 1 from cold_history_imports where kind=$1 and domain_id=$2 and export_id=$3)`, request.Kind, request.DomainID, request.ExportID).Scan(&claimed); err != nil {
		return ColdHistoryImportResult{}, ErrDatabaseUnavailable
	}
	if claimed {
		return reject("cold.history.import.conflict", result, ErrColdHistoryImportConflict)
	}
	if err := tx.QueryRowContext(ctx, `insert into cold_history_imports(id,kind,domain_id,export_id,object_id,source_epoch,operation_epoch,target_epoch,key_id,key_fingerprint,
	 artifact_sha256,artifact_size,payload_sha256,entry_count,retain_until,imported_at)
	 values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,clock_timestamp()) returning imported_at`,
		result.ImportID, result.Kind, result.DomainID, result.ExportID, result.ObjectID, result.SourceEpoch, result.OperationEpoch, result.TargetEpoch, result.KeyID, fingerprint,
		result.ArtifactSHA256, result.ArtifactSize, payloadSHA, result.Entries, result.RetainUntil).Scan(&result.ImportedAt); err != nil {
		return ColdHistoryImportResult{}, ErrDatabaseUnavailable
	}
	result.ImportedAt = result.ImportedAt.UTC()
	if _, err := tx.ExecContext(ctx, `insert into cold_history_import_payloads(import_id,payload) values($1,$2::jsonb)`, result.ImportID, string(plain)); err != nil {
		return ColdHistoryImportResult{}, ErrDatabaseUnavailable
	}
	if err := coldHistoryImportAudit(ctx, tx, "cold.history.import", "success", result, request.DatabaseEpoch, request.AccessFingerprint); err != nil {
		return ColdHistoryImportResult{}, err
	}
	if tx.Commit() != nil {
		return ColdHistoryImportResult{}, ErrDatabaseUnavailable
	}
	return result, nil
}
