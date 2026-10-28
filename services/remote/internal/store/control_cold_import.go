package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"dsh-mobile-ustc/services/remote/internal/coldarchive"
)

var ErrControlImportInvalid = errors.New("store: invalid control history import")
var ErrControlImportConflict = errors.New("store: control history import conflicts")
var ErrControlImportExpired = errors.New("store: imported history is no longer retained")

type ControlImportRequest struct {
	ImportID, ExportID, DomainID, DatabaseEpoch string
	AccessFingerprint                           string
	Key                                         *coldarchive.Key
}

func (request ControlImportRequest) valid() bool {
	return coldarchive.UUID(request.ImportID) && coldarchive.UUID(request.ExportID) && coldarchive.UUID(request.DomainID) && coldarchive.UUID(request.DatabaseEpoch) && validSHA256Hex(request.AccessFingerprint) && request.Key != nil
}

type ControlImportResult struct {
	ImportID         string    `json:"import_id"`
	ExportID         string    `json:"export_id"`
	DomainID         string    `json:"domain_id"`
	BatchID          string    `json:"batch_id"`
	BatchEpoch       string    `json:"batch_epoch"`
	SourceEpoch      string    `json:"source_epoch"`
	TargetEpoch      string    `json:"target_epoch"`
	KeyID            string    `json:"key_id"`
	ArtifactSHA256   string    `json:"artifact_sha256"`
	ArtifactSize     int       `json:"artifact_size"`
	Events           int       `json:"events"`
	Acknowledgements int       `json:"acknowledgements"`
	RetainUntil      time.Time `json:"retain_until"`
	ImportedAt       time.Time `json:"imported_at"`
}

type controlImportRecord struct {
	ControlImportResult
	KeyFingerprint string
	PayloadSHA256  string
}

func readControlImport(ctx context.Context, tx *sql.Tx, id string) (controlImportRecord, error) {
	var record controlImportRecord
	err := tx.QueryRowContext(ctx, `select i.id::text,i.export_id::text,i.domain_id::text,i.batch_id::text,i.batch_epoch::text,i.source_epoch::text,i.target_epoch::text,
	 i.key_id,i.artifact_sha256,i.artifact_size,i.event_count,i.acknowledgement_count,i.retain_until,i.imported_at,i.key_fingerprint,i.payload_sha256
	 from control_archive_imports i where i.id=$1`, id).
		Scan(&record.ImportID, &record.ExportID, &record.DomainID, &record.BatchID, &record.BatchEpoch, &record.SourceEpoch, &record.TargetEpoch,
			&record.KeyID, &record.ArtifactSHA256, &record.ArtifactSize, &record.Events, &record.Acknowledgements, &record.RetainUntil, &record.ImportedAt,
			&record.KeyFingerprint, &record.PayloadSHA256)
	record.RetainUntil = record.RetainUntil.UTC()
	record.ImportedAt = record.ImportedAt.UTC()
	return record, err
}

func importAudit(ctx context.Context, tx *sql.Tx, action string, result ControlImportResult, accessFingerprint string) error {
	fields := map[string]any{"import_id": result.ImportID, "export_id": result.ExportID, "domain_id": result.DomainID, "batch_id": result.BatchID,
		"batch_epoch": result.BatchEpoch, "source_epoch": result.SourceEpoch, "target_epoch": result.TargetEpoch, "key_id": result.KeyID,
		"artifact_sha256": result.ArtifactSHA256, "artifact_size": result.ArtifactSize, "events": result.Events, "acknowledgements": result.Acknowledgements,
		"access_location_fingerprint": accessFingerprint}
	metadata, _ := json.Marshal(fields)
	if _, err := tx.ExecContext(ctx, `insert into audit_log(actor_type,actor_id,action,result,metadata) values('system',current_user,$1,'success',$2::jsonb||jsonb_build_object('db_session_user',session_user))`, action, string(metadata)); err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}

// ImportControlHistory authenticates the artifact and stores only inert history.
// It does not insert live outbox events, acknowledgements, recovery runs, or grants.
func (postgres *Postgres) ImportControlHistory(ctx context.Context, request ControlImportRequest, artifact []byte) (ControlImportResult, error) {
	if !request.valid() {
		return ControlImportResult{}, ErrControlImportInvalid
	}
	payload, err := coldarchive.Open(request.Key, artifact, request.DomainID, request.ExportID)
	if err != nil {
		return ControlImportResult{}, ErrControlImportInvalid
	}
	plain, err := coldarchive.Encode(payload)
	if err != nil {
		return ControlImportResult{}, ErrControlImportInvalid
	}
	defer clear(plain)
	fingerprint, err := request.Key.Fingerprint()
	if err != nil {
		return ControlImportResult{}, ErrControlImportInvalid
	}
	result := ControlImportResult{ImportID: request.ImportID, ExportID: request.ExportID, DomainID: request.DomainID, BatchID: payload.Batch.ID, BatchEpoch: payload.Batch.DatabaseEpoch,
		SourceEpoch: payload.OperationEpoch, TargetEpoch: request.DatabaseEpoch, KeyID: payload.KeyID, ArtifactSHA256: coldarchive.Digest(artifact), ArtifactSize: len(artifact),
		Events: len(payload.Events), RetainUntil: payload.Batch.RetainUntil.UTC()}
	for _, event := range payload.Events {
		result.Acknowledgements += len(event.Acknowledgements)
	}
	payloadSHA := coldarchive.Digest(plain)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return ControlImportResult{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	// Lock the artifact before the operation identity; all callers use this
	// order so two IDs cannot concurrently claim the same authenticated export.
	if _, err := tx.ExecContext(ctx, `select pg_advisory_xact_lock(hashtextextended('dsh-control-import-export:'||$1::text||':'||$2::text,0))`, request.DomainID, request.ExportID); err != nil {
		return ControlImportResult{}, ErrDatabaseUnavailable
	}
	if _, err := tx.ExecContext(ctx, `select pg_advisory_xact_lock(hashtextextended('dsh-control-import-operation:'||$1::text,0))`, request.ImportID); err != nil {
		return ControlImportResult{}, ErrDatabaseUnavailable
	}
	if _, err := lockRecoveryReady(ctx, tx, request.DatabaseEpoch); err != nil {
		return ControlImportResult{}, err
	}
	previous, err := readControlImport(ctx, tx, request.ImportID)
	if err == nil {
		if previous.DomainID != result.DomainID || previous.ExportID != result.ExportID || previous.BatchID != result.BatchID || previous.BatchEpoch != result.BatchEpoch || previous.SourceEpoch != result.SourceEpoch || previous.TargetEpoch != result.TargetEpoch ||
			previous.KeyID != result.KeyID || !coldarchive.EqualDigest(previous.KeyFingerprint, fingerprint) || !coldarchive.EqualDigest(previous.ArtifactSHA256, result.ArtifactSHA256) || previous.ArtifactSize != result.ArtifactSize ||
			previous.Events != result.Events || previous.Acknowledgements != result.Acknowledgements || !previous.RetainUntil.Equal(result.RetainUntil) || !coldarchive.EqualDigest(previous.PayloadSHA256, payloadSHA) {
			return ControlImportResult{}, ErrControlImportConflict
		}
		var same bool
		if err := tx.QueryRowContext(ctx, `select payload=$2::jsonb from control_archive_import_payloads where import_id=$1 for share`, request.ImportID, string(plain)).Scan(&same); errors.Is(err, sql.ErrNoRows) {
			return ControlImportResult{}, ErrControlImportExpired
		} else if err != nil {
			return ControlImportResult{}, ErrDatabaseUnavailable
		}
		if !same {
			return ControlImportResult{}, ErrControlImportConflict
		}
		if err := importAudit(ctx, tx, "control.archive.import.verified", previous.ControlImportResult, request.AccessFingerprint); err != nil {
			return ControlImportResult{}, err
		}
		if tx.Commit() != nil {
			return ControlImportResult{}, ErrDatabaseUnavailable
		}
		return previous.ControlImportResult, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ControlImportResult{}, ErrDatabaseUnavailable
	}
	var claimed bool
	if err := tx.QueryRowContext(ctx, `select exists(select 1 from control_archive_imports where domain_id=$1 and export_id=$2)`, request.DomainID, request.ExportID).Scan(&claimed); err != nil {
		return ControlImportResult{}, ErrDatabaseUnavailable
	}
	if claimed {
		return ControlImportResult{}, ErrControlImportConflict
	}
	if err := tx.QueryRowContext(ctx, `insert into control_archive_imports(id,domain_id,export_id,batch_id,batch_epoch,source_epoch,target_epoch,key_id,key_fingerprint,
	 artifact_sha256,artifact_size,payload_sha256,event_count,acknowledgement_count,retain_until,imported_at)
	 values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,clock_timestamp()) returning imported_at`,
		result.ImportID, result.DomainID, result.ExportID, result.BatchID, result.BatchEpoch, result.SourceEpoch, result.TargetEpoch, result.KeyID, fingerprint,
		result.ArtifactSHA256, result.ArtifactSize, payloadSHA, result.Events, result.Acknowledgements, result.RetainUntil).Scan(&result.ImportedAt); err != nil {
		return ControlImportResult{}, ErrDatabaseUnavailable
	}
	result.ImportedAt = result.ImportedAt.UTC()
	if _, err := tx.ExecContext(ctx, `insert into control_archive_import_payloads(import_id,payload) values($1,$2::jsonb)`, result.ImportID, string(plain)); err != nil {
		return ControlImportResult{}, ErrDatabaseUnavailable
	}
	if err := importAudit(ctx, tx, "control.archive.import", result, request.AccessFingerprint); err != nil {
		return ControlImportResult{}, err
	}
	if tx.Commit() != nil {
		return ControlImportResult{}, ErrDatabaseUnavailable
	}
	return result, nil
}
