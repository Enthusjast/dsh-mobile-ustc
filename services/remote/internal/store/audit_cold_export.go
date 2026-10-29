package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auditarchive"
	"dsh-mobile-ustc/services/remote/internal/coldarchive"
)

var ErrAuditColdExportInvalid = errors.New("store: invalid audit cold export")
var ErrAuditColdExportConflict = errors.New("store: audit cold export conflicts")
var ErrAuditColdExportNotFound = errors.New("store: audit cold export not found")
var ErrAuditColdIncomplete = errors.New("store: audit archive source is incomplete or too large")
var ErrAuditColdSourceInvalid = errors.New("store: audit archive source is invalid")

type AuditColdExportRequest struct {
	ExportID, DomainID, DatabaseEpoch, BatchID string
	DestinationFingerprint                     string
	Key                                        *coldarchive.Key
}

func (request AuditColdExportRequest) valid(destination bool) bool {
	return coldarchive.UUID(request.ExportID) && coldarchive.UUID(request.DomainID) && coldarchive.UUID(request.DatabaseEpoch) && coldarchive.UUID(request.BatchID) && request.Key != nil && (!destination || validSHA256Hex(request.DestinationFingerprint))
}

type AuditColdExportState struct {
	ExportID               string     `json:"export_id"`
	DomainID               string     `json:"domain_id"`
	OperationEpoch         string     `json:"operation_epoch"`
	BatchID                string     `json:"batch_id"`
	KeyID                  string     `json:"key_id"`
	KeyFingerprint         string     `json:"-"`
	DestinationFingerprint string     `json:"-"`
	Salt                   [32]byte   `json:"-"`
	Nonce                  [12]byte   `json:"-"`
	PayloadSHA256          string     `json:"-"`
	ArtifactSHA256         string     `json:"artifact_sha256"`
	ArtifactSize           int        `json:"artifact_size"`
	EntryCount             int        `json:"entries"`
	PreparedAt             time.Time  `json:"prepared_at"`
	State                  string     `json:"state"`
	CompletedAt            *time.Time `json:"completed_at,omitempty"`
}

func (AuditColdExportState) String() string   { return "store.AuditColdExportState" }
func (AuditColdExportState) GoString() string { return "store.AuditColdExportState" }

func lockAuditColdExport(ctx context.Context, tx *sql.Tx, id string) error {
	if _, err := tx.ExecContext(ctx, `select pg_advisory_xact_lock(hashtextextended('dsh-audit-cold-export:'||$1::text,0))`, id); err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}

func readAuditColdExport(ctx context.Context, tx *sql.Tx, id string) (AuditColdExportState, error) {
	var result AuditColdExportState
	var salt, nonce []byte
	err := tx.QueryRowContext(ctx, `select id::text,domain_id::text,operation_epoch::text,batch_id::text,key_id,key_fingerprint,destination_fingerprint,salt,nonce,
	 payload_sha256,artifact_sha256,artifact_size,entry_count,prepared_at,state,completed_at from audit_cold_exports where id=$1`, id).
		Scan(&result.ExportID, &result.DomainID, &result.OperationEpoch, &result.BatchID, &result.KeyID, &result.KeyFingerprint, &result.DestinationFingerprint,
			&salt, &nonce, &result.PayloadSHA256, &result.ArtifactSHA256, &result.ArtifactSize, &result.EntryCount, &result.PreparedAt, &result.State, &result.CompletedAt)
	if err != nil {
		return result, err
	}
	if len(salt) != len(result.Salt) || len(nonce) != len(result.Nonce) {
		return AuditColdExportState{}, ErrDatabaseUnavailable
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

func checkAuditColdExportBinding(result AuditColdExportState, request AuditColdExportRequest, destination, epoch bool) error {
	fingerprint, err := request.Key.Fingerprint()
	if err != nil {
		return ErrAuditColdExportInvalid
	}
	if result.ExportID != request.ExportID || result.DomainID != request.DomainID || result.BatchID != request.BatchID || result.KeyID != request.Key.ID() || !coldarchive.EqualDigest(result.KeyFingerprint, fingerprint) ||
		(destination && !coldarchive.EqualDigest(result.DestinationFingerprint, request.DestinationFingerprint)) || (epoch && result.OperationEpoch != request.DatabaseEpoch) {
		return ErrAuditColdExportConflict
	}
	return nil
}

func auditColdExportAudit(ctx context.Context, tx *sql.Tx, action, status string, result AuditColdExportState, currentEpoch string, location ...string) error {
	metadata := map[string]any{"export_id": result.ExportID, "domain_id": result.DomainID, "batch_id": result.BatchID, "operation_epoch": result.OperationEpoch,
		"current_epoch": currentEpoch, "key_id": result.KeyID, "artifact_sha256": result.ArtifactSHA256, "artifact_size": result.ArtifactSize, "entries": result.EntryCount}
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

func auditColdExportSnapshot(ctx context.Context, tx *sql.Tx, request AuditColdExportRequest, prepared time.Time) (auditarchive.Payload, error) {
	batch, err := readAuditArchive(ctx, tx, request.BatchID)
	if errors.Is(err, sql.ErrNoRows) {
		return auditarchive.Payload{}, ErrAuditColdIncomplete
	}
	if err != nil {
		return auditarchive.Payload{}, ErrDatabaseUnavailable
	}
	if err := checkExportRecoveryPath(ctx, tx, batch.DatabaseEpoch, request.DatabaseEpoch); err != nil {
		return auditarchive.Payload{}, err
	}
	result := auditarchive.Payload{Format: "dsh-audit-archive", Version: 1, DomainID: request.DomainID, ExportID: request.ExportID, OperationEpoch: request.DatabaseEpoch,
		KeyID: request.Key.ID(), PreparedAt: prepared.UTC(), Batch: auditarchive.Batch{ID: batch.BatchID, DatabaseEpoch: batch.DatabaseEpoch, Limit: batch.Limit,
			RetentionYears: batch.RetentionYears, Cutoff: batch.Cutoff.UTC(), ArchivedAt: batch.ArchivedAt.UTC(), RetainUntil: batch.RetainUntil.UTC(), Entries: batch.Entries},
		Entries: []auditarchive.Entry{}, Recoveries: []coldarchive.Recovery{}}
	success := false
	defer func() {
		if !success {
			auditarchive.Clear(&result)
		}
	}()
	rows, err := tx.QueryContext(ctx, `select source_id,source_epoch::text,source_ts,case when octet_length(source::text)<=$2 then source::text end
	 from audit_log_archive where batch_id=$1 order by source_id limit 129 for share`, request.BatchID, auditarchive.MaxSource)
	if err != nil {
		return auditarchive.Payload{}, ErrDatabaseUnavailable
	}
	budget, needsRecovery := 0, batch.DatabaseEpoch != request.DatabaseEpoch
	for rows.Next() {
		var item auditarchive.Entry
		var epoch, raw sql.NullString
		if rows.Scan(&item.SourceID, &epoch, &item.SourceTime, &raw) != nil {
			_ = rows.Close()
			return auditarchive.Payload{}, ErrDatabaseUnavailable
		}
		if !raw.Valid || len(result.Entries) >= 128 {
			_ = rows.Close()
			return auditarchive.Payload{}, ErrAuditColdIncomplete
		}
		budget += 4*((len(raw.String)+2)/3) + 1024
		if budget > auditarchive.MaxPlaintext {
			_ = rows.Close()
			return auditarchive.Payload{}, ErrAuditColdIncomplete
		}
		if epoch.Valid {
			value := epoch.String
			item.SourceEpoch = &value
			if value != batch.DatabaseEpoch {
				needsRecovery = true
			}
		}
		item.SourceTime = item.SourceTime.UTC()
		item.Source = []byte(raw.String)
		result.Entries = append(result.Entries, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return auditarchive.Payload{}, ErrDatabaseUnavailable
	}
	if err := rows.Close(); err != nil {
		return auditarchive.Payload{}, ErrDatabaseUnavailable
	}
	if len(result.Entries) != batch.Entries {
		return auditarchive.Payload{}, ErrAuditColdIncomplete
	}
	if needsRecovery {
		rows, err = tx.QueryContext(ctx, `select id::text,source_epoch::text,target_epoch::text,prepared_at,released_at,authority_sha256,
		 case when octet_length(counts::text)<=$1 then counts::text end from remote_recovery_runs where phase='ready' order by id limit 257`, auditarchive.MaxPlaintext)
		if err != nil {
			return auditarchive.Payload{}, ErrDatabaseUnavailable
		}
		for rows.Next() {
			var item coldarchive.Recovery
			var raw sql.NullString
			if rows.Scan(&item.ID, &item.SourceEpoch, &item.TargetEpoch, &item.PreparedAt, &item.ReleasedAt, &item.AuthoritySHA256, &raw) != nil {
				_ = rows.Close()
				return auditarchive.Payload{}, ErrDatabaseUnavailable
			}
			budget += len(raw.String)*6 + 512
			if !raw.Valid || len(result.Recoveries) >= coldarchive.MaxRecoveries || budget > auditarchive.MaxPlaintext {
				_ = rows.Close()
				return auditarchive.Payload{}, ErrAuditColdIncomplete
			}
			item.PreparedAt, item.ReleasedAt = item.PreparedAt.UTC(), item.ReleasedAt.UTC()
			item.Counts = json.RawMessage(raw.String)
			result.Recoveries = append(result.Recoveries, item)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return auditarchive.Payload{}, ErrDatabaseUnavailable
		}
		if err := rows.Close(); err != nil {
			return auditarchive.Payload{}, ErrDatabaseUnavailable
		}
	}
	auditarchive.Sort(&result)
	if result.Validate() != nil {
		return auditarchive.Payload{}, ErrAuditColdSourceInvalid
	}
	success = true
	return result, nil
}

func auditColdExportRejected(ctx context.Context, tx *sql.Tx, request AuditColdExportRequest, reason error) error {
	status := "failure"
	if errors.Is(reason, ErrAuditColdIncomplete) {
		status = "unavailable"
	} else if errors.Is(reason, ErrRecoveryUnavailable) {
		status = "lineage_denied"
	} else if errors.Is(reason, ErrAuditColdExportConflict) {
		status = "conflict"
	} else if !errors.Is(reason, ErrAuditColdSourceInvalid) {
		return reason
	}
	result := AuditColdExportState{ExportID: request.ExportID, DomainID: request.DomainID, OperationEpoch: request.DatabaseEpoch, BatchID: request.BatchID, KeyID: request.Key.ID()}
	if err := auditColdExportAudit(ctx, tx, "audit.cold.export.prepare", status, result, request.DatabaseEpoch, request.DestinationFingerprint); err != nil {
		return err
	}
	if tx.Commit() != nil {
		return ErrDatabaseUnavailable
	}
	return reason
}

// PrepareAuditColdExport validates and pins the immutable source before
// returning a single encrypted artifact for durable publication.
func (postgres *Postgres) PrepareAuditColdExport(ctx context.Context, request AuditColdExportRequest) (AuditColdExportState, []byte, error) {
	if !request.valid(true) {
		return AuditColdExportState{}, nil, ErrAuditColdExportInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return AuditColdExportState{}, nil, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if err := lockAuditColdExport(ctx, tx, request.ExportID); err != nil {
		return AuditColdExportState{}, nil, err
	}
	if _, err := lockRecoveryReady(ctx, tx, request.DatabaseEpoch); err != nil {
		return AuditColdExportState{}, nil, err
	}
	previous, err := readAuditColdExport(ctx, tx, request.ExportID)
	if err == nil {
		if err := checkAuditColdExportBinding(previous, request, true, true); err != nil {
			return AuditColdExportState{}, nil, err
		}
		if previous.State == "aborted" {
			return AuditColdExportState{}, nil, ErrAuditColdExportConflict
		}
		if tx.Commit() != nil {
			return AuditColdExportState{}, nil, ErrDatabaseUnavailable
		}
		return previous, nil, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return AuditColdExportState{}, nil, ErrDatabaseUnavailable
	}
	var prepared time.Time
	if err := tx.QueryRowContext(ctx, `select clock_timestamp()`).Scan(&prepared); err != nil {
		return AuditColdExportState{}, nil, ErrDatabaseUnavailable
	}
	prepared = prepared.UTC()
	payload, err := auditColdExportSnapshot(ctx, tx, request, prepared)
	if err != nil {
		return AuditColdExportState{}, nil, auditColdExportRejected(ctx, tx, request, err)
	}
	defer auditarchive.Clear(&payload)
	plain, err := auditarchive.Encode(payload)
	if err != nil {
		return AuditColdExportState{}, nil, auditColdExportRejected(ctx, tx, request, ErrAuditColdSourceInvalid)
	}
	defer clear(plain)
	salt, nonce, err := coldarchive.Material()
	if err != nil {
		return AuditColdExportState{}, nil, ErrDatabaseUnavailable
	}
	artifact, err := coldarchive.SealEncodedWithLimit(request.Key, plain, salt, nonce, auditarchive.MaxPlaintext)
	if err != nil {
		return AuditColdExportState{}, nil, ErrAuditColdExportInvalid
	}
	fingerprint, err := request.Key.Fingerprint()
	if err != nil {
		clear(artifact)
		return AuditColdExportState{}, nil, ErrAuditColdExportInvalid
	}
	result := AuditColdExportState{ExportID: request.ExportID, DomainID: request.DomainID, OperationEpoch: request.DatabaseEpoch, BatchID: request.BatchID, KeyID: request.Key.ID(),
		KeyFingerprint: fingerprint, DestinationFingerprint: request.DestinationFingerprint, Salt: salt, Nonce: nonce, PayloadSHA256: coldarchive.Digest(plain),
		ArtifactSHA256: coldarchive.Digest(artifact), ArtifactSize: len(artifact), EntryCount: len(payload.Entries), PreparedAt: prepared, State: "prepared"}
	if _, err := tx.ExecContext(ctx, `insert into audit_cold_exports(id,domain_id,operation_epoch,batch_id,key_id,key_fingerprint,destination_fingerprint,salt,nonce,payload_sha256,artifact_sha256,artifact_size,entry_count,prepared_at,state)
	 values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'prepared')`, result.ExportID, result.DomainID, result.OperationEpoch, result.BatchID, result.KeyID, result.KeyFingerprint,
		result.DestinationFingerprint, result.Salt[:], result.Nonce[:], result.PayloadSHA256, result.ArtifactSHA256, result.ArtifactSize, result.EntryCount, result.PreparedAt); err != nil {
		clear(artifact)
		return AuditColdExportState{}, nil, ErrDatabaseUnavailable
	}
	if err := auditColdExportAudit(ctx, tx, "audit.cold.export.prepared", "success", result, request.DatabaseEpoch, request.DestinationFingerprint); err != nil {
		clear(artifact)
		return AuditColdExportState{}, nil, err
	}
	if tx.Commit() != nil {
		clear(artifact)
		return AuditColdExportState{}, nil, ErrDatabaseUnavailable
	}
	return result, artifact, nil
}

func (postgres *Postgres) RebuildAuditColdExport(ctx context.Context, request AuditColdExportRequest) (AuditColdExportState, []byte, error) {
	if !request.valid(true) {
		return AuditColdExportState{}, nil, ErrAuditColdExportInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return AuditColdExportState{}, nil, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if err := lockAuditColdExport(ctx, tx, request.ExportID); err != nil {
		return AuditColdExportState{}, nil, err
	}
	if _, err := lockRecoveryReady(ctx, tx, request.DatabaseEpoch); err != nil {
		return AuditColdExportState{}, nil, err
	}
	result, err := readAuditColdExport(ctx, tx, request.ExportID)
	if errors.Is(err, sql.ErrNoRows) {
		return AuditColdExportState{}, nil, ErrAuditColdExportNotFound
	}
	if err != nil {
		return AuditColdExportState{}, nil, ErrDatabaseUnavailable
	}
	if err := checkAuditColdExportBinding(result, request, true, true); err != nil {
		return AuditColdExportState{}, nil, err
	}
	if result.State == "aborted" {
		return AuditColdExportState{}, nil, ErrAuditColdExportConflict
	}
	payload, err := auditColdExportSnapshot(ctx, tx, request, result.PreparedAt)
	if err != nil {
		return AuditColdExportState{}, nil, auditColdExportRejected(ctx, tx, request, err)
	}
	defer auditarchive.Clear(&payload)
	plain, err := auditarchive.Encode(payload)
	if err != nil {
		return AuditColdExportState{}, nil, auditColdExportRejected(ctx, tx, request, ErrAuditColdSourceInvalid)
	}
	defer clear(plain)
	if !coldarchive.EqualDigest(coldarchive.Digest(plain), result.PayloadSHA256) {
		return AuditColdExportState{}, nil, auditColdExportRejected(ctx, tx, request, ErrAuditColdExportConflict)
	}
	artifact, err := coldarchive.SealEncodedWithLimit(request.Key, plain, result.Salt, result.Nonce, auditarchive.MaxPlaintext)
	if err != nil {
		return AuditColdExportState{}, nil, ErrAuditColdExportInvalid
	}
	if len(artifact) != result.ArtifactSize || !coldarchive.EqualDigest(coldarchive.Digest(artifact), result.ArtifactSHA256) {
		clear(artifact)
		return AuditColdExportState{}, nil, ErrAuditColdExportConflict
	}
	if tx.Commit() != nil {
		clear(artifact)
		return AuditColdExportState{}, nil, ErrDatabaseUnavailable
	}
	return result, artifact, nil
}

// AuditColdExportForVerification may inspect a protected copy in another
// directory or an explicitly released successor epoch, but cannot publish it.
func (postgres *Postgres) AuditColdExportForVerification(ctx context.Context, request AuditColdExportRequest) (AuditColdExportState, error) {
	if !request.valid(true) {
		return AuditColdExportState{}, ErrAuditColdExportInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return AuditColdExportState{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if _, err := lockRecoveryReady(ctx, tx, request.DatabaseEpoch); err != nil {
		return AuditColdExportState{}, err
	}
	result, err := readAuditColdExport(ctx, tx, request.ExportID)
	if errors.Is(err, sql.ErrNoRows) {
		return AuditColdExportState{}, ErrAuditColdExportNotFound
	}
	if err != nil {
		return AuditColdExportState{}, ErrDatabaseUnavailable
	}
	if err := checkAuditColdExportBinding(result, request, false, false); err != nil {
		return AuditColdExportState{}, err
	}
	if err := checkExportRecoveryPath(ctx, tx, result.OperationEpoch, request.DatabaseEpoch); err != nil {
		return AuditColdExportState{}, err
	}
	if tx.Commit() != nil {
		return AuditColdExportState{}, ErrDatabaseUnavailable
	}
	return result, nil
}

func (postgres *Postgres) FinishAuditColdExport(ctx context.Context, request AuditColdExportRequest, artifactSHA256 string, size int) (AuditColdExportState, error) {
	if !request.valid(true) || !validSHA256Hex(artifactSHA256) || size < 0 {
		return AuditColdExportState{}, ErrAuditColdExportInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return AuditColdExportState{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if err := lockAuditColdExport(ctx, tx, request.ExportID); err != nil {
		return AuditColdExportState{}, err
	}
	if _, err := lockRecoveryReady(ctx, tx, request.DatabaseEpoch); err != nil {
		return AuditColdExportState{}, err
	}
	result, err := readAuditColdExport(ctx, tx, request.ExportID)
	if errors.Is(err, sql.ErrNoRows) {
		return AuditColdExportState{}, ErrAuditColdExportNotFound
	}
	if err != nil {
		return AuditColdExportState{}, ErrDatabaseUnavailable
	}
	if err := checkAuditColdExportBinding(result, request, true, true); err != nil {
		return AuditColdExportState{}, err
	}
	if result.State == "aborted" || result.ArtifactSize != size || !coldarchive.EqualDigest(result.ArtifactSHA256, artifactSHA256) {
		return AuditColdExportState{}, ErrAuditColdExportConflict
	}
	if result.State == "published" {
		if tx.Commit() != nil {
			return AuditColdExportState{}, ErrDatabaseUnavailable
		}
		return result, nil
	}
	var completed time.Time
	if err := tx.QueryRowContext(ctx, `update audit_cold_exports set state='published',completed_at=clock_timestamp() where id=$1 and state='prepared' returning completed_at`, request.ExportID).Scan(&completed); err != nil {
		return AuditColdExportState{}, ErrDatabaseUnavailable
	}
	completed = completed.UTC()
	result.State, result.CompletedAt = "published", &completed
	if err := auditColdExportAudit(ctx, tx, "audit.cold.export.published", "success", result, request.DatabaseEpoch, request.DestinationFingerprint); err != nil {
		return AuditColdExportState{}, err
	}
	if tx.Commit() != nil {
		return AuditColdExportState{}, ErrDatabaseUnavailable
	}
	return result, nil
}

// AbortAuditColdExport requires the same domain/key but not the original
// directory. A released successor may retire an ancestor's pending operation.
func (postgres *Postgres) AbortAuditColdExport(ctx context.Context, request AuditColdExportRequest) (AuditColdExportState, error) {
	if !request.valid(false) {
		return AuditColdExportState{}, ErrAuditColdExportInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return AuditColdExportState{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if err := lockAuditColdExport(ctx, tx, request.ExportID); err != nil {
		return AuditColdExportState{}, err
	}
	if _, err := lockRecoveryReady(ctx, tx, request.DatabaseEpoch); err != nil {
		return AuditColdExportState{}, err
	}
	result, err := readAuditColdExport(ctx, tx, request.ExportID)
	if errors.Is(err, sql.ErrNoRows) {
		return AuditColdExportState{}, ErrAuditColdExportNotFound
	}
	if err != nil {
		return AuditColdExportState{}, ErrDatabaseUnavailable
	}
	if err := checkAuditColdExportBinding(result, request, false, false); err != nil {
		return AuditColdExportState{}, err
	}
	if err := checkExportRecoveryPath(ctx, tx, result.OperationEpoch, request.DatabaseEpoch); err != nil {
		return AuditColdExportState{}, err
	}
	if result.State == "published" {
		return AuditColdExportState{}, ErrAuditColdExportConflict
	}
	if result.State == "aborted" {
		if tx.Commit() != nil {
			return AuditColdExportState{}, ErrDatabaseUnavailable
		}
		return result, nil
	}
	var completed time.Time
	if err := tx.QueryRowContext(ctx, `update audit_cold_exports set state='aborted',completed_at=clock_timestamp() where id=$1 and state='prepared' returning completed_at`, request.ExportID).Scan(&completed); err != nil {
		return AuditColdExportState{}, ErrDatabaseUnavailable
	}
	completed = completed.UTC()
	result.State, result.CompletedAt = "aborted", &completed
	if err := auditColdExportAudit(ctx, tx, "audit.cold.export.aborted", "success", result, request.DatabaseEpoch); err != nil {
		return AuditColdExportState{}, err
	}
	if tx.Commit() != nil {
		return AuditColdExportState{}, ErrDatabaseUnavailable
	}
	return result, nil
}

func (postgres *Postgres) StartAuditColdExportRepair(ctx context.Context, request AuditColdExportRequest, artifactSHA256 string, size int) error {
	return postgres.recordAuditColdExportAccess(ctx, request, artifactSHA256, size, "audit.cold.export.repair_started", true)
}

// RecordAuditColdExportAccess requires callers to authenticate the complete
// artifact before requesting an audited verification or repair record.
func (postgres *Postgres) RecordAuditColdExportAccess(ctx context.Context, request AuditColdExportRequest, artifactSHA256 string, size int, repaired bool) error {
	action := "audit.cold.export.verified"
	if repaired {
		action = "audit.cold.export.repaired"
	}
	return postgres.recordAuditColdExportAccess(ctx, request, artifactSHA256, size, action, false)
}

func (postgres *Postgres) recordAuditColdExportAccess(ctx context.Context, request AuditColdExportRequest, artifactSHA256 string, size int, action string, repairIntent bool) error {
	if !request.valid(true) || !validSHA256Hex(artifactSHA256) || size < 0 {
		return ErrAuditColdExportInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if err := lockAuditColdExport(ctx, tx, request.ExportID); err != nil {
		return err
	}
	if _, err := lockRecoveryReady(ctx, tx, request.DatabaseEpoch); err != nil {
		return err
	}
	result, err := readAuditColdExport(ctx, tx, request.ExportID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAuditColdExportNotFound
	}
	if err != nil {
		return ErrDatabaseUnavailable
	}
	if err := checkAuditColdExportBinding(result, request, repairIntent, repairIntent); err != nil {
		return err
	}
	if err := checkExportRecoveryPath(ctx, tx, result.OperationEpoch, request.DatabaseEpoch); err != nil {
		return err
	}
	if result.State != "published" || result.ArtifactSize != size || !coldarchive.EqualDigest(result.ArtifactSHA256, artifactSHA256) {
		return ErrAuditColdExportConflict
	}
	if err := auditColdExportAudit(ctx, tx, action, "success", result, request.DatabaseEpoch, request.DestinationFingerprint); err != nil {
		return err
	}
	if tx.Commit() != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}
