package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"dsh-mobile-ustc/services/remote/internal/coldarchive"
)

var ErrControlExportInvalid = errors.New("store: invalid control export request")
var ErrControlExportConflict = errors.New("store: control export conflicts")
var ErrControlExportNotFound = errors.New("store: control export not found")
var ErrControlExportIncomplete = errors.New("store: control archive source is incomplete or too large")

type ControlExportRequest struct {
	ExportID, DomainID, DatabaseEpoch, BatchID string
	DestinationFingerprint                     string
	Key                                        *coldarchive.Key
}

func (request ControlExportRequest) valid(destination bool) bool {
	return coldarchive.UUID(request.ExportID) && coldarchive.UUID(request.DomainID) && coldarchive.UUID(request.DatabaseEpoch) && coldarchive.UUID(request.BatchID) && request.Key != nil && (!destination || validSHA256Hex(request.DestinationFingerprint))
}

type ControlExportState struct {
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
	Events                 int        `json:"events"`
	Acknowledgements       int        `json:"acknowledgements"`
	PreparedAt             time.Time  `json:"prepared_at"`
	State                  string     `json:"state"`
	CompletedAt            *time.Time `json:"completed_at,omitempty"`
}

func (ControlExportState) String() string   { return "store.ControlExportState" }
func (ControlExportState) GoString() string { return "store.ControlExportState" }

func lockExportOperation(ctx context.Context, tx *sql.Tx, id string) error {
	if _, err := tx.ExecContext(ctx, `select pg_advisory_xact_lock(hashtextextended('dsh-control-export:'||$1::text,0))`, id); err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}
func readControlExport(ctx context.Context, tx *sql.Tx, id string) (ControlExportState, error) {
	var result ControlExportState
	var salt, nonce []byte
	err := tx.QueryRowContext(ctx, `select id::text,domain_id::text,operation_epoch::text,batch_id::text,key_id,key_fingerprint,destination_fingerprint,salt,nonce,
	 payload_sha256,artifact_sha256,artifact_size,event_count,acknowledgement_count,prepared_at,state,completed_at from control_archive_exports where id=$1`, id).
		Scan(&result.ExportID, &result.DomainID, &result.OperationEpoch, &result.BatchID, &result.KeyID, &result.KeyFingerprint, &result.DestinationFingerprint, &salt, &nonce,
			&result.PayloadSHA256, &result.ArtifactSHA256, &result.ArtifactSize, &result.Events, &result.Acknowledgements, &result.PreparedAt, &result.State, &result.CompletedAt)
	if err != nil {
		return result, err
	}
	if len(salt) != len(result.Salt) || len(nonce) != len(result.Nonce) {
		return ControlExportState{}, ErrDatabaseUnavailable
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

func checkControlExportBinding(result ControlExportState, request ControlExportRequest, destination, epoch bool) error {
	fingerprint, err := request.Key.Fingerprint()
	if err != nil {
		return ErrControlExportInvalid
	}
	if result.ExportID != request.ExportID || result.DomainID != request.DomainID || result.BatchID != request.BatchID || result.KeyID != request.Key.ID() || !coldarchive.EqualDigest(result.KeyFingerprint, fingerprint) ||
		(destination && !coldarchive.EqualDigest(result.DestinationFingerprint, request.DestinationFingerprint)) || (epoch && result.OperationEpoch != request.DatabaseEpoch) {
		return ErrControlExportConflict
	}
	return nil
}

func (postgres *Postgres) ControlExport(ctx context.Context, request ControlExportRequest) (ControlExportState, error) {
	return postgres.controlExport(ctx, request, false)
}

// Verification may use a copied artifact in a new directory or a released
// recovery epoch. It never reuses old encryption material or changes that export.
func (postgres *Postgres) ControlExportForVerification(ctx context.Context, request ControlExportRequest) (ControlExportState, error) {
	return postgres.controlExport(ctx, request, true)
}

func (postgres *Postgres) controlExport(ctx context.Context, request ControlExportRequest, verification bool) (ControlExportState, error) {
	if !request.valid(true) {
		return ControlExportState{}, ErrControlExportInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return ControlExportState{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if _, err := lockRecoveryReady(ctx, tx, request.DatabaseEpoch); err != nil {
		return ControlExportState{}, err
	}
	result, err := readControlExport(ctx, tx, request.ExportID)
	if errors.Is(err, sql.ErrNoRows) {
		return ControlExportState{}, ErrControlExportNotFound
	}
	if err != nil {
		return ControlExportState{}, ErrDatabaseUnavailable
	}
	if err := checkControlExportBinding(result, request, !verification, !verification); err != nil {
		return ControlExportState{}, err
	}
	if verification {
		if err := checkExportRecoveryPath(ctx, tx, result.OperationEpoch, request.DatabaseEpoch); err != nil {
			return ControlExportState{}, err
		}
	}
	if tx.Commit() != nil {
		return ControlExportState{}, ErrDatabaseUnavailable
	}
	return result, nil
}

func checkExportRecoveryPath(ctx context.Context, tx *sql.Tx, source, current string) error {
	if source == current {
		return nil
	}
	var ancestor bool
	if err := tx.QueryRowContext(ctx, `with recursive lineage(epoch) as (
	 select $1::uuid union select r.target_epoch from remote_recovery_runs r join lineage l on r.source_epoch=l.epoch where r.phase='ready'
	) select exists(select 1 from lineage where epoch=$2::uuid)`, source, current).Scan(&ancestor); err != nil {
		return ErrDatabaseUnavailable
	}
	if !ancestor {
		return ErrRecoveryUnavailable
	}
	return nil
}

func exportSnapshot(ctx context.Context, tx *sql.Tx, request ControlExportRequest, preparedAt time.Time) (coldarchive.Payload, error) {
	batch, err := readControlArchive(ctx, tx, request.BatchID)
	if errors.Is(err, sql.ErrNoRows) {
		return coldarchive.Payload{}, ErrControlExportNotFound
	}
	if err != nil {
		return coldarchive.Payload{}, ErrDatabaseUnavailable
	}
	payload := coldarchive.Payload{Format: "dsh-control-archive", Version: 1, DomainID: request.DomainID, ExportID: request.ExportID, OperationEpoch: request.DatabaseEpoch, KeyID: request.Key.ID(), PreparedAt: preparedAt.UTC(),
		Batch: coldarchive.Batch{ID: batch.BatchID, DatabaseEpoch: batch.DatabaseEpoch, Limit: batch.Limit, RetentionYears: batch.RetentionYears, Cutoff: batch.Cutoff.UTC(), ArchivedAt: batch.ArchivedAt.UTC(), RetainUntil: batch.RetainUntil.UTC(), Events: batch.Events, PreviousEpochEvents: batch.PreviousEpochEvents}, Events: []coldarchive.Event{}, Recoveries: []coldarchive.Recovery{}}
	rows, err := tx.QueryContext(ctx, `select event_id::text,batch_id::text,batch_epoch::text,database_epoch::text,topic,source_created_at,
	 case when octet_length(source::text)<=$2 then source::text end,reason,archived_at,retain_until from control_outbox_archive
	 where batch_id=$1 order by event_id limit 129 for share`, request.BatchID, coldarchive.MaxPlaintext)
	if err != nil {
		return coldarchive.Payload{}, ErrDatabaseUnavailable
	}
	budget := 0
	indexes := map[string]int{}
	for rows.Next() {
		var event coldarchive.Event
		var raw sql.NullString
		if rows.Scan(&event.ID, &event.BatchID, &event.BatchEpoch, &event.DatabaseEpoch, &event.Topic, &event.SourceCreatedAt, &raw, &event.Reason, &event.ArchivedAt, &event.RetainUntil) != nil {
			_ = rows.Close()
			return coldarchive.Payload{}, ErrDatabaseUnavailable
		}
		budget += len(raw.String) + 512
		if !raw.Valid || budget > coldarchive.MaxPlaintext || len(payload.Events) >= 128 {
			_ = rows.Close()
			return coldarchive.Payload{}, ErrControlExportIncomplete
		}
		event.Source = json.RawMessage(raw.String)
		event.SourceCreatedAt = event.SourceCreatedAt.UTC()
		event.ArchivedAt = event.ArchivedAt.UTC()
		event.RetainUntil = event.RetainUntil.UTC()
		event.Acknowledgements = []coldarchive.Acknowledgement{}
		indexes[event.ID] = len(payload.Events)
		payload.Events = append(payload.Events, event)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return coldarchive.Payload{}, ErrDatabaseUnavailable
	}
	if err := rows.Close(); err != nil {
		return coldarchive.Payload{}, ErrDatabaseUnavailable
	}
	if len(payload.Events) != batch.Events {
		return coldarchive.Payload{}, ErrControlExportIncomplete
	}
	rows, err = tx.QueryContext(ctx, `select a.event_id::text,a.node_id::text,a.applied_at,case when octet_length(a.source::text)<=$2 then a.source::text end
	 from control_event_ack_archive a join control_outbox_archive e on e.event_id=a.event_id where e.batch_id=$1 order by a.event_id,a.node_id limit 8193`, request.BatchID, coldarchive.MaxPlaintext)
	if err != nil {
		return coldarchive.Payload{}, ErrDatabaseUnavailable
	}
	count := 0
	for rows.Next() {
		var ack coldarchive.Acknowledgement
		var raw sql.NullString
		if rows.Scan(&ack.EventID, &ack.NodeID, &ack.AppliedAt, &raw) != nil {
			_ = rows.Close()
			return coldarchive.Payload{}, ErrDatabaseUnavailable
		}
		count++
		budget += len(raw.String) + 256
		index, ok := indexes[ack.EventID]
		if !ok || !raw.Valid || count > coldarchive.MaxAcknowledgements || budget > coldarchive.MaxPlaintext {
			_ = rows.Close()
			return coldarchive.Payload{}, ErrControlExportIncomplete
		}
		ack.AppliedAt = ack.AppliedAt.UTC()
		ack.Source = json.RawMessage(raw.String)
		payload.Events[index].Acknowledgements = append(payload.Events[index].Acknowledgements, ack)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return coldarchive.Payload{}, ErrDatabaseUnavailable
	}
	if err := rows.Close(); err != nil {
		return coldarchive.Payload{}, ErrDatabaseUnavailable
	}
	if batch.DatabaseEpoch != request.DatabaseEpoch || batch.PreviousEpochEvents > 0 {
		rows, err = tx.QueryContext(ctx, `select id::text,source_epoch::text,target_epoch::text,prepared_at,released_at,authority_sha256,
		 case when octet_length(counts::text)<=$1 then counts::text end from remote_recovery_runs where phase='ready' order by id limit 257`, coldarchive.MaxPlaintext)
		if err != nil {
			return coldarchive.Payload{}, ErrDatabaseUnavailable
		}
		for rows.Next() {
			var item coldarchive.Recovery
			var raw sql.NullString
			if rows.Scan(&item.ID, &item.SourceEpoch, &item.TargetEpoch, &item.PreparedAt, &item.ReleasedAt, &item.AuthoritySHA256, &raw) != nil {
				_ = rows.Close()
				return coldarchive.Payload{}, ErrDatabaseUnavailable
			}
			budget += len(raw.String) + 256
			if !raw.Valid || len(payload.Recoveries) >= coldarchive.MaxRecoveries || budget > coldarchive.MaxPlaintext {
				_ = rows.Close()
				return coldarchive.Payload{}, ErrControlExportIncomplete
			}
			item.PreparedAt = item.PreparedAt.UTC()
			item.ReleasedAt = item.ReleasedAt.UTC()
			item.Counts = json.RawMessage(raw.String)
			payload.Recoveries = append(payload.Recoveries, item)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return coldarchive.Payload{}, ErrDatabaseUnavailable
		}
		if err := rows.Close(); err != nil {
			return coldarchive.Payload{}, ErrDatabaseUnavailable
		}
	}
	coldarchive.Sort(&payload)
	if payload.Validate() != nil {
		return coldarchive.Payload{}, ErrControlExportIncomplete
	}
	return payload, nil
}

func exportAudit(ctx context.Context, tx *sql.Tx, action string, result ControlExportState, currentEpoch string, location ...string) error {
	fields := map[string]any{"export_id": result.ExportID, "domain_id": result.DomainID, "operation_epoch": result.OperationEpoch, "current_epoch": currentEpoch, "batch_id": result.BatchID,
		"key_id": result.KeyID, "artifact_sha256": result.ArtifactSHA256, "artifact_size": result.ArtifactSize, "events": result.Events, "acknowledgements": result.Acknowledgements}
	if len(location) > 0 {
		fields["access_location_fingerprint"] = location[0]
	}
	metadata, _ := json.Marshal(fields)
	if _, err := tx.ExecContext(ctx, `insert into audit_log(actor_type,actor_id,action,result,metadata) values('system',current_user,$1,'success',$2::jsonb||jsonb_build_object('db_session_user',session_user))`, action, string(metadata)); err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}

func (postgres *Postgres) PrepareControlExport(ctx context.Context, request ControlExportRequest) (ControlExportState, []byte, error) {
	if !request.valid(true) {
		return ControlExportState{}, nil, ErrControlExportInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return ControlExportState{}, nil, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if err := lockExportOperation(ctx, tx, request.ExportID); err != nil {
		return ControlExportState{}, nil, err
	}
	if _, err := lockRecoveryReady(ctx, tx, request.DatabaseEpoch); err != nil {
		return ControlExportState{}, nil, err
	}
	previous, err := readControlExport(ctx, tx, request.ExportID)
	if err == nil {
		if err := checkControlExportBinding(previous, request, true, true); err != nil {
			return ControlExportState{}, nil, err
		}
		if previous.State == "aborted" {
			return ControlExportState{}, nil, ErrControlExportConflict
		}
		if tx.Commit() != nil {
			return ControlExportState{}, nil, ErrDatabaseUnavailable
		}
		return previous, nil, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ControlExportState{}, nil, ErrDatabaseUnavailable
	}
	var prepared time.Time
	if err := tx.QueryRowContext(ctx, `select clock_timestamp()`).Scan(&prepared); err != nil {
		return ControlExportState{}, nil, ErrDatabaseUnavailable
	}
	prepared = prepared.UTC()
	payload, err := exportSnapshot(ctx, tx, request, prepared)
	if err != nil {
		return ControlExportState{}, nil, err
	}
	plain, err := coldarchive.Encode(payload)
	if err != nil {
		return ControlExportState{}, nil, ErrControlExportIncomplete
	}
	defer clear(plain)
	salt, nonce, err := coldarchive.Material()
	if err != nil {
		return ControlExportState{}, nil, ErrDatabaseUnavailable
	}
	artifact, err := coldarchive.SealEncoded(request.Key, plain, salt, nonce)
	if err != nil {
		return ControlExportState{}, nil, ErrControlExportInvalid
	}
	fingerprint, err := request.Key.Fingerprint()
	if err != nil {
		clear(artifact)
		return ControlExportState{}, nil, ErrControlExportInvalid
	}
	result := ControlExportState{ExportID: request.ExportID, DomainID: request.DomainID, OperationEpoch: request.DatabaseEpoch, BatchID: request.BatchID, KeyID: request.Key.ID(), KeyFingerprint: fingerprint, DestinationFingerprint: request.DestinationFingerprint, Salt: salt, Nonce: nonce,
		PayloadSHA256: coldarchive.Digest(plain), ArtifactSHA256: coldarchive.Digest(artifact), ArtifactSize: len(artifact), Events: len(payload.Events), PreparedAt: prepared, State: "prepared"}
	for _, event := range payload.Events {
		result.Acknowledgements += len(event.Acknowledgements)
	}
	if _, err := tx.ExecContext(ctx, `insert into control_archive_exports(id,domain_id,operation_epoch,batch_id,key_id,key_fingerprint,destination_fingerprint,salt,nonce,payload_sha256,artifact_sha256,artifact_size,event_count,acknowledgement_count,prepared_at,state)
	 values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'prepared')`, result.ExportID, result.DomainID, result.OperationEpoch, result.BatchID, result.KeyID, result.KeyFingerprint, result.DestinationFingerprint, result.Salt[:], result.Nonce[:], result.PayloadSHA256, result.ArtifactSHA256, result.ArtifactSize, result.Events, result.Acknowledgements, result.PreparedAt); err != nil {
		clear(artifact)
		return ControlExportState{}, nil, ErrDatabaseUnavailable
	}
	if err := exportAudit(ctx, tx, "control.archive.export.prepared", result, request.DatabaseEpoch); err != nil {
		clear(artifact)
		return ControlExportState{}, nil, err
	}
	if tx.Commit() != nil {
		clear(artifact)
		return ControlExportState{}, nil, ErrDatabaseUnavailable
	}
	return result, artifact, nil
}

func (postgres *Postgres) RebuildControlExport(ctx context.Context, request ControlExportRequest) (ControlExportState, []byte, error) {
	if !request.valid(true) {
		return ControlExportState{}, nil, ErrControlExportInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return ControlExportState{}, nil, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if err := lockExportOperation(ctx, tx, request.ExportID); err != nil {
		return ControlExportState{}, nil, err
	}
	if _, err := lockRecoveryReady(ctx, tx, request.DatabaseEpoch); err != nil {
		return ControlExportState{}, nil, err
	}
	result, err := readControlExport(ctx, tx, request.ExportID)
	if errors.Is(err, sql.ErrNoRows) {
		return ControlExportState{}, nil, ErrControlExportNotFound
	}
	if err != nil {
		return ControlExportState{}, nil, ErrDatabaseUnavailable
	}
	if err := checkControlExportBinding(result, request, true, true); err != nil {
		return ControlExportState{}, nil, err
	}
	if result.State == "aborted" {
		return ControlExportState{}, nil, ErrControlExportConflict
	}
	payload, err := exportSnapshot(ctx, tx, request, result.PreparedAt)
	if err != nil {
		return ControlExportState{}, nil, err
	}
	plain, err := coldarchive.Encode(payload)
	if err != nil {
		return ControlExportState{}, nil, ErrControlExportIncomplete
	}
	defer clear(plain)
	// Never reuse GCM material when any source or metadata differs.
	if !coldarchive.EqualDigest(coldarchive.Digest(plain), result.PayloadSHA256) {
		return ControlExportState{}, nil, ErrControlExportConflict
	}
	artifact, err := coldarchive.SealEncoded(request.Key, plain, result.Salt, result.Nonce)
	if err != nil {
		return ControlExportState{}, nil, ErrControlExportInvalid
	}
	if len(artifact) != result.ArtifactSize || !coldarchive.EqualDigest(coldarchive.Digest(artifact), result.ArtifactSHA256) {
		clear(artifact)
		return ControlExportState{}, nil, ErrControlExportConflict
	}
	if tx.Commit() != nil {
		clear(artifact)
		return ControlExportState{}, nil, ErrDatabaseUnavailable
	}
	return result, artifact, nil
}

func (postgres *Postgres) FinishControlExport(ctx context.Context, request ControlExportRequest, artifactSHA256 string, size int) (ControlExportState, error) {
	if !request.valid(true) || !validSHA256Hex(artifactSHA256) || size < 0 {
		return ControlExportState{}, ErrControlExportInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return ControlExportState{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if err := lockExportOperation(ctx, tx, request.ExportID); err != nil {
		return ControlExportState{}, err
	}
	if _, err := lockRecoveryReady(ctx, tx, request.DatabaseEpoch); err != nil {
		return ControlExportState{}, err
	}
	result, err := readControlExport(ctx, tx, request.ExportID)
	if errors.Is(err, sql.ErrNoRows) {
		return ControlExportState{}, ErrControlExportNotFound
	}
	if err != nil {
		return ControlExportState{}, ErrDatabaseUnavailable
	}
	if err := checkControlExportBinding(result, request, true, true); err != nil {
		return ControlExportState{}, err
	}
	if result.State == "aborted" || result.ArtifactSize != size || !coldarchive.EqualDigest(result.ArtifactSHA256, artifactSHA256) {
		return ControlExportState{}, ErrControlExportConflict
	}
	if result.State == "published" {
		if tx.Commit() != nil {
			return ControlExportState{}, ErrDatabaseUnavailable
		}
		return result, nil
	}
	var completed time.Time
	if err := tx.QueryRowContext(ctx, `update control_archive_exports set state='published',completed_at=clock_timestamp() where id=$1 and state='prepared' returning completed_at`, request.ExportID).Scan(&completed); err != nil {
		return ControlExportState{}, ErrDatabaseUnavailable
	}
	completed = completed.UTC()
	result.State = "published"
	result.CompletedAt = &completed
	if err := exportAudit(ctx, tx, "control.archive.export.published", result, request.DatabaseEpoch); err != nil {
		return ControlExportState{}, err
	}
	if tx.Commit() != nil {
		return ControlExportState{}, ErrDatabaseUnavailable
	}
	return result, nil
}

// Abort requires the same archive key and domain, but not the original
// directory, so a lost/unmounted destination cannot pin history forever.
// A recovered epoch may abort only an ancestor's prepared export.
func (postgres *Postgres) AbortControlExport(ctx context.Context, request ControlExportRequest) (ControlExportState, error) {
	if !request.valid(false) {
		return ControlExportState{}, ErrControlExportInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return ControlExportState{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if err := lockExportOperation(ctx, tx, request.ExportID); err != nil {
		return ControlExportState{}, err
	}
	if _, err := lockRecoveryReady(ctx, tx, request.DatabaseEpoch); err != nil {
		return ControlExportState{}, err
	}
	result, err := readControlExport(ctx, tx, request.ExportID)
	if errors.Is(err, sql.ErrNoRows) {
		return ControlExportState{}, ErrControlExportNotFound
	}
	if err != nil {
		return ControlExportState{}, ErrDatabaseUnavailable
	}
	if err := checkControlExportBinding(result, request, false, false); err != nil {
		return ControlExportState{}, err
	}
	if err := checkExportRecoveryPath(ctx, tx, result.OperationEpoch, request.DatabaseEpoch); err != nil {
		return ControlExportState{}, err
	}
	if result.State == "published" {
		return ControlExportState{}, ErrControlExportConflict
	}
	if result.State == "aborted" {
		if tx.Commit() != nil {
			return ControlExportState{}, ErrDatabaseUnavailable
		}
		return result, nil
	}
	var completed time.Time
	if err := tx.QueryRowContext(ctx, `update control_archive_exports set state='aborted',completed_at=clock_timestamp() where id=$1 and state='prepared' returning completed_at`, request.ExportID).Scan(&completed); err != nil {
		return ControlExportState{}, ErrDatabaseUnavailable
	}
	completed = completed.UTC()
	result.State = "aborted"
	result.CompletedAt = &completed
	if err := exportAudit(ctx, tx, "control.archive.export.aborted", result, request.DatabaseEpoch); err != nil {
		return ControlExportState{}, err
	}
	if tx.Commit() != nil {
		return ControlExportState{}, ErrDatabaseUnavailable
	}
	return result, nil
}

// StartControlExportRepair records intent before writing a reconstructed file.
// If the process dies after publication, the intent remains for reconciliation.
func (postgres *Postgres) StartControlExportRepair(ctx context.Context, request ControlExportRequest, artifactSHA256 string, size int) error {
	return postgres.recordControlExportAccess(ctx, request, artifactSHA256, size, "control.archive.export.repair_started", true)
}

// RecordControlExportAccess audits a verified published artifact. Callers must
// authenticate/decrypt the file and check its digest before invoking this.
func (postgres *Postgres) RecordControlExportAccess(ctx context.Context, request ControlExportRequest, artifactSHA256 string, size int, repaired bool) error {
	action := "control.archive.export.verified"
	if repaired {
		action = "control.archive.export.repaired"
	}
	return postgres.recordControlExportAccess(ctx, request, artifactSHA256, size, action, false)
}

func (postgres *Postgres) recordControlExportAccess(ctx context.Context, request ControlExportRequest, artifactSHA256 string, size int, action string, repairIntent bool) error {
	if !request.valid(true) || !validSHA256Hex(artifactSHA256) || size < 0 {
		return ErrControlExportInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if err := lockExportOperation(ctx, tx, request.ExportID); err != nil {
		return err
	}
	if _, err := lockRecoveryReady(ctx, tx, request.DatabaseEpoch); err != nil {
		return err
	}
	result, err := readControlExport(ctx, tx, request.ExportID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrControlExportNotFound
	}
	if err != nil {
		return ErrDatabaseUnavailable
	}
	if err := checkControlExportBinding(result, request, repairIntent, repairIntent); err != nil {
		return err
	}
	if err := checkExportRecoveryPath(ctx, tx, result.OperationEpoch, request.DatabaseEpoch); err != nil {
		return err
	}
	if result.State != "published" || result.ArtifactSize != size || !coldarchive.EqualDigest(result.ArtifactSHA256, artifactSHA256) {
		return ErrControlExportConflict
	}
	if err := exportAudit(ctx, tx, action, result, request.DatabaseEpoch, request.DestinationFingerprint); err != nil {
		return err
	}
	if tx.Commit() != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}
