package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auditarchive"
	"dsh-mobile-ustc/services/remote/internal/coldarchive"
	"dsh-mobile-ustc/services/remote/internal/store"
)

type auditColdExportSummary struct {
	ExportID       string     `json:"export_id"`
	DomainID       string     `json:"domain_id"`
	BatchID        string     `json:"batch_id"`
	OperationEpoch string     `json:"operation_epoch"`
	KeyID          string     `json:"key_id"`
	State          string     `json:"state"`
	Verification   string     `json:"verification,omitempty"`
	Entries        int        `json:"entries"`
	ArtifactSHA256 string     `json:"artifact_sha256"`
	ArtifactSize   int        `json:"artifact_size"`
	PreparedAt     time.Time  `json:"prepared_at"`
	RetainUntil    *time.Time `json:"retain_until,omitempty"`
}

func auditColdSummary(state store.AuditColdExportState, proof *auditarchive.Payload) auditColdExportSummary {
	result := auditColdExportSummary{ExportID: state.ExportID, DomainID: state.DomainID, BatchID: state.BatchID, OperationEpoch: state.OperationEpoch, KeyID: state.KeyID,
		State: state.State, Entries: state.EntryCount, ArtifactSHA256: state.ArtifactSHA256, ArtifactSize: state.ArtifactSize, PreparedAt: state.PreparedAt}
	if proof != nil {
		retained := proof.Batch.RetainUntil
		result.RetainUntil = &retained
	}
	return result
}

func checkAuditColdArtifact(key *coldarchive.Key, raw []byte, domain, id string, state *store.AuditColdExportState) (auditarchive.Payload, error) {
	payload, err := auditarchive.Open(key, raw, domain, id)
	if err != nil {
		return auditarchive.Payload{}, err
	}
	if state != nil && (len(raw) != state.ArtifactSize || !coldarchive.EqualDigest(coldarchive.Digest(raw), state.ArtifactSHA256) || payload.Batch.ID != state.BatchID || len(payload.Entries) != state.EntryCount ||
		payload.OperationEpoch != state.OperationEpoch || payload.KeyID != state.KeyID || !payload.PreparedAt.Equal(state.PreparedAt)) {
		auditarchive.Clear(&payload)
		return auditarchive.Payload{}, coldarchive.ErrConflict
	}
	return payload, nil
}

func runAuditColdExportCommand(command string, arguments []string, output io.Writer) error {
	if command != "export-audit" && command != "verify-audit-export" && command != "verify-audit-offline" && command != "abort-audit-export" {
		return errors.New("remote audit history export command is invalid")
	}
	flags := flag.NewFlagSet("archive "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	id := flags.String("export-id", "", "stable export UUID")
	domain := flags.String("domain-id", "", "external archive domain UUID")
	batchID := flags.String("batch-id", "", "source audit batch UUID")
	epoch := flags.String("expected-epoch", "", "external database epoch")
	keyID := flags.String("key-id", "", "archive key identifier")
	keyPath := flags.String("key-file", "", "protected raw 32-byte key")
	path := flags.String("directory", "", "owner-only archive directory")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || !coldarchive.UUID(*id) || !coldarchive.UUID(*domain) || !coldarchive.KeyID(*keyID) || *keyPath == "" || os.Getenv("REMOTE_ARCHIVE_DOMAIN_ID") != *domain {
		return errors.New("remote audit history export identity or external domain is invalid")
	}
	if command == "verify-audit-offline" {
		if *batchID != "" || *epoch != "" || *path == "" {
			return errors.New("remote audit history offline verification arguments are invalid")
		}
	} else if !coldarchive.UUID(*batchID) || !coldarchive.UUID(*epoch) || os.Getenv("REMOTE_DATABASE_EPOCH") != *epoch || ((command == "abort-audit-export") != (*path == "")) {
		return errors.New("remote audit history export requires a matching external epoch and valid operation arguments")
	}
	rawKey, err := coldarchive.ReadKeyFile(*keyPath)
	if err != nil {
		return errors.New("remote archive key is unavailable or unprotected")
	}
	defer clear(rawKey)
	key, err := coldarchive.NewKey(*keyID, rawKey)
	if err != nil {
		return errors.New("remote archive key is invalid")
	}
	defer key.Close()
	var directory *coldarchive.Directory
	if *path != "" {
		directory, err = coldarchive.OpenDirectoryWithLimit(*path, auditarchive.MaxArtifact)
		if err != nil {
			return errors.New("remote archive directory is unavailable or unprotected")
		}
		defer directory.Close()
	}
	if command == "verify-audit-offline" {
		artifact, err := directory.Read(*id)
		if err != nil {
			return errors.New("remote audit history artifact is unavailable or invalid")
		}
		defer clear(artifact)
		payload, err := checkAuditColdArtifact(key, artifact, *domain, *id, nil)
		if err != nil {
			return errors.New("remote audit history artifact verification failed")
		}
		defer auditarchive.Clear(&payload)
		state := store.AuditColdExportState{ExportID: payload.ExportID, DomainID: payload.DomainID, BatchID: payload.Batch.ID, OperationEpoch: payload.OperationEpoch,
			KeyID: payload.KeyID, State: "offline_verified", EntryCount: len(payload.Entries), ArtifactSHA256: coldarchive.Digest(artifact), ArtifactSize: len(artifact), PreparedAt: payload.PreparedAt}
		result := auditColdSummary(state, &payload)
		result.Verification = "offline"
		if json.NewEncoder(output).Encode(result) != nil {
			return errors.New("remote audit history verification output failed")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	database, err := store.Open(ctx, os.Getenv("REMOTE_DATABASE_URL"))
	if err != nil {
		return errors.New("remote audit history database is unavailable or insecurely configured")
	}
	defer database.Close()
	request := store.AuditColdExportRequest{ExportID: *id, DomainID: *domain, DatabaseEpoch: *epoch, BatchID: *batchID, Key: key}
	if directory != nil {
		request.DestinationFingerprint, err = directory.Fingerprint(key)
		if err != nil {
			return errors.New("remote archive directory identity is unavailable")
		}
	}
	if command == "abort-audit-export" {
		state, err := database.AbortAuditColdExport(ctx, request)
		if err != nil {
			return err
		}
		if json.NewEncoder(output).Encode(auditColdSummary(state, nil)) != nil {
			return errors.New("remote audit history abort output failed; reconcile using the same export UUID")
		}
		return nil
	}
	if command == "verify-audit-export" {
		state, err := database.AuditColdExportForVerification(ctx, request)
		if err != nil {
			return err
		}
		if state.State != "published" {
			return store.ErrAuditColdExportConflict
		}
		artifact, err := directory.Read(*id)
		if err != nil {
			return errors.New("remote audit history artifact is unavailable or invalid")
		}
		defer clear(artifact)
		payload, err := checkAuditColdArtifact(key, artifact, *domain, *id, &state)
		if err != nil {
			return errors.New("remote audit history artifact verification failed")
		}
		defer auditarchive.Clear(&payload)
		if err := database.RecordAuditColdExportAccess(ctx, request, coldarchive.Digest(artifact), len(artifact), false); err != nil {
			return err
		}
		result := auditColdSummary(state, &payload)
		result.Verification = "database_audited"
		if json.NewEncoder(output).Encode(result) != nil {
			return errors.New("remote audit history verification output failed")
		}
		return nil
	}
	state, artifact, err := database.PrepareAuditColdExport(ctx, request)
	if err != nil {
		return err
	}
	previousState := state.State
	repaired := false
	if len(artifact) == 0 {
		artifact, err = directory.Read(*id)
		if errors.Is(err, os.ErrNotExist) {
			state, artifact, err = database.RebuildAuditColdExport(ctx, request)
			repaired = previousState == "published"
		}
		if err != nil {
			return err
		}
	}
	defer clear(artifact)
	validate := func(value []byte) error {
		payload, err := checkAuditColdArtifact(key, value, *domain, *id, &state)
		if err == nil {
			auditarchive.Clear(&payload)
		}
		return err
	}
	if repaired {
		if err := database.StartAuditColdExportRepair(ctx, request, coldarchive.Digest(artifact), len(artifact)); err != nil {
			return err
		}
	}
	if err := directory.Publish(*id, artifact, validate); err != nil {
		return err
	}
	state, err = database.FinishAuditColdExport(ctx, request, coldarchive.Digest(artifact), len(artifact))
	if err != nil {
		return err
	}
	if previousState == "published" {
		if err := database.RecordAuditColdExportAccess(ctx, request, coldarchive.Digest(artifact), len(artifact), repaired); err != nil {
			return err
		}
	}
	payload, err := checkAuditColdArtifact(key, artifact, *domain, *id, &state)
	if err != nil {
		return err
	}
	defer auditarchive.Clear(&payload)
	result := auditColdSummary(state, &payload)
	result.Verification = "published"
	if json.NewEncoder(output).Encode(result) != nil {
		return errors.New("remote audit history output failed; reconcile using the same export UUID")
	}
	return nil
}
