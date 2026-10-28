package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"dsh-mobile-ustc/services/remote/internal/coldarchive"
	"dsh-mobile-ustc/services/remote/internal/store"
)

type coldSummary struct {
	ExportID         string     `json:"export_id"`
	DomainID         string     `json:"domain_id"`
	BatchID          string     `json:"batch_id"`
	OperationEpoch   string     `json:"operation_epoch"`
	KeyID            string     `json:"key_id"`
	State            string     `json:"state"`
	Verification     string     `json:"verification,omitempty"`
	Events           int        `json:"events"`
	Acknowledgements int        `json:"acknowledgements"`
	ArtifactSHA256   string     `json:"artifact_sha256"`
	ArtifactSize     int        `json:"artifact_size"`
	PreparedAt       time.Time  `json:"prepared_at"`
	RetainUntil      *time.Time `json:"retain_until,omitempty"`
}

func summaryFor(state store.ControlExportState) coldSummary {
	return coldSummary{ExportID: state.ExportID, DomainID: state.DomainID, BatchID: state.BatchID, OperationEpoch: state.OperationEpoch, KeyID: state.KeyID,
		State: state.State, Events: state.Events, Acknowledgements: state.Acknowledgements, ArtifactSHA256: state.ArtifactSHA256, ArtifactSize: state.ArtifactSize, PreparedAt: state.PreparedAt}
}
func payloadSummary(payload coldarchive.Payload, artifact []byte) coldSummary {
	acks := 0
	for _, event := range payload.Events {
		acks += len(event.Acknowledgements)
	}
	retain := payload.Batch.RetainUntil
	return coldSummary{ExportID: payload.ExportID, DomainID: payload.DomainID, BatchID: payload.Batch.ID, OperationEpoch: payload.OperationEpoch, KeyID: payload.KeyID,
		State: "offline_verified", Verification: "offline", Events: len(payload.Events), Acknowledgements: acks, ArtifactSHA256: coldarchive.Digest(artifact), ArtifactSize: len(artifact), PreparedAt: payload.PreparedAt, RetainUntil: &retain}
}
func checkArtifact(key *coldarchive.Key, raw []byte, domain, id string, state *store.ControlExportState) (coldarchive.Payload, error) {
	payload, err := coldarchive.Open(key, raw, domain, id)
	if err != nil {
		return coldarchive.Payload{}, err
	}
	if state == nil {
		return payload, nil
	}
	acks := 0
	for _, event := range payload.Events {
		acks += len(event.Acknowledgements)
	}
	if len(raw) != state.ArtifactSize || !coldarchive.EqualDigest(coldarchive.Digest(raw), state.ArtifactSHA256) || payload.Batch.ID != state.BatchID || payload.OperationEpoch != state.OperationEpoch || payload.KeyID != state.KeyID ||
		!payload.PreparedAt.Equal(state.PreparedAt) || len(payload.Events) != state.Events || acks != state.Acknowledgements {
		return coldarchive.Payload{}, coldarchive.ErrConflict
	}
	return payload, nil
}

func runColdArchiveCommand(command string, arguments []string, output io.Writer) error {
	if command != "export" && command != "verify" && command != "verify-offline" && command != "abort-export" {
		return errors.New("remote archive command is invalid")
	}
	flags := flag.NewFlagSet("archive "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	id := flags.String("export-id", "", "stable export UUID")
	domain := flags.String("domain-id", "", "external archive domain UUID")
	batch := flags.String("batch-id", "", "source archive batch UUID")
	epoch := flags.String("expected-epoch", "", "external database epoch")
	keyID := flags.String("key-id", "", "archive key identifier")
	keyPath := flags.String("key-file", "", "protected raw 32-byte key")
	path := flags.String("directory", "", "owner-only archive directory")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || !coldarchive.UUID(*id) || !coldarchive.UUID(*domain) || !coldarchive.KeyID(*keyID) || *keyPath == "" || os.Getenv("REMOTE_ARCHIVE_DOMAIN_ID") != *domain {
		return errors.New("remote archive export identity or external domain is invalid")
	}
	if command == "verify-offline" {
		if *batch != "" || *epoch != "" || *path == "" {
			return errors.New("remote archive offline verification arguments are invalid")
		}
	} else if !coldarchive.UUID(*batch) || !coldarchive.UUID(*epoch) || os.Getenv("REMOTE_DATABASE_EPOCH") != *epoch || ((command == "abort-export") != (*path == "")) {
		return errors.New("remote archive requires a matching external epoch and valid operation arguments")
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
		directory, err = coldarchive.OpenDirectory(*path)
		if err != nil {
			return errors.New("remote archive directory is unavailable or unprotected")
		}
		defer directory.Close()
	}
	if command == "verify-offline" {
		artifact, err := directory.Read(*id)
		if err != nil {
			return errors.New("remote archive artifact is unavailable or invalid")
		}
		defer clear(artifact)
		payload, err := checkArtifact(key, artifact, *domain, *id, nil)
		if err != nil {
			return errors.New("remote archive artifact verification failed")
		}
		if json.NewEncoder(output).Encode(payloadSummary(payload, artifact)) != nil {
			return errors.New("remote archive verification output failed")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	database, err := store.Open(ctx, os.Getenv("REMOTE_DATABASE_URL"))
	if err != nil {
		return errors.New("remote archive database is unavailable or insecurely configured")
	}
	defer database.Close()
	request := store.ControlExportRequest{ExportID: *id, DomainID: *domain, DatabaseEpoch: *epoch, BatchID: *batch, Key: key}
	if directory != nil {
		request.DestinationFingerprint, err = directory.Fingerprint(key)
		if err != nil {
			return errors.New("remote archive directory identity is unavailable")
		}
	}
	if command == "abort-export" {
		state, err := database.AbortControlExport(ctx, request)
		if err != nil {
			return err
		}
		if json.NewEncoder(output).Encode(summaryFor(state)) != nil {
			return errors.New("remote archive abort output failed; reconcile using the same export UUID")
		}
		return nil
	}
	if command == "verify" {
		state, err := database.ControlExportForVerification(ctx, request)
		if err != nil {
			return err
		}
		if state.State != "published" {
			return store.ErrControlExportConflict
		}
		artifact, err := directory.Read(*id)
		if err != nil {
			return errors.New("remote archive artifact is unavailable or invalid")
		}
		defer clear(artifact)
		payload, err := checkArtifact(key, artifact, *domain, *id, &state)
		if err != nil {
			return errors.New("remote archive artifact verification failed")
		}
		if err := database.RecordControlExportAccess(ctx, request, coldarchive.Digest(artifact), len(artifact), false); err != nil {
			return err
		}
		result := summaryFor(state)
		result.Verification = "database_audited"
		retain := payload.Batch.RetainUntil
		result.RetainUntil = &retain
		if json.NewEncoder(output).Encode(result) != nil {
			return errors.New("remote archive verification output failed")
		}
		return nil
	}
	state, artifact, err := database.PrepareControlExport(ctx, request)
	if err != nil {
		return err
	}
	previousState := state.State
	repaired := false
	if len(artifact) == 0 {
		artifact, err = directory.Read(*id)
		if errors.Is(err, os.ErrNotExist) {
			state, artifact, err = database.RebuildControlExport(ctx, request)
			repaired = previousState == "published"
		}
		if err != nil {
			return err
		}
	}
	defer clear(artifact)
	validate := func(value []byte) error { _, err := checkArtifact(key, value, *domain, *id, &state); return err }
	if repaired {
		// A durable intent precedes filesystem changes. If the final audit fails
		// or the process crashes, an operator can verify and reconcile the file.
		if err := database.StartControlExportRepair(ctx, request, coldarchive.Digest(artifact), len(artifact)); err != nil {
			return err
		}
	}
	if err := directory.Publish(*id, artifact, validate); err != nil {
		return err
	}
	state, err = database.FinishControlExport(ctx, request, coldarchive.Digest(artifact), len(artifact))
	if err != nil {
		return err
	}
	if previousState == "published" {
		if err := database.RecordControlExportAccess(ctx, request, coldarchive.Digest(artifact), len(artifact), repaired); err != nil {
			return err
		}
	}
	payload, err := checkArtifact(key, artifact, *domain, *id, &state)
	if err != nil {
		return err
	}
	result := summaryFor(state)
	result.Verification = "published"
	retain := payload.Batch.RetainUntil
	result.RetainUntil = &retain
	if json.NewEncoder(output).Encode(result) != nil {
		return errors.New("remote archive output failed; reconcile using the same export UUID")
	}
	return nil
}
