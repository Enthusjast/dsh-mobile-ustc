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
	"dsh-mobile-ustc/services/remote/internal/evidencearchive"
	"dsh-mobile-ustc/services/remote/internal/store"
)

type evidenceExportSummary struct {
	ExportID          string     `json:"export_id"`
	DomainID          string     `json:"domain_id"`
	ApprovalID        string     `json:"approval_id"`
	OperationEpoch    string     `json:"operation_epoch"`
	KeyID             string     `json:"key_id"`
	State             string     `json:"state"`
	Verification      string     `json:"verification,omitempty"`
	FingerprintSource string     `json:"fingerprint_source,omitempty"`
	ArtifactSHA256    string     `json:"artifact_sha256"`
	ArtifactSize      int        `json:"artifact_size"`
	PreparedAt        time.Time  `json:"prepared_at"`
	RetainUntil       *time.Time `json:"retain_until,omitempty"`
}

func evidenceSummary(state store.EvidenceExportState, proof *evidencearchive.Payload) evidenceExportSummary {
	result := evidenceExportSummary{ExportID: state.ExportID, DomainID: state.DomainID, ApprovalID: state.ApprovalID, OperationEpoch: state.OperationEpoch, KeyID: state.KeyID,
		State: state.State, ArtifactSHA256: state.ArtifactSHA256, ArtifactSize: state.ArtifactSize, PreparedAt: state.PreparedAt}
	if proof != nil {
		retained := proof.Proof.RetainUntil
		result.FingerprintSource, result.RetainUntil = proof.Proof.FingerprintSource, &retained
	}
	return result
}

func checkEvidenceArtifact(key *coldarchive.Key, raw []byte, domain, id string, state *store.EvidenceExportState) (evidencearchive.Payload, error) {
	payload, err := evidencearchive.Open(key, raw, domain, id)
	if err != nil {
		return evidencearchive.Payload{}, err
	}
	if state != nil && (len(raw) != state.ArtifactSize || !coldarchive.EqualDigest(coldarchive.Digest(raw), state.ArtifactSHA256) || payload.Proof.ApprovalID != state.ApprovalID ||
		payload.OperationEpoch != state.OperationEpoch || payload.KeyID != state.KeyID || !payload.PreparedAt.Equal(state.PreparedAt)) {
		return evidencearchive.Payload{}, coldarchive.ErrConflict
	}
	return payload, nil
}

func runEvidenceExportCommand(command string, arguments []string, output io.Writer) error {
	if command != "export-approval" && command != "verify-approval-export" && command != "verify-approval-offline" && command != "abort-approval-export" {
		return errors.New("remote approval evidence export command is invalid")
	}
	flags := flag.NewFlagSet("archive "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	id := flags.String("export-id", "", "stable export UUID")
	domain := flags.String("domain-id", "", "external archive domain UUID")
	approvalID := flags.String("approval-id", "", "source approval UUID")
	epoch := flags.String("expected-epoch", "", "external database epoch")
	keyID := flags.String("key-id", "", "archive key identifier")
	keyPath := flags.String("key-file", "", "protected raw 32-byte key")
	path := flags.String("directory", "", "owner-only archive directory")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || !coldarchive.UUID(*id) || !coldarchive.UUID(*domain) || !coldarchive.KeyID(*keyID) || *keyPath == "" || os.Getenv("REMOTE_ARCHIVE_DOMAIN_ID") != *domain {
		return errors.New("remote approval evidence export identity or external domain is invalid")
	}
	if command == "verify-approval-offline" {
		if *approvalID != "" || *epoch != "" || *path == "" {
			return errors.New("remote approval evidence offline verification arguments are invalid")
		}
	} else if !coldarchive.UUID(*approvalID) || !coldarchive.UUID(*epoch) || os.Getenv("REMOTE_DATABASE_EPOCH") != *epoch || ((command == "abort-approval-export") != (*path == "")) {
		return errors.New("remote approval evidence export requires a matching external epoch and valid operation arguments")
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
	if command == "verify-approval-offline" {
		artifact, err := directory.Read(*id)
		if err != nil {
			return errors.New("remote approval evidence artifact is unavailable or invalid")
		}
		defer clear(artifact)
		payload, err := checkEvidenceArtifact(key, artifact, *domain, *id, nil)
		if err != nil {
			return errors.New("remote approval evidence artifact verification failed")
		}
		state := store.EvidenceExportState{ExportID: payload.ExportID, DomainID: payload.DomainID, ApprovalID: payload.Proof.ApprovalID, OperationEpoch: payload.OperationEpoch,
			KeyID: payload.KeyID, State: "offline_verified", ArtifactSHA256: coldarchive.Digest(artifact), ArtifactSize: len(artifact), PreparedAt: payload.PreparedAt}
		result := evidenceSummary(state, &payload)
		result.Verification = "offline"
		if json.NewEncoder(output).Encode(result) != nil {
			return errors.New("remote approval evidence verification output failed")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	database, err := store.Open(ctx, os.Getenv("REMOTE_DATABASE_URL"))
	if err != nil {
		return errors.New("remote approval evidence database is unavailable or insecurely configured")
	}
	defer database.Close()
	request := store.EvidenceExportRequest{ExportID: *id, DomainID: *domain, DatabaseEpoch: *epoch, ApprovalID: *approvalID, Key: key}
	if directory != nil {
		request.DestinationFingerprint, err = directory.Fingerprint(key)
		if err != nil {
			return errors.New("remote archive directory identity is unavailable")
		}
	}
	if command == "abort-approval-export" {
		state, err := database.AbortEvidenceExport(ctx, request)
		if err != nil {
			return err
		}
		if json.NewEncoder(output).Encode(evidenceSummary(state, nil)) != nil {
			return errors.New("remote approval evidence abort output failed; reconcile using the same export UUID")
		}
		return nil
	}
	if command == "verify-approval-export" {
		state, err := database.EvidenceExportForVerification(ctx, request)
		if err != nil {
			return err
		}
		if state.State != "published" {
			return store.ErrEvidenceExportConflict
		}
		artifact, err := directory.Read(*id)
		if err != nil {
			return errors.New("remote approval evidence artifact is unavailable or invalid")
		}
		defer clear(artifact)
		payload, err := checkEvidenceArtifact(key, artifact, *domain, *id, &state)
		if err != nil {
			return errors.New("remote approval evidence artifact verification failed")
		}
		if err := database.RecordEvidenceExportAccess(ctx, request, coldarchive.Digest(artifact), len(artifact), false); err != nil {
			return err
		}
		result := evidenceSummary(state, &payload)
		result.Verification = "database_audited"
		if json.NewEncoder(output).Encode(result) != nil {
			return errors.New("remote approval evidence verification output failed")
		}
		return nil
	}
	state, artifact, err := database.PrepareEvidenceExport(ctx, request)
	if err != nil {
		return err
	}
	previousState := state.State
	repaired := false
	if len(artifact) == 0 {
		artifact, err = directory.Read(*id)
		if errors.Is(err, os.ErrNotExist) {
			state, artifact, err = database.RebuildEvidenceExport(ctx, request)
			repaired = previousState == "published"
		}
		if err != nil {
			return err
		}
	}
	defer clear(artifact)
	validate := func(value []byte) error {
		_, err := checkEvidenceArtifact(key, value, *domain, *id, &state)
		return err
	}
	if repaired {
		if err := database.StartEvidenceExportRepair(ctx, request, coldarchive.Digest(artifact), len(artifact)); err != nil {
			return err
		}
	}
	if err := directory.Publish(*id, artifact, validate); err != nil {
		return err
	}
	state, err = database.FinishEvidenceExport(ctx, request, coldarchive.Digest(artifact), len(artifact))
	if err != nil {
		return err
	}
	if previousState == "published" {
		if err := database.RecordEvidenceExportAccess(ctx, request, coldarchive.Digest(artifact), len(artifact), repaired); err != nil {
			return err
		}
	}
	payload, err := checkEvidenceArtifact(key, artifact, *domain, *id, &state)
	if err != nil {
		return err
	}
	result := evidenceSummary(state, &payload)
	result.Verification = "published"
	if json.NewEncoder(output).Encode(result) != nil {
		return errors.New("remote approval evidence output failed; reconcile using the same export UUID")
	}
	return nil
}
