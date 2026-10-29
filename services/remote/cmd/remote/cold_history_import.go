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

// The imported document is inert history, never a live authorization or event.
func runColdHistoryImportCommand(command string, arguments []string, output io.Writer) error {
	kind := ""
	switch command {
	case "import-audit":
		kind = "audit"
	case "import-approval":
		kind = "approval"
	default:
		return errors.New("remote cold history import command is invalid")
	}
	flags := flag.NewFlagSet("archive "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	importID := flags.String("import-id", "", "stable import UUID")
	exportID := flags.String("export-id", "", "source export UUID")
	domain := flags.String("domain-id", "", "external archive domain UUID")
	epoch := flags.String("expected-epoch", "", "external target database epoch")
	keyID := flags.String("key-id", "", "archive key identifier")
	keyPath := flags.String("key-file", "", "protected raw 32-byte key")
	path := flags.String("directory", "", "owner-only archive directory")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || !coldarchive.UUID(*importID) || !coldarchive.UUID(*exportID) || !coldarchive.UUID(*domain) || !coldarchive.UUID(*epoch) ||
		!coldarchive.KeyID(*keyID) || *keyPath == "" || *path == "" || os.Getenv("REMOTE_ARCHIVE_DOMAIN_ID") != *domain || os.Getenv("REMOTE_DATABASE_EPOCH") != *epoch {
		return errors.New("remote cold history import requires valid identities and matching external domain and epoch")
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
	limit := coldarchive.MaxArtifact
	if kind == "audit" {
		limit = auditarchive.MaxArtifact
	}
	directory, err := coldarchive.OpenDirectoryWithLimit(*path, limit)
	if err != nil {
		return errors.New("remote archive directory is unavailable or unprotected")
	}
	defer directory.Close()
	location, err := directory.Fingerprint(key)
	if err != nil {
		return errors.New("remote archive directory identity is unavailable")
	}
	artifact, err := directory.Read(*exportID)
	if err != nil {
		return errors.New("remote archive artifact is unavailable or invalid")
	}
	defer clear(artifact)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	database, err := store.Open(ctx, os.Getenv("REMOTE_DATABASE_URL"))
	if err != nil {
		return errors.New("remote cold history database is unavailable or insecurely configured")
	}
	defer database.Close()
	request := store.ColdHistoryImportRequest{Kind: kind, ImportID: *importID, ExportID: *exportID, DomainID: *domain, DatabaseEpoch: *epoch, AccessFingerprint: location, Key: key}
	result, err := database.ImportColdHistory(ctx, request, artifact)
	if err != nil {
		return err
	}
	if json.NewEncoder(output).Encode(result) != nil {
		return errors.New("remote cold history import output failed; reconcile using the same import UUID")
	}
	return nil
}
