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

func runApprovalEvidenceCommand(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("archive verify-approval", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	id := flags.String("approval-id", "", "approval evidence UUID")
	epoch := flags.String("expected-epoch", "", "external deployment database epoch")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || !coldarchive.UUID(*id) || !coldarchive.UUID(*epoch) || os.Getenv("REMOTE_DATABASE_EPOCH") != *epoch {
		return errors.New("remote approval evidence verification requires valid UUIDs and the matching external epoch")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	database, err := store.Open(ctx, os.Getenv("REMOTE_DATABASE_URL"))
	if err != nil {
		return errors.New("remote approval evidence database is unavailable or insecurely configured")
	}
	defer database.Close()
	result, err := database.VerifyApprovalEvidence(ctx, *id, *epoch)
	if err != nil {
		return err
	}
	if json.NewEncoder(output).Encode(result) != nil {
		return errors.New("remote approval evidence verification output failed")
	}
	return nil
}
