package main

import (
	"context"
	"dsh-mobile-ustc/services/remote/internal/store"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"time"
)

func runApprovalEvidenceRetentionCommand(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("archive retain-approval", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	id := flags.String("operation-id", "", "stable retention operation UUID")
	approval := flags.String("approval-id", "", "existing approval evidence UUID")
	epoch := flags.String("expected-epoch", "", "external deployment database epoch")
	years := flags.Int("retention-years", 0, "total UTC calendar years from original decision")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 {
		return errors.New("remote evidence retention requires valid arguments")
	}
	request := store.ApprovalEvidenceRetentionRequest{OperationID: *id, ApprovalID: *approval, DatabaseEpoch: *epoch, RetentionYears: *years}
	if !request.Valid() || os.Getenv("REMOTE_DATABASE_EPOCH") != *epoch {
		return errors.New("remote evidence retention requires valid UUIDs, retention 2–10 years and the matching external epoch")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	database, err := store.Open(ctx, os.Getenv("REMOTE_DATABASE_URL"))
	if err != nil {
		return errors.New("remote evidence retention database is unavailable or insecurely configured")
	}
	defer database.Close()
	result, err := database.ExtendApprovalEvidenceRetention(ctx, request)
	if err != nil {
		return err
	}
	if json.NewEncoder(output).Encode(result) != nil {
		return errors.New("remote evidence retention output failed; reconcile with the same operation UUID")
	}
	return nil
}
