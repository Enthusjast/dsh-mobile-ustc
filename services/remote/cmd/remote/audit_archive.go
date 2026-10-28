package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

func runAuditArchiveCommand(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("archive audit", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	id := flags.String("batch-id", "", "stable audit archive operation UUID")
	epoch := flags.String("expected-epoch", "", "external deployment database epoch")
	limit := flags.Int("limit", 64, "bounded source batch")
	retention := flags.Int("retention-years", 1, "minimum archive retention in years")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 {
		return errors.New("remote audit archive arguments are invalid")
	}
	request := store.AuditArchiveRequest{BatchID: *id, DatabaseEpoch: *epoch, Limit: *limit, RetentionYears: *retention}
	if !request.Valid() || os.Getenv("REMOTE_DATABASE_EPOCH") != *epoch {
		return errors.New("remote audit archive requires valid batch/epoch UUIDs, limit 1–128, retention 1–10 years and matching external epoch")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	database, err := store.Open(ctx, os.Getenv("REMOTE_DATABASE_URL"))
	if err != nil {
		return errors.New("remote audit archive database is unavailable or insecurely configured")
	}
	defer database.Close()
	result, err := database.ArchiveAuditHistory(ctx, request)
	if err != nil {
		return err
	}
	if json.NewEncoder(output).Encode(result) != nil {
		return errors.New("remote audit archive output failed; reconcile with the same batch UUID")
	}
	return nil
}
