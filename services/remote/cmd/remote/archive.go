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

// Administrative local CLI only; no listener or caller-selected source SQL.
func runArchiveCommand(arguments []string, output io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("remote archive requires control, export, verify, verify-offline or abort-export")
	}
	if arguments[0] != "control" {
		return runColdArchiveCommand(arguments[0], arguments[1:], output)
	}
	flags := flag.NewFlagSet("archive control", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	id := flags.String("batch-id", "", "stable archive operation UUID")
	epoch := flags.String("expected-epoch", "", "external deployment database epoch")
	limit := flags.Int("limit", 64, "bounded source batch")
	retention := flags.Int("retention-years", 1, "minimum archive retention in years")
	if flags.Parse(arguments[1:]) != nil || flags.NArg() != 0 || !(store.ControlArchiveRequest{BatchID: *id, DatabaseEpoch: *epoch, Limit: *limit, RetentionYears: *retention}).Valid() || os.Getenv("REMOTE_DATABASE_EPOCH") != *epoch {
		return errors.New("remote archive requires valid batch/epoch UUIDs, limit 1–128, retention 1–10 years and matching external epoch")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	database, err := store.Open(ctx, os.Getenv("REMOTE_DATABASE_URL"))
	if err != nil {
		return errors.New("remote archive database is unavailable or insecurely configured")
	}
	defer database.Close()
	result, err := database.ArchiveControlEvents(ctx, store.ControlArchiveRequest{BatchID: *id, DatabaseEpoch: *epoch, Limit: *limit, RetentionYears: *retention})
	if err != nil {
		return err
	}
	if json.NewEncoder(output).Encode(result) != nil {
		return errors.New("remote archive result output failed; reconcile with the same batch UUID")
	}
	return nil
}
