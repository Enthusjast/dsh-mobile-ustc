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

func runCommandArchiveCommand(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("archive commands", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	id := flags.String("batch-id", "", "stable command archive operation UUID")
	epoch := flags.String("expected-epoch", "", "external deployment database epoch")
	limit := flags.Int("limit", 64, "bounded source batch")
	hot := flags.Int("hot-days", 30, "minimum age of terminal command metadata")
	retention := flags.Int("cold-days", 0, "additional history retention after moving expired metadata")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 {
		return errors.New("remote command archive arguments are invalid")
	}
	request := store.CommandArchiveRequest{BatchID: *id, DatabaseEpoch: *epoch, Limit: *limit, ColdDays: *retention, HotDays: *hot}
	if !request.Valid() || os.Getenv("REMOTE_DATABASE_EPOCH") != *epoch {
		return errors.New("remote command archive requires valid batch/epoch UUIDs, limit 1–128, hot age 1–3650 days, additional history retention 0–3650 days and matching external epoch")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	database, err := store.Open(ctx, os.Getenv("REMOTE_DATABASE_URL"))
	if err != nil {
		return errors.New("remote command archive database is unavailable or insecurely configured")
	}
	defer database.Close()
	result, err := database.ArchiveCommandHistory(ctx, request)
	if err != nil {
		return err
	}
	if json.NewEncoder(output).Encode(result) != nil {
		return errors.New("remote command archive output failed; reconcile with the same batch UUID")
	}
	return nil
}
