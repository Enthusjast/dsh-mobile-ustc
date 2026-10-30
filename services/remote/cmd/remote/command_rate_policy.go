package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"regexp"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

var commandRateEpochPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func runCommandRateCommand(args []string, output io.Writer) error {
	if len(args) > 0 && args[0] == "describe" {
		return runCommandRateDescription(args, output)
	}
	if len(args) == 0 || (args[0] != "status" && args[0] != "replace") {
		return errCommandRateConfiguration
	}
	command := args[0]
	flags := flag.NewFlagSet("command-limits "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var path, id, expected *string
	if command == "replace" {
		path = flags.String("policy-file", "", "protected new command policy")
		id = flags.String("operation-id", "", "stable replacement operation UUID")
		expected = flags.String("expected-sha256", "", "currently installed policy digest")
	}
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || !commandRateEpochPattern.MatchString(os.Getenv("REMOTE_DATABASE_EPOCH")) {
		return errCommandRateConfiguration
	}
	var limits store.CommandRateLimits
	var err error
	if command == "replace" {
		if *path == "" {
			return errCommandRateConfiguration
		}
		limits, err = loadCommandRateLimits(*path)
		if err != nil || !store.ValidCommandRatePolicyReplacement(os.Getenv("REMOTE_DATABASE_EPOCH"), *id, *expected, limits) {
			return errCommandRateConfiguration
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	database, err := store.Open(ctx, os.Getenv("REMOTE_DATABASE_URL"))
	if err != nil {
		return errors.New("remote command policy database is unavailable or insecurely configured")
	}
	defer database.Close()
	var result any
	if command == "status" {
		result, err = database.CommandRatePolicyStatus(ctx, os.Getenv("REMOTE_DATABASE_EPOCH"))
	} else {
		result, err = database.ReplaceCommandRatePolicy(ctx, os.Getenv("REMOTE_DATABASE_EPOCH"), *id, *expected, limits)
	}
	if err != nil {
		return err
	}
	if json.NewEncoder(output).Encode(result) != nil {
		return errors.New("remote command policy result output failed; reconcile with the same operation UUID and parameters")
	}
	return nil
}
