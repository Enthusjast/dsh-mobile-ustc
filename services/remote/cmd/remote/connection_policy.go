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

func runConnectionLimitCommand(args []string, output io.Writer) error {
	if len(args) > 0 && args[0] == "describe" {
		return runConnectionLimitDescription(args, output)
	}
	if len(args) == 0 || (args[0] != "status" && args[0] != "replace") {
		return errConnectionLimitConfiguration
	}
	command := args[0]
	flags := flag.NewFlagSet("connection-limits "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var path, id, expected *string
	if command == "replace" {
		path = flags.String("policy-file", "", "protected new connection policy")
		id = flags.String("operation-id", "", "stable replacement operation UUID")
		expected = flags.String("expected-sha256", "", "currently installed policy digest")
	}
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || !commandRateEpochPattern.MatchString(os.Getenv("REMOTE_DATABASE_EPOCH")) {
		return errConnectionLimitConfiguration
	}
	var limits store.ConnectionLimits
	var err error
	if command == "replace" {
		if *path == "" {
			return errConnectionLimitConfiguration
		}
		limits, err = loadConnectionLimits(*path)
		if err != nil || !store.ValidConnectionPolicyReplacement(os.Getenv("REMOTE_DATABASE_EPOCH"), *id, *expected, limits) {
			return errConnectionLimitConfiguration
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	database, err := store.Open(ctx, os.Getenv("REMOTE_DATABASE_URL"))
	if err != nil {
		return errors.New("remote connection policy database is unavailable or insecurely configured")
	}
	defer database.Close()
	var result any
	if command == "status" {
		result, err = database.ConnectionPolicyStatus(ctx, os.Getenv("REMOTE_DATABASE_EPOCH"))
	} else {
		result, err = database.ReplaceConnectionPolicy(ctx, os.Getenv("REMOTE_DATABASE_EPOCH"), *id, *expected, limits)
	}
	if err != nil {
		return err
	}
	if json.NewEncoder(output).Encode(result) != nil {
		return errors.New("remote connection policy result output failed; reconcile with the same operation UUID and parameters")
	}
	return nil
}
