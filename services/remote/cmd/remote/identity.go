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

func runIdentityCommand(arguments []string, output io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("remote identities requires status or apply")
	}
	command := arguments[0]
	flags := flag.NewFlagSet("identities "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("authority-file", "", "protected complete current identity snapshot")
	if flags.Parse(arguments[1:]) != nil || flags.NArg() != 0 || (command != "status" && command != "apply") ||
		(command == "status" && *path != "") || (command == "apply" && *path == "") || os.Getenv("REMOTE_DATABASE_EPOCH") == "" || os.Getenv("REMOTE_ISSUER") == "" {
		return errors.New("remote identities requires explicit epoch, issuer and valid command arguments")
	}
	var snapshot store.IdentitySnapshot
	if command == "apply" {
		raw, err := readProtectedFile(*path, 8<<20)
		if err != nil {
			return errors.New("remote identity authority file is unavailable or unprotected")
		}
		defer clear(raw)
		if strictFileJSON(raw, &snapshot) != nil || store.ValidateIdentitySnapshot(snapshot, os.Getenv("REMOTE_DATABASE_EPOCH"), os.Getenv("REMOTE_ISSUER")) != nil {
			return errors.New("remote identity authority file is invalid")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	database, err := store.Open(ctx, os.Getenv("REMOTE_DATABASE_URL"))
	if err != nil {
		return errors.New("remote identity database is unavailable or insecurely configured")
	}
	defer database.Close()
	var result any
	if command == "status" {
		result, err = database.IdentitySyncStatus(ctx, os.Getenv("REMOTE_DATABASE_EPOCH"), os.Getenv("REMOTE_ISSUER"))
	} else {
		result, err = database.ApplyIdentitySnapshot(ctx, os.Getenv("REMOTE_DATABASE_EPOCH"), os.Getenv("REMOTE_ISSUER"), snapshot)
	}
	if err != nil {
		return err
	}
	if json.NewEncoder(output).Encode(result) != nil {
		return errors.New("remote identity result output failed; reconcile with the same operation UUID and snapshot")
	}
	return nil
}
