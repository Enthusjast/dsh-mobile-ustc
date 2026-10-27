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

func runRecoveryCommand(arguments []string, output io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("remote recovery requires status, quarantine or release")
	}
	command := arguments[0]
	flags := flag.NewFlagSet("recovery", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	id := flags.String("recovery-id", "", "stable operation UUID")
	expected := flags.String("expected-epoch", "", "epoch present in the restored backup")
	epoch := flags.String("epoch", "", "fresh epoch from external deployment configuration")
	path := flags.String("authority-file", "", "protected current authority snapshot")
	if flags.Parse(arguments[1:]) != nil || flags.NArg() != 0 {
		return errors.New("remote recovery arguments are invalid")
	}
	if command != "status" && command != "quarantine" && command != "release" {
		return errors.New("remote recovery command is invalid")
	}
	if command == "quarantine" && (*id == "" || *expected == "" || *epoch == "" || *path != "" || os.Getenv("REMOTE_DATABASE_EPOCH") != *epoch) {
		return errors.New("remote recovery quarantine requires matching external epoch and operation identifiers")
	}
	if command == "release" && (*id == "" || *path == "" || *expected != "" || *epoch != "" || os.Getenv("REMOTE_DATABASE_EPOCH") == "" || os.Getenv("REMOTE_ISSUER") == "") {
		return errors.New("remote recovery release requires external epoch, issuer and protected authority snapshot")
	}
	if command == "status" && (*id != "" || *expected != "" || *epoch != "" || *path != "") {
		return errors.New("remote recovery status does not accept mutation flags")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	database, err := store.Open(ctx, os.Getenv("REMOTE_DATABASE_URL"))
	if err != nil {
		return errors.New("remote recovery database is unavailable or insecurely configured")
	}
	defer database.Close()
	var result any
	switch command {
	case "status":
		result, err = database.RecoveryStatus(ctx)
	case "quarantine":
		result, err = database.QuarantineRecovery(ctx, *id, *expected, *epoch)
	case "release":
		raw, readErr := readProtectedFile(*path, 8<<20)
		if readErr != nil {
			return errors.New("remote recovery authority file is unavailable or unprotected")
		}
		defer clear(raw)
		var authority store.RecoveryAuthority
		if strictFileJSON(raw, &authority) != nil || authority.RecoveryID != *id {
			return errors.New("remote recovery authority file is invalid")
		}
		result, err = database.ReleaseRecovery(ctx, os.Getenv("REMOTE_DATABASE_EPOCH"), os.Getenv("REMOTE_ISSUER"), authority)
	}
	if err != nil {
		return err
	}
	if err := json.NewEncoder(output).Encode(result); err != nil {
		return errors.New("remote recovery result output failed; reconcile using the same operation UUID")
	}
	return nil
}
