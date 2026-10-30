package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"dsh-mobile-ustc/services/remote/internal/store"
)

var errConnectionLimitConfiguration = errors.New("remote shared connection limits are invalid, unavailable or inconsistent")

func loadConnectionLimits(path string) (store.ConnectionLimits, error) {
	if path == "" {
		return store.DefaultConnectionLimits(), nil
	}
	raw, err := readProtectedFile(path, 8<<10)
	if err != nil {
		return store.ConnectionLimits{}, errConnectionLimitConfiguration
	}
	limits, err := store.ParseConnectionLimits(raw)
	if err != nil {
		return limits, errConnectionLimitConfiguration
	}
	return limits, nil
}

func runConnectionLimitDescription(args []string, output io.Writer) error {
	if len(args) == 0 || args[0] != "describe" {
		return errConnectionLimitConfiguration
	}
	flags := flag.NewFlagSet("connection-limits describe", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("policy-file", os.Getenv("REMOTE_CONNECTION_LIMITS_FILE"), "protected connection limits")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return errConnectionLimitConfiguration
	}
	limits, err := loadConnectionLimits(*path)
	if err != nil {
		return err
	}
	digest, err := limits.PolicyDigest()
	if err != nil {
		return errConnectionLimitConfiguration
	}
	return json.NewEncoder(output).Encode(struct {
		Policy store.ConnectionLimits `json:"policy"`
		SHA256 string                 `json:"policy_sha256"`
	}{limits, hex.EncodeToString(digest[:])})
}
