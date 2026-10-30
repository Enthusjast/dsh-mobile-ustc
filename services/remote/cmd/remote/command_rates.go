package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"strings"

	"dsh-mobile-ustc/services/remote/internal/store"
)

var errCommandRateConfiguration = errors.New("remote shared command admission limits are invalid, unavailable or inconsistent")

func loadCommandRateLimits(path string) (store.CommandRateLimits, error) {
	if path == "" {
		return store.DefaultCommandRateLimits(), nil
	}
	if strings.TrimSpace(path) != path {
		return store.CommandRateLimits{}, errCommandRateConfiguration
	}
	raw, err := readProtectedFile(path, 8<<10)
	if err != nil {
		return store.CommandRateLimits{}, errCommandRateConfiguration
	}
	limits, err := store.ParseCommandRateLimits(raw)
	if err != nil {
		return limits, errCommandRateConfiguration
	}
	return limits, nil
}

func runCommandRateDescription(args []string, output io.Writer) error {
	if len(args) == 0 || args[0] != "describe" {
		return errCommandRateConfiguration
	}
	flags := flag.NewFlagSet("command-limits describe", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("policy-file", os.Getenv("REMOTE_COMMAND_LIMITS_FILE"), "protected command admission policy")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return errCommandRateConfiguration
	}
	limits, err := loadCommandRateLimits(*path)
	if err != nil {
		return err
	}
	digest, err := limits.PolicyDigest()
	if err != nil {
		return errCommandRateConfiguration
	}
	return json.NewEncoder(output).Encode(struct {
		Policy store.CommandRateLimits `json:"policy"`
		SHA256 string                  `json:"policy_sha256"`
	}{limits, hex.EncodeToString(digest[:])})
}
