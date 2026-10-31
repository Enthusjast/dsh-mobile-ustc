package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"dsh-mobile-ustc/services/remote/internal/relay"
)

var errSendQueueConfiguration = errors.New("remote relay send queue limits are invalid")

func loadSendQueueLimits(path string) (relay.SendQueueLimits, error) {
	if path == "" {
		return relay.DefaultSendQueueLimits(), nil
	}
	raw, err := readProtectedFile(path, 4096)
	if err != nil {
		return relay.SendQueueLimits{}, errSendQueueConfiguration
	}
	limits, err := relay.ParseSendQueueLimits(raw)
	if err != nil {
		return relay.SendQueueLimits{}, errSendQueueConfiguration
	}
	return limits, nil
}

func runSendQueueDescription(args []string, output io.Writer) error {
	if len(args) == 0 || args[0] != "describe" {
		return errSendQueueConfiguration
	}
	flags := flag.NewFlagSet("queue-limits describe", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("limits-file", os.Getenv("REMOTE_RELAY_QUEUE_LIMITS_FILE"), "protected node queue limits")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return errSendQueueConfiguration
	}
	limits, err := loadSendQueueLimits(*path)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		Limits relay.SendQueueLimits `json:"limits"`
	}{limits})
}
