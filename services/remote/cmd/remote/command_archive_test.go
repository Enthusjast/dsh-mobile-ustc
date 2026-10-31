package main

import (
	"bytes"
	"dsh-mobile-ustc/services/remote/internal/store"
	"strings"
	"testing"
)

func TestCommandArchiveCLIRejectsInvalidParametersBeforeDatabase(t *testing.T) {
	t.Setenv("REMOTE_DATABASE_URL", "PRIVATE_INVALID_DSN")
	t.Setenv("REMOTE_DATABASE_EPOCH", store.OriginalDatabaseEpoch)
	base := []string{"commands", "--batch-id", "aaaaaaaa-1111-4111-8111-111111111111", "--expected-epoch", store.OriginalDatabaseEpoch}
	cases := [][]string{{"commands"}, append(append([]string{}, base...), "extra")}
	for _, change := range [][]string{{"--hot-days", "0"}, {"--hot-days", "3651"}, {"--limit", "0"}, {"--limit", "129"}, {"--cold-days", "-1"}, {"--cold-days", "3651"}, {"--expected-epoch", "bbbbbbbb-1111-4111-8111-111111111111"}} {
		cases = append(cases, append(append([]string{}, base...), change...))
	}
	for _, args := range cases {
		var out bytes.Buffer
		err := runArchiveCommand(args, &out)
		if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "PRIVATE_") {
			t.Fatal("invalid archive parameters exposed configuration or succeeded", err)
		}
	}
}
