package main

import (
	"bytes"
	"strings"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/store"
)

func TestApprovalEvidenceCLIRejectsInvalidArgumentsBeforeDatabase(t *testing.T) {
	t.Setenv("REMOTE_DATABASE_URL", "PRIVATE_INVALID_DSN")
	t.Setenv("REMOTE_DATABASE_EPOCH", store.OriginalDatabaseEpoch)
	id := "aaaaaaaa-1111-4111-8111-111111111111"
	for _, args := range [][]string{
		{"verify-approval"},
		{"verify-approval", "--approval-id", "bad", "--expected-epoch", store.OriginalDatabaseEpoch},
		{"verify-approval", "--approval-id", id, "--expected-epoch", "bbbbbbbb-1111-4111-8111-111111111111"},
		{"verify-approval", "--approval-id", id, "--expected-epoch", store.OriginalDatabaseEpoch, "extra"},
	} {
		var output bytes.Buffer
		err := runArchiveCommand(args, &output)
		if err == nil || strings.Contains(err.Error(), "PRIVATE_INVALID_DSN") || output.Len() != 0 {
			t.Fatal("invalid verification exposed configuration or succeeded", err)
		}
	}
}
