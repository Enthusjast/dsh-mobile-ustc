package main

import (
	"bytes"
	"dsh-mobile-ustc/services/remote/internal/store"
	"strings"
	"testing"
)

func TestApprovalEvidenceRetentionCLIRejectsInvalidArgumentsBeforeDatabase(t *testing.T) {
	t.Setenv("REMOTE_DATABASE_URL", "PRIVATE_INVALID_DSN")
	t.Setenv("REMOTE_DATABASE_EPOCH", store.OriginalDatabaseEpoch)
	id := "aaaaaaaa-1111-4111-8111-111111111111"
	valid := []string{"retain-approval", "--operation-id", id, "--approval-id", id, "--expected-epoch", store.OriginalDatabaseEpoch, "--retention-years", "3"}
	cases := [][]string{{"retain-approval"}, append(append([]string{}, valid...), "extra")}
	for _, index := range []int{2, 4, 6, 8} {
		candidate := append([]string{}, valid...)
		candidate[index] = "invalid"
		cases = append(cases, candidate)
	}
	for _, years := range []string{"0", "1", "11", "-1"} {
		candidate := append([]string{}, valid...)
		candidate[8] = years
		cases = append(cases, candidate)
	}
	mismatch := append([]string{}, valid...)
	mismatch[6] = "bbbbbbbb-1111-4111-8111-111111111111"
	cases = append(cases, mismatch)
	for _, args := range cases {
		var output bytes.Buffer
		err := runArchiveCommand(args, &output)
		if err == nil || output.Len() != 0 || strings.Contains(err.Error(), "PRIVATE_") {
			t.Fatal("invalid extension succeeded or exposed configuration", err)
		}
	}
}
