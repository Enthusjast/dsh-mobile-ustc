package main

import (
	"bytes"
	"strings"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/store"
)

func TestAuditColdExportCLIRejectsInvalidArgumentsWithoutDisclosure(t *testing.T) {
	domain := "aaaaaaaa-1111-4111-8111-111111111111"
	id := "bbbbbbbb-1111-4111-8111-111111111111"
	t.Setenv("REMOTE_ARCHIVE_DOMAIN_ID", domain)
	t.Setenv("REMOTE_DATABASE_EPOCH", store.OriginalDatabaseEpoch)
	t.Setenv("REMOTE_DATABASE_URL", "PRIVATE_INVALID_DSN")
	for _, args := range [][]string{
		{"export-audit"},
		{"export-audit", "--export-id", id, "--domain-id", domain, "--batch-id", id, "--expected-epoch", "cccccccc-1111-4111-8111-111111111111", "--key-id", "key", "--key-file", "/PRIVATE_KEY_PATH", "--directory", "/PRIVATE_DIRECTORY"},
		{"verify-audit-offline", "--export-id", id, "--domain-id", domain, "--batch-id", id, "--key-id", "key", "--key-file", "/PRIVATE_KEY_PATH", "--directory", "/PRIVATE_DIRECTORY"},
		{"abort-audit-export", "--export-id", id, "--domain-id", domain, "--batch-id", id, "--expected-epoch", store.OriginalDatabaseEpoch, "--key-id", "key", "--key-file", "/PRIVATE_KEY_PATH", "--directory", "/PRIVATE_DIRECTORY"},
	} {
		var output bytes.Buffer
		err := runArchiveCommand(args, &output)
		if err == nil || output.Len() != 0 || strings.Contains(err.Error(), "PRIVATE_") {
			t.Fatal("invalid audit export exposed configuration or succeeded", err)
		}
	}
}
