package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
)

func TestIdentitySyncCLIRejectsInvalidInputBeforeDatabaseAccess(t *testing.T) {
	t.Setenv("REMOTE_DATABASE_URL", "PRIVATE_INVALID_DATABASE")
	t.Setenv("REMOTE_DATABASE_EPOCH", store.OriginalDatabaseEpoch)
	t.Setenv("REMOTE_ISSUER", "https://id.example.edu")
	for _, args := range [][]string{nil, {"unknown"}, {"apply"}, {"status", "--authority-file", "private.json"}, {"status", "extra"}} {
		var output bytes.Buffer
		if err := runIdentityCommand(args, &output); err == nil || strings.Contains(err.Error(), "PRIVATE_INVALID_DATABASE") || output.Len() != 0 {
			t.Fatal("invalid command accepted or exposed database state", err)
		}
	}
	path := filepath.Join(t.TempDir(), "authority.json")
	for _, body := range []string{`{"v":1,"v":1}`, `{"v":1,"complete":true}`, `{"PRIVATE_SUBJECT":"secret"}`} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if err := runIdentityCommand([]string{"apply", "--authority-file", path}, &output); err == nil || strings.Contains(err.Error(), "PRIVATE_SUBJECT") || strings.Contains(err.Error(), "database") {
			t.Fatal("invalid snapshot reached database or leaked source", err)
		}
	}
}

func TestIdentitySyncCLIReconcilesLostOutputWithProductionBinary(t *testing.T) {
	binary := os.Getenv("REMOTE_TEST_SERVICE_BIN")
	if binary == "" {
		t.Skip("explicit disposable production service binary required")
	}
	ctx, db := testsupport.PostgresDatabase(t)
	dsn := archiveTestDSN(t, ctx, db)
	t.Setenv("REMOTE_DATABASE_URL", dsn)
	t.Setenv("REMOTE_DATABASE_EPOCH", store.OriginalDatabaseEpoch)
	t.Setenv("REMOTE_ISSUER", "https://id.example.edu")
	var output bytes.Buffer
	if err := runIdentityCommand([]string{"status"}, &output); err != nil {
		t.Fatal(err)
	}
	var state store.IdentitySyncState
	if json.Unmarshal(output.Bytes(), &state) != nil || state.Revision != 0 {
		t.Fatal("unexpected empty identity source")
	}
	input := store.IdentitySnapshot{Version: 1, Complete: true, OperationID: "aaaaaaaa-1111-4111-8111-111111111111", DatabaseEpoch: store.OriginalDatabaseEpoch, Issuer: "https://id.example.edu", Revision: 1, CapturedAt: time.Now().Add(-time.Second), ExpiresAt: time.Now().Add(5 * time.Minute),
		Organizations: []store.IdentityOrganization{{ID: "bbbbbbbb-1111-4111-8111-111111111111", Slug: "example", Name: "Example"}},
		Users:         []store.RecoveryUser{{Subject: "PRIVATE_CURRENT_SUBJECT", Status: "active", Memberships: []store.RecoveryMembership{{OrganizationID: "bbbbbbbb-1111-4111-8111-111111111111", Role: "member"}}}}}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "authority.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"apply", "--authority-file", path}
	if err = runIdentityCommand(args, archiveFailedOutput{}); err == nil || !strings.Contains(err.Error(), "same operation UUID") || strings.Contains(err.Error(), "PRIVATE_OUTPUT_ERROR") {
		t.Fatal("lost output was not reconcilable", err)
	}
	command := exec.CommandContext(ctx, binary, append([]string{"identities"}, args...)...)
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "REMOTE_DATABASE_URL=" + dsn, "REMOTE_DATABASE_EPOCH=" + store.OriginalDatabaseEpoch, "REMOTE_ISSUER=" + input.Issuer}
	result, err := command.CombinedOutput()
	if err != nil {
		t.Fatal("production identity retry failed", err, string(result))
	}
	var run store.IdentitySyncRun
	if json.Unmarshal(result, &run) != nil || run.ID != input.OperationID || run.Revision != 1 || run.Counts["users_created"] != 1 {
		t.Fatal("CLI did not return original committed receipt")
	}
	if bytes.Contains(result, []byte("PRIVATE_CURRENT_SUBJECT")) || bytes.Contains(result, []byte(dsn)) {
		t.Fatal("CLI exposed source or database credentials")
	}
	var runs, audits int
	if err = db.QueryRowContext(ctx, `select (select count(*) from identity_sync_runs),(select count(*) from audit_log where action='identity.sync')`).Scan(&runs, &audits); err != nil || runs != 1 || audits != 1 {
		t.Fatal("retry duplicated synchronization", err)
	}
}
