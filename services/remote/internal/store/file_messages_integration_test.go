package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
)

type messageFileFixture struct {
	*handoffFixture
	ticket TicketRedemption
}

func newMessageFileFixture(t *testing.T) *messageFileFixture {
	t.Helper()
	h := newHandoffFixture(t)
	h.exec(t, `update runtime_grants set scope=jsonb_set(scope,'{actions}',(scope->'actions')||'["message.submit","command.status"]'::jsonb)`)
	ticket := TicketRedemption{UserID: h.file.UploaderID, DeviceID: h.file.DeviceID, RuntimeID: h.file.RuntimeID, DeviceKeyVersion: h.file.KeyVersion, ProofKeyThumbprint: h.file.ProofKeyJKT, GrantVersion: h.file.GrantVersion}
	var raw []byte
	if err := h.database.DB.QueryRowContext(h.ctx, `select scope from runtime_grants where runtime_id=$1 and user_id=$2`, ticket.RuntimeID, ticket.UserID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &ticket.Scope); err != nil {
		t.Fatal(err)
	}
	return &messageFileFixture{h, ticket}
}
func (h *messageFileFixture) stage(t *testing.T, file files.Record) *files.FileOffer {
	t.Helper()
	offer, err := h.repository.IssueHandoff(h.ctx, h.host, file.ID, fileTestPolicy)
	if err != nil || offer == nil {
		t.Fatalf("stage offer: %v", err)
	}
	if _, err := h.repository.RedeemFileRead(h.ctx, offer.HandoffID, offer.DownloadToken, fileTestPolicy, func(files.ReadPermit) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := h.repository.StageHandoff(h.ctx, h.host, offer.HandoffID, file.SHA256, file.SizeBytes, file.Name, fileTestPolicy); err != nil {
		t.Fatal(err)
	}
	return offer
}
func (h *messageFileFixture) record(t *testing.T, request string, ids ...string) (CommandStatus, error) {
	t.Helper()
	return h.database.RecordRealtimeFileCommand(h.ctx, h.ticket, h.host, request, h.file.SessionID, strings.Repeat("a", 64), fileTestPolicy, ids, func() bool { return true })
}
func (h *messageFileFixture) count(t *testing.T, table string) int {
	t.Helper()
	var count int
	// This helper's callers pass fixed test-owned table names.
	if err := h.database.DB.QueryRowContext(h.ctx, "select count(*) from "+table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestPostgresFileMessageAdmissionAndTerminalRetryAreAtomic(t *testing.T) {
	h := newMessageFileFixture(t)
	offer := h.stage(t, h.file)
	request := approvalTestUUID(t)
	first, err := h.record(t, request, h.file.ID)
	if err != nil || first.State != "received" {
		t.Fatalf("admission: %v", err)
	}
	if _, err := h.record(t, request, h.file.ID); err != nil {
		t.Fatal(err)
	}
	if h.count(t, "file_message_refs") != 1 || h.count(t, "commands") != 1 {
		t.Fatal("retry duplicated command or file ownership")
	}
	var audits int
	if err := h.database.DB.QueryRowContext(h.ctx, `select count(*) from audit_log where action='file.message_bound'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("binding audit duplicated")
	}
	if _, err := h.record(t, approvalTestUUID(t), h.file.ID); !errors.Is(err, files.ErrConflict) {
		t.Fatalf("another command reused upload: %v", err)
	}
	if h.count(t, "commands") != 1 {
		t.Fatal("failed binding persisted a command")
	}
	receipt := RelayCommandReceipt{InstallationID: h.host.InstallationID, KeyVersion: h.host.KeyVersion, RuntimeID: h.host.RuntimeID, RuntimeEpoch: h.host.RuntimeEpoch, ConnectionID: h.host.ConnectionID, DeviceID: h.ticket.DeviceID, RequestID: request, SessionID: h.file.SessionID, PayloadSHA256: first.PayloadSHA256, State: "host_accepted"}
	for _, state := range []string{"host_accepted", "dispatching", "agent_queued"} {
		receipt.State = state
		if _, err := h.database.RecordRealtimeCommandReceipt(h.ctx, receipt); err != nil {
			t.Fatal(err)
		}
	}
	if pending, err := h.repository.PendingHandoffFiles(h.ctx, h.host, fileTestPolicy, 2); err != nil || len(pending) != 0 {
		t.Fatal("consumed file was offered again")
	}
	if _, err := h.repository.RenewHandoff(h.ctx, h.host, offer.HandoffID, fileTestPolicy); !errors.Is(err, files.ErrStale) {
		t.Fatal("consumed file renewed its receipt authority")
	}
	h.exec(t, `update files set created_at=clock_timestamp()-interval '1 day',expires_at=clock_timestamp()-interval '1 second' where id=$1`, h.file.ID)
	if err := h.repository.EndHandoff(h.ctx, h.host, offer.HandoffID); err != nil {
		t.Fatal(err)
	}
	if retry, err := h.record(t, request, h.file.ID); err != nil || retry.State != "agent_queued" {
		t.Fatalf("terminal retry required a new receipt: %v", err)
	}
	if _, err := h.repository.IssueHandoff(h.ctx, h.host, h.file.ID, fileTestPolicy); err == nil {
		t.Fatal("consumed file received fresh authority")
	}
}

func TestPostgresFileMessageBatchFailureRollsBackEveryReference(t *testing.T) {
	h := newMessageFileFixture(t)
	h.input.RequestID = approvalTestUUID(t)
	other := h.scanning(t)
	claim := h.claim(t)
	if err := h.repository.CompleteScan(h.ctx, claim); err != nil {
		t.Fatal(err)
	}
	ordered := []files.Record{h.file, other}
	slices.SortFunc(ordered, func(a, b files.Record) int { return strings.Compare(a.ID, b.ID) })
	h.stage(t, ordered[0]) // The later file is clean, but never staged.
	if _, err := h.record(t, approvalTestUUID(t), ordered[0].ID, ordered[1].ID); !errors.Is(err, files.ErrStale) {
		t.Fatalf("unstaged batch result=%v", err)
	}
	if h.count(t, "commands") != 0 || h.count(t, "file_message_refs") != 0 {
		t.Fatal("batch failure left a partial command/file claim")
	}
	var audits int
	if err := h.database.DB.QueryRowContext(h.ctx, `select count(*) from audit_log where action in ('command.received','file.message_bound')`).Scan(&audits); err != nil || audits != 0 {
		t.Fatal("batch rollback retained success audit")
	}
	h.stage(t, ordered[1])
	if _, err := h.record(t, approvalTestUUID(t), ordered[0].ID, ordered[1].ID); err != nil {
		t.Fatal(err)
	}
	if h.count(t, "file_message_refs") != 2 {
		t.Fatal("complete batch did not claim both files")
	}
}

func TestPostgresFileMessageCompetingCommandsHaveOneWinner(t *testing.T) {
	h := newMessageFileFixture(t)
	h.stage(t, h.file)
	var wait sync.WaitGroup
	var winners atomic.Int32
	for range 8 {
		request := approvalTestUUID(t)
		wait.Go(func() {
			_, err := h.record(t, request, h.file.ID)
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, files.ErrConflict) {
				t.Error(err)
			}
		})
	}
	wait.Wait()
	if winners.Load() != 1 || h.count(t, "commands") != 1 || h.count(t, "file_message_refs") != 1 {
		t.Fatal("file/command reservation was not serializable")
	}
}

func TestPostgresFileMessageLostConnectionRollsBackTheWholeTransaction(t *testing.T) {
	h := newMessageFileFixture(t)
	h.stage(t, h.file)
	checks := 0
	_, err := h.database.RecordRealtimeFileCommand(h.ctx, h.ticket, h.host, approvalTestUUID(t), h.file.SessionID, strings.Repeat("a", 64), fileTestPolicy, []string{h.file.ID}, func() bool { checks++; return checks == 1 })
	if !errors.Is(err, files.ErrStale) || checks != 2 {
		t.Fatal("lost Host readiness did not fail the final check")
	}
	if h.count(t, "commands") != 0 || h.count(t, "file_message_refs") != 0 {
		t.Fatal("lost readiness committed a command or reference")
	}
	if _, err := h.database.RecordRealtimeFileCommand(h.ctx, h.ticket, h.host, approvalTestUUID(t), h.file.SessionID, strings.Repeat("a", 64), fileTestPolicy, []string{h.file.ID}, nil); !errors.Is(err, files.ErrStale) {
		t.Fatal("missing readiness callback admitted a fresh message")
	}
}

func TestPostgresFileMessageExpiredOriginalReturnsOnlyReconciliation(t *testing.T) {
	h := newMessageFileFixture(t)
	offer := h.stage(t, h.file)
	request := approvalTestUUID(t)
	if first, err := h.record(t, request, h.file.ID); err != nil || first.ReconcileFiles {
		t.Fatalf("first admission=%v", err)
	}
	if err := h.repository.EndHandoff(h.ctx, h.host, offer.HandoffID); err != nil {
		t.Fatal(err)
	}
	h.exec(t, `update files set created_at=clock_timestamp()-interval '1 day',expires_at=clock_timestamp()-interval '1 second',state='expired' where id=$1`, h.file.ID)
	retry, err := h.database.RecordRealtimeFileCommand(h.ctx, h.ticket, h.host, request, h.file.SessionID, strings.Repeat("a", 64), fileTestPolicy, []string{h.file.ID}, nil)
	if err != nil || !retry.ReconcileFiles || retry.State != "received" {
		t.Fatalf("read-only reconciliation=%+v err=%v", retry, err)
	}
	public, _ := json.Marshal(retry)
	if strings.Contains(string(public), "Reconcile") || strings.Contains(string(public), "reconcile") {
		t.Fatal("internal dispatch mode leaked into public status")
	}
	if _, err := h.record(t, approvalTestUUID(t), h.file.ID); err == nil {
		t.Fatal("expired upload admitted another command")
	}
	if _, err := h.record(t, request, approvalTestUUID(t)); !errors.Is(err, files.ErrConflict) {
		t.Fatal("reconciliation changed the original manifest")
	}
	if h.count(t, "commands") != 1 || h.count(t, "file_message_refs") != 1 {
		t.Fatal("reconciliation allocated another intent")
	}
	h.host.ConnectionID = approvalTestUUID(t)
	if _, err := h.database.RecordRealtimeFileCommand(h.ctx, h.ticket, h.host, request, h.file.SessionID, strings.Repeat("a", 64), fileTestPolicy, []string{h.file.ID}, nil); !errors.Is(err, files.ErrAccess) {
		t.Fatal("old Host connection obtained reconciliation")
	}
}

func TestPostgresFileMessageReconciliationRollsBackPartialHandoffChanges(t *testing.T) {
	h := newMessageFileFixture(t)
	h.input.RequestID = approvalTestUUID(t)
	other := h.scanning(t)
	claim := h.claim(t)
	if err := h.repository.CompleteScan(h.ctx, claim); err != nil {
		t.Fatal(err)
	}
	ordered := []files.Record{h.file, other}
	slices.SortFunc(ordered, func(a, b files.Record) int { return strings.Compare(a.ID, b.ID) })
	first := h.stage(t, ordered[0])
	h.stage(t, ordered[1])
	request := approvalTestUUID(t)
	if _, err := h.record(t, request, ordered[0].ID, ordered[1].ID); err != nil {
		t.Fatal(err)
	}
	if err := h.repository.EndHandoff(h.ctx, h.host, first.HandoffID); err != nil {
		t.Fatal(err)
	}
	fresh := h.stage(t, ordered[0])
	if fresh.HandoffID == first.HandoffID {
		t.Fatal("restaging did not rotate handoff")
	}
	h.exec(t, `update file_transfers set scanner_policy_sha256=$2 where file_id=$1`, ordered[1].ID, strings.Repeat("b", 64))
	retry, err := h.record(t, request, ordered[0].ID, ordered[1].ID)
	if err != nil || !retry.ReconcileFiles {
		t.Fatalf("reconciliation=%v", err)
	}
	var retained string
	if err := h.database.DB.QueryRowContext(h.ctx, `select handoff_id::text from file_message_refs where file_id=$1`, ordered[0].ID).Scan(&retained); err != nil || retained != first.HandoffID {
		t.Fatal("read-only fallback retained a partial handoff update")
	}
}

func TestPostgresFileMessageReconciliationRetainsCurrentCallerAuthorization(t *testing.T) {
	h := newMessageFileFixture(t)
	h.stage(t, h.file)
	request := approvalTestUUID(t)
	if _, err := h.record(t, request, h.file.ID); err != nil {
		t.Fatal(err)
	}
	h.exec(t, `update sessions set state='archived'`)
	if retry, err := h.record(t, request, h.file.ID); err != nil || !retry.ReconcileFiles {
		t.Fatal("archived original could not reconcile")
	}
	if _, err := h.record(t, approvalTestUUID(t), h.file.ID); err == nil {
		t.Fatal("archived session admitted a new file message")
	}
	h.exec(t, `update runtime_grants set grant_version=grant_version+1`)
	if _, err := h.record(t, request, h.file.ID); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("revoked caller acquired read-only dispatch")
	}
}

func TestPostgresFileMessageRejectsStaleAuthorityBeforeRecordingCommand(t *testing.T) {
	for _, variant := range []string{"connection", "epoch", "policy", "expired", "device", "grant", "archive", "unstaged", "duplicate"} {
		t.Run(variant, func(t *testing.T) {
			h := newMessageFileFixture(t)
			if variant != "unstaged" {
				h.stage(t, h.file)
			}
			ids := []string{h.file.ID}
			switch variant {
			case "connection":
				h.host.ConnectionID = approvalTestUUID(t)
			case "epoch":
				h.host.RuntimeEpoch = approvalTestUUID(t)
			case "policy":
				h.exec(t, `update file_transfers set scanner_policy_sha256=$1`, strings.Repeat("b", 64))
			case "expired":
				h.exec(t, `update files set created_at=clock_timestamp()-interval '1 day',expires_at=clock_timestamp()-interval '1 second'`)
			case "device":
				h.exec(t, `update file_transfers set device_key_version=device_key_version+1`)
			case "grant":
				h.exec(t, `update runtime_grants set grant_version=grant_version+1`)
			case "archive":
				h.exec(t, `update sessions set state='archived'`)
			case "duplicate":
				ids = append(ids, h.file.ID)
			}
			if _, err := h.record(t, approvalTestUUID(t), ids...); err == nil {
				t.Fatal("invalid file authority admitted")
			}
			if h.count(t, "commands") != 0 || h.count(t, "file_message_refs") != 0 {
				t.Fatal("invalid attachment left durable admission")
			}
		})
	}
}

func TestPostgresFileMessageMigrationRollbackCannotReviveConsumedUploads(t *testing.T) {
	h := newMessageFileFixture(t)
	offer := h.stage(t, h.file)
	if _, err := h.record(t, approvalTestUUID(t), h.file.ID); err != nil {
		t.Fatal(err)
	}
	_, source, _, _ := runtime.Caller(0)
	applyCommandArchiveFixtureMigration(t, h.ctx, h.database, "down")
	for _, name := range []string{"011_file_message_refs.down.sql", "011_file_message_refs.up.sql"} {
		raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../deploy/sql", name))
		if err != nil {
			t.Fatal(err)
		}
		h.exec(t, string(raw))
	}
	applyCommandArchiveFixtureMigration(t, h.ctx, h.database, "up")
	if _, err := h.repository.RenewHandoff(h.ctx, h.host, offer.HandoffID, fileTestPolicy); err == nil {
		t.Fatal("rollback revived old handoff")
	}
	if _, err := h.record(t, approvalTestUUID(t), h.file.ID); err == nil {
		t.Fatal("rollback revived consumed upload")
	}
	var expires time.Time
	var state string
	if err := h.database.DB.QueryRowContext(h.ctx, `select state,expires_at from files where id=$1`, h.file.ID).Scan(&state, &expires); err != nil || state != "expired" {
		t.Fatal("rollback did not expire referenced upload")
	}
}
