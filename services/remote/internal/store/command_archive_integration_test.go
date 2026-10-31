package store

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
)

func commandArchiveRequest(t *testing.T) CommandArchiveRequest {
	t.Helper()
	return CommandArchiveRequest{BatchID: approvalTestUUID(t), DatabaseEpoch: OriginalDatabaseEpoch, Limit: 64, HotDays: 30, ColdDays: 365}
}
func oldCommand(t *testing.T, h *messageFileFixture, state string) string {
	t.Helper()
	id := approvalTestUUID(t)
	if _, err := h.database.RecordRealtimeCommand(h.ctx, h.ticket, "message.submit", id, h.file.SessionID, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	h.exec(t, `update commands set state=$2,created_at=clock_timestamp()-interval '60 days',updated_at=clock_timestamp()-interval '60 days' where request_id=$1`, id, state)
	return id
}
func commandArchiveCounts(t *testing.T, h *messageFileFixture, hot, cold, keys int) {
	t.Helper()
	if h.count(t, "commands") != hot || h.count(t, "command_archive") != cold || h.count(t, "command_keys") != keys {
		t.Fatal("command archive counts", h.count(t, "commands"), h.count(t, "command_archive"), h.count(t, "command_keys"))
	}
}
func expireCommandArchive(t *testing.T, h *messageFileFixture) {
	t.Helper()
	h.exec(t, `alter table command_archive_batches disable trigger command_archive_batch_guard;
 update command_archive_batches set archived_at=archived_at-interval '2 years',cutoff=cutoff-interval '2 years',retain_until=retain_until-interval '2 years';
 alter table command_archive_batches enable trigger command_archive_batch_guard`)
}
func applyCommandArchiveFixtureMigration(t *testing.T, ctx context.Context, db *Postgres, direction string) {
	t.Helper()
	if direction != "up" && direction != "down" {
		t.Fatal("invalid direction")
	}
	raw, err := os.ReadFile("../../../../deploy/sql/046_command_archive." + direction + ".sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, string(raw)); err != nil {
		t.Fatal(err)
	}
}

func TestCommandArchiveMovesOnlyOldTerminalRowsAndKeepsAuthorizedReconciliation(t *testing.T) {
	h := newMessageFileFixture(t)
	id := oldCommand(t, h, "settled")
	_ = oldCommand(t, h, "rejected")
	for _, state := range []string{"received", "host_accepted", "dispatching", "agent_queued", "observed", "outcome_unknown"} {
		_ = oldCommand(t, h, state)
	}
	recent := oldCommand(t, h, "settled")
	h.exec(t, `update commands set updated_at=clock_timestamp() where request_id=$1`, recent)
	var before string
	if err := h.database.DB.QueryRowContext(h.ctx, `select to_jsonb(c)::text from commands c where request_id=$1`, id).Scan(&before); err != nil {
		t.Fatal(err)
	}
	request := commandArchiveRequest(t)
	result, err := h.database.ArchiveCommandHistory(h.ctx, request)
	if err != nil || result.Entries != 2 || result.HotDays != 30 {
		t.Fatal("terminal archive", result, err)
	}
	commandArchiveCounts(t, h, 7, 2, 9)
	var after string
	if err := h.database.DB.QueryRowContext(h.ctx, `select source::text from command_archive where request_id=$1`, id).Scan(&after); err != nil || before != after {
		t.Fatal("source changed", err)
	}
	retry, err := h.database.ArchiveCommandHistory(h.ctx, request)
	if err != nil || !reflect.DeepEqual(result, retry) {
		t.Fatal("batch retry changed result", err)
	}
	changed := request
	changed.HotDays = 31
	if _, err := h.database.ArchiveCommandHistory(h.ctx, changed); !errors.Is(err, ErrCommandArchiveConflict) {
		t.Fatal("batch identity changed", err)
	}
	status, err := h.database.RecordRealtimeCommand(h.ctx, h.ticket, "message.submit", id, h.file.SessionID, strings.Repeat("a", 64))
	if err != nil || status.State != "settled" {
		t.Fatal("archived retry", err)
	}
	if _, err := h.database.RecordRealtimeCommand(h.ctx, h.ticket, "message.submit", id, h.file.SessionID, strings.Repeat("b", 64)); !errors.Is(err, ErrCommandConflict) {
		t.Fatal("archived digest conflict", err)
	}
	if err := h.database.AuthorizeRealtimeCommandReceipt(h.ctx, h.ticket, status); err != nil {
		t.Fatal("archived recipient", err)
	}
	receipt := fixtureReceipt(h, id)
	receipt.State = "settled"
	if got, err := h.database.RecordRealtimeCommandReceipt(h.ctx, receipt); err != nil || got.State != "settled" {
		t.Fatal("late identical receipt", err)
	}
	receipt.State = "outcome_unknown"
	if _, err := h.database.RecordRealtimeCommandReceipt(h.ctx, receipt); !errors.Is(err, ErrCommandTransition) {
		t.Fatal("late receipt changed history", err)
	}
	if got, err := h.database.MarkRealtimeCommandUnknown(h.ctx, h.ticket, id, h.file.SessionID, strings.Repeat("a", 64)); err != nil || got.State != "settled" {
		t.Fatal("late unknown marker", err)
	}
	var issuer, subject string
	if err := h.database.DB.QueryRowContext(h.ctx, `select issuer,subject from users where id=$1`, h.ticket.UserID).Scan(&issuer, &subject); err != nil {
		t.Fatal(err)
	}
	identity := UserIdentity{Issuer: issuer, Subject: subject}
	if got, err := h.database.CommandStatus(h.ctx, identity, h.ticket.DeviceID, id); err != nil || got.State != "settled" {
		t.Fatal("archived current status", err)
	}
	h.exec(t, `update runtime_grants set revoked_at=clock_timestamp()`)
	if _, err := h.database.CommandStatus(h.ctx, identity, h.ticket.DeviceID, id); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatal("archive bypassed revocation", err)
	}
	counts, err := h.database.UnknownResults(h.ctx)
	if err != nil || counts.Commands != 1 {
		t.Fatal("unknown retention", counts, err)
	}
}

func TestCommandArchiveExpiryRetainsRequestIdentityWithoutReexecution(t *testing.T) {
	h := newMessageFileFixture(t)
	id := oldCommand(t, h, "rejected")
	if _, err := h.database.ArchiveCommandHistory(h.ctx, commandArchiveRequest(t)); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{`delete from command_archive`, `update command_archive set state='settled'`, `delete from command_keys`, `truncate commands`, `truncate command_archive`, `truncate command_keys`} {
		if _, err := h.database.DB.ExecContext(h.ctx, statement); err == nil {
			t.Fatal("retention bypass", statement)
		}
	}
	expireCommandArchive(t, h)
	h.exec(t, `delete from command_archive`)
	commandArchiveCounts(t, h, 0, 0, 1)
	for _, digest := range []string{strings.Repeat("a", 64), strings.Repeat("b", 64)} {
		if _, err := h.database.RecordRealtimeCommand(h.ctx, h.ticket, "message.submit", id, h.file.SessionID, digest); !errors.Is(err, ErrCommandConflict) {
			t.Fatal("expired ID re-admitted", err)
		}
	}
	if _, err := h.database.DB.ExecContext(h.ctx, `insert into commands(device_id,request_id,user_id,runtime_id,session_id,payload_sha256,state) values($1,$2,$3,$4,$5,repeat('a',64),'received')`, h.ticket.DeviceID, id, h.ticket.UserID, h.ticket.RuntimeID, h.file.SessionID); err == nil {
		t.Fatal("direct writer reused expired ID")
	}
	commandArchiveCounts(t, h, 0, 0, 1)
}

func TestCommandArchivePreservesFileReferencesAndBlocksFreshHandoffAuthority(t *testing.T) {
	h := newMessageFileFixture(t)
	h.stage(t, h.file)
	id := approvalTestUUID(t)
	if _, err := h.record(t, id, h.file.ID); err != nil {
		t.Fatal(err)
	}
	h.exec(t, `update commands set state='settled',created_at=clock_timestamp()-interval '60 days',updated_at=clock_timestamp()-interval '60 days' where request_id=$1`, id)
	if _, err := h.database.ArchiveCommandHistory(h.ctx, commandArchiveRequest(t)); err != nil {
		t.Fatal("file-bound command could not archive", err)
	}
	commandArchiveCounts(t, h, 0, 1, 1)
	delivery, err := h.repository.FileMessageReference(h.ctx, h.file.ID)
	if err != nil || delivery == nil || delivery.RequestID != id || delivery.CommandState != "settled" {
		t.Fatal("file delivery disappeared", delivery, err)
	}
	if got, err := h.record(t, id, h.file.ID); err != nil || got.State != "settled" {
		t.Fatal("file retry lost its binding", err)
	}
	if _, err := h.repository.IssueHandoff(h.ctx, h.host, h.file.ID, fileTestPolicy); !errors.Is(err, files.ErrStale) {
		t.Fatal("archive granted a new handoff", err)
	}
	expireCommandArchive(t, h)
	if _, err := h.database.DB.ExecContext(h.ctx, `delete from command_archive`); err == nil {
		t.Fatal("file reference did not pin command history")
	}
}

func TestCommandArchiveFailuresRollBackCopiesKeysAndSourceDeletion(t *testing.T) {
	for _, table := range []string{"audit_log", "command_archive", "commands"} {
		for _, ignore := range []bool{false, true} {
			t.Run(table+map[bool]string{false: "-error", true: "-ignore"}[ignore], func(t *testing.T) {
				h := newMessageFileFixture(t)
				_ = oldCommand(t, h, "settled")
				event := "insert"
				when := "true"
				if table == "commands" {
					event = "delete"
				}
				if table == "audit_log" {
					when = "new.action='command.archive.batch'"
				}
				body := "raise exception 'PRIVATE_ARCHIVE_FAILURE';"
				if ignore {
					body = "return null;"
				}
				h.exec(t, `create function fixture_command_archive_failure() returns trigger language plpgsql as $$ begin if `+when+` then `+body+` end if;return new;end $$;
 create trigger aaa_command_archive_failure before `+event+` on `+table+` for each row execute function fixture_command_archive_failure()`)
				if _, err := h.database.ArchiveCommandHistory(h.ctx, commandArchiveRequest(t)); !errors.Is(err, ErrDatabaseUnavailable) {
					t.Fatal("incomplete archive committed", err)
				}
				commandArchiveCounts(t, h, 1, 0, 1)
				if h.count(t, "command_archive_batches") != 0 {
					t.Fatal("failed archive left a batch")
				}
			})
		}
	}
}

func TestCommandArchiveConcurrentBatchRetriesAndLockedRows(t *testing.T) {
	h := newMessageFileFixture(t)
	first := oldCommand(t, h, "settled")
	_ = oldCommand(t, h, "rejected")
	held, err := h.database.DB.BeginTx(h.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Rollback()
	if _, err := held.ExecContext(h.ctx, `select 1 from commands where request_id=$1 for update`, first); err != nil {
		t.Fatal(err)
	}
	request := commandArchiveRequest(t)
	var group sync.WaitGroup
	results := make(chan CommandArchiveResult, 4)
	failures := make(chan error, 4)
	for range 4 {
		group.Go(func() {
			result, err := h.database.ArchiveCommandHistory(h.ctx, request)
			results <- result
			failures <- err
		})
	}
	group.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	for result := range results {
		if result.Entries != 1 {
			t.Fatal("concurrent retry included locked source", result)
		}
	}
	if err := held.Commit(); err != nil {
		t.Fatal(err)
	}
	next, err := h.database.ArchiveCommandHistory(h.ctx, commandArchiveRequest(t))
	if err != nil || next.Entries != 1 {
		t.Fatal("later batch missed previously locked source", err)
	}
	commandArchiveCounts(t, h, 0, 2, 2)
}

func TestCommandArchiveActualRestoreKeepsHistoryAndKeysWithoutRestoringAuthority(t *testing.T) {
	h := newMessageFileFixture(t)
	id := oldCommand(t, h, "settled")
	request := commandArchiveRequest(t)
	if _, err := h.database.ArchiveCommandHistory(h.ctx, request); err != nil {
		t.Fatal(err)
	}
	ctx, db, _ := testsupport.RestoredPostgresDatabase(t, h.database.DB)
	restored := &Postgres{DB: db}
	epoch, operation := approvalTestUUID(t), approvalTestUUID(t)
	if _, err := restored.QuarantineRecovery(ctx, operation, OriginalDatabaseEpoch, epoch); err != nil {
		t.Fatal(err)
	}
	if _, err := restored.ArchiveCommandHistory(ctx, request); !errors.Is(err, ErrRecoveryUnavailable) {
		t.Fatal("old epoch archive succeeded", err)
	}
	manifest := RecoveryAuthority{Version: 1, Complete: true, RecoveryID: operation, DatabaseEpoch: epoch, Issuer: "https://id.example.edu", CapturedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Minute).UTC(), Users: []RecoveryUser{}}
	if _, err := restored.ReleaseRecovery(ctx, epoch, manifest.Issuer, manifest); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := db.QueryRowContext(ctx, `select state from command_records where request_id=$1`, id).Scan(&state); err != nil || state != "settled" {
		t.Fatal("restore changed archived fact", err)
	}
	var active int
	if err := db.QueryRowContext(ctx, `select count(*) from runtime_grants where revoked_at is null`).Scan(&active); err != nil || active != 0 {
		t.Fatal("archive restored grants", err)
	}
	next := commandArchiveRequest(t)
	next.DatabaseEpoch = epoch
	if _, err := restored.ArchiveCommandHistory(ctx, next); err != nil {
		t.Fatal("released successor could not archive", err)
	}
}

func TestCommandArchiveProductionBinaryReconcilesDiscardedOutput(t *testing.T) {
	binary := os.Getenv("REMOTE_TEST_SERVICE_BIN")
	if binary == "" {
		t.Skip("explicit disposable service binary required")
	}
	h := newMessageFileFixture(t)
	_ = oldCommand(t, h, "rejected")
	request := commandArchiveRequest(t)
	dsn := auditColdFixtureDSN(t, h.ctx, h.database.DB)
	args := []string{"archive", "commands", "--batch-id", request.BatchID, "--expected-epoch", OriginalDatabaseEpoch}
	command := func() *exec.Cmd {
		c := exec.CommandContext(h.ctx, binary, args...)
		c.Env = []string{"PATH=" + os.Getenv("PATH"), "REMOTE_DATABASE_URL=" + dsn, "REMOTE_DATABASE_EPOCH=" + OriginalDatabaseEpoch}
		return c
	}
	lost := command()
	lost.Stdout = io.Discard
	if err := lost.Run(); err != nil {
		t.Fatal(err)
	}
	raw, err := command().CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	var result CommandArchiveResult
	if json.Unmarshal(raw, &result) != nil || result.BatchID != request.BatchID || result.Entries != 1 || result.HotDays != 30 {
		t.Fatal("CLI result mismatch")
	}
	for _, private := range []string{dsn, h.ticket.DeviceID, h.ticket.UserID, strings.Repeat("a", 64)} {
		if strings.Contains(string(raw), private) {
			t.Fatal("CLI exposed source metadata")
		}
	}
	commandArchiveCounts(t, h, 0, 1, 1)
}

func TestCommandArchiveQuestionAndForkEvidenceRemainScoped(t *testing.T) {
	h := questionFixture(t)
	id := approvalTestUUID(t)
	digest := strings.Repeat("a", 64)
	if _, err := h.database.RecordRealtimeCommand(h.ctx, h.ticket, "question.answer", id, h.request.SessionID, digest); err != nil {
		t.Fatal(err)
	}
	age := func(id string) {
		if _, err := h.database.DB.ExecContext(h.ctx, `update commands set state='settled',created_at=clock_timestamp()-interval '60 days',updated_at=clock_timestamp()-interval '60 days' where request_id=$1`, id); err != nil {
			t.Fatal(err)
		}
	}
	age(id)
	if _, err := h.database.ArchiveCommandHistory(h.ctx, commandArchiveRequest(t)); err != nil {
		t.Fatal(err)
	}
	var issuer, subject string
	if err := h.database.DB.QueryRowContext(h.ctx, `select issuer,subject from users where id=$1`, h.ticket.UserID).Scan(&issuer, &subject); err != nil {
		t.Fatal(err)
	}
	identity := UserIdentity{Issuer: issuer, Subject: subject}
	status, err := h.database.QuestionAnswerStatus(h.ctx, identity, h.ticket.DeviceID, h.ticket.ProofKeyThumbprint, h.ticket.RuntimeID, h.request.SessionID, id, time.Now().Add(time.Minute))
	if err != nil || status.State != "settled" {
		t.Fatal("archived answer workflow", err)
	}
	scope := GrantScope{Actions: []string{"session.read", "session.fork", "session.create", "command.status"}, Workspaces: []string{h.request.Workspace.WorkspaceID}, Sessions: []string{}}
	raw, _ := json.Marshal(scope)
	if _, err := h.database.DB.ExecContext(h.ctx, `update runtime_grants set scope=$1`, raw); err != nil {
		t.Fatal(err)
	}
	h.ticket.Scope = scope
	fork, child := approvalTestUUID(t), approvalTestUUID(t)
	if _, err := h.database.RecordRealtimeSessionFork(h.ctx, h.ticket, fork, h.request.SessionID, h.request.Workspace.WorkspaceID, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := h.database.DB.ExecContext(h.ctx, `update commands set child_session_id=$2,fork_outcome='{"v":1,"workspace_attachment":"failed","checkpoint":"persisted"}' where request_id=$1`, fork, child); err != nil {
		t.Fatal(err)
	}
	age(fork)
	if _, err := h.database.ArchiveCommandHistory(h.ctx, commandArchiveRequest(t)); err != nil {
		t.Fatal(err)
	}
	retry, err := h.database.RecordRealtimeSessionFork(h.ctx, h.ticket, fork, h.request.SessionID, h.request.Workspace.WorkspaceID, digest)
	if err != nil || retry.State != "settled" || retry.ChildSessionID != child || retry.ForkOutcome == nil || retry.ForkOutcome.WorkspaceAttachment != "failed" {
		t.Fatal("archived fork lost evidence", retry, err)
	}
	got, err := h.database.CommandStatus(h.ctx, identity, h.ticket.DeviceID, fork)
	if err != nil || got.CommandType != "session.fork" || got.ChildSessionID != child {
		t.Fatal("archived fork status", err)
	}
	scope.Workspaces = []string{}
	scope.Sessions = []string{h.request.SessionID}
	raw, _ = json.Marshal(scope)
	if _, err := h.database.DB.ExecContext(h.ctx, `update runtime_grants set scope=$1`, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := h.database.CommandStatus(h.ctx, identity, h.ticket.DeviceID, fork); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatal("historical fork bypassed workspace authority", err)
	}
}

func TestCommandArchiveDeletionAuditAndViewACLFailClosed(t *testing.T) {
	h := newMessageFileFixture(t)
	id := oldCommand(t, h, "rejected")
	if _, err := h.database.ArchiveCommandHistory(h.ctx, commandArchiveRequest(t)); err != nil {
		t.Fatal(err)
	}
	expireCommandArchive(t, h)
	h.exec(t, `create function fixture_command_expiry_audit() returns trigger language plpgsql as $$ begin if new.action='command.archive.delete' then return null;end if;return new;end $$;create trigger aaa_command_expiry_audit before insert on audit_log for each row execute function fixture_command_expiry_audit()`)
	if _, err := h.database.DB.ExecContext(h.ctx, `delete from command_archive`); err == nil {
		t.Fatal("ignored audit permitted removal")
	}
	commandArchiveCounts(t, h, 0, 1, 1)
	h.exec(t, `drop trigger aaa_command_expiry_audit on audit_log;drop function fixture_command_expiry_audit()`)
	role := "command_read_" + strings.ReplaceAll(approvalTestUUID(t), "-", "")
	h.exec(t, "create role "+role)
	t.Cleanup(func() {
		_, _ = h.database.DB.ExecContext(context.Background(), "drop owned by "+role)
		_, _ = h.database.DB.ExecContext(context.Background(), "drop role "+role)
	})
	h.exec(t, "grant usage on schema public to "+role)
	h.exec(t, "grant select on commands,command_records to "+role)
	conn, err := h.database.DB.Conn(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(h.ctx, "set role "+role); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := conn.QueryRowContext(h.ctx, `select state from command_records where request_id=$1`, id).Scan(&state); err == nil {
		t.Fatal("view owner bypassed SELECT ACL")
	}
	if _, err := conn.ExecContext(h.ctx, "reset role"); err != nil {
		t.Fatal(err)
	}
	h.exec(t, "grant select on command_archive to "+role)
	if _, err := conn.ExecContext(h.ctx, "set role "+role); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRowContext(h.ctx, `select state from command_records where request_id=$1`, id).Scan(&state); err != nil || state != "rejected" {
		t.Fatal("granted history read failed", err)
	}
	if _, err := conn.ExecContext(h.ctx, "reset role"); err != nil {
		t.Fatal(err)
	}
	h.exec(t, `delete from command_archive`)
	commandArchiveCounts(t, h, 0, 0, 1)
}

func TestCommandArchiveAdmissionWaitingOnSourceReconcilesTheMovedTerminal(t *testing.T) {
	h := newMessageFileFixture(t)
	id := oldCommand(t, h, "settled")
	h.database.DB.SetMaxOpenConns(6)
	h.exec(t, `create function fixture_command_archive_wait() returns trigger language plpgsql as $$ begin if new.action='command.archive.batch' then perform pg_advisory_xact_lock(845602);end if;return new;end $$;
 create trigger fixture_command_archive_wait before insert on audit_log for each row execute function fixture_command_archive_wait()`)
	holder, err := h.database.DB.Conn(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if _, err := holder.ExecContext(h.ctx, `select pg_advisory_lock(845602)`); err != nil {
		t.Fatal(err)
	}
	defer holder.ExecContext(context.Background(), `select pg_advisory_unlock(845602)`)
	archived, admitted := make(chan error, 1), make(chan error, 1)
	go func() { _, err := h.database.ArchiveCommandHistory(h.ctx, commandArchiveRequest(t)); archived <- err }()
	waitForGrantLock(t, h.ctx, h.database, "insert into audit_log")
	go func() {
		status, err := h.database.RecordRealtimeCommand(h.ctx, h.ticket, "message.submit", id, h.file.SessionID, strings.Repeat("a", 64))
		if err == nil && status.State != "settled" {
			err = errors.New("waiting retry recreated the active intent")
		}
		admitted <- err
	}()
	waitForGrantLock(t, h.ctx, h.database, "from commands where device_id = $1 and request_id = $2 for update")
	if _, err := holder.ExecContext(h.ctx, `select pg_advisory_unlock(845602)`); err != nil {
		t.Fatal(err)
	}
	if err := <-archived; err != nil {
		t.Fatal("archive failed", err)
	}
	if err := <-admitted; err != nil {
		t.Fatal("waiting retry lost its moved terminal", err)
	}
	commandArchiveCounts(t, h, 0, 1, 1)
}
