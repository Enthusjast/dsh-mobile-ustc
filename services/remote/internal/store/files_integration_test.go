package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
)

type fileFixture struct {
	ctx        context.Context
	database   *Postgres
	repository *FileStore
	actor      files.Actor
	input      files.UploadRegistration
	limits     files.Limits
}

func newFileFixture(t *testing.T) *fileFixture {
	t.Helper()
	ctx, database := newPostgresIntegrationDatabase(t)
	jkt := seedGrantFixture(t, ctx, database.DB)
	const runtime = "55555555-5555-4555-8555-555555555555"
	scope := GrantScope{Actions: []string{"grant.manage", "session.read", "file.upload", "file.download"}, Workspaces: []string{"77777777-7777-4777-8777-777777777777"}, Sessions: []string{}}
	encoded, _ := json.Marshal(scope)
	if _, err := database.DB.ExecContext(ctx, `update runtime_grants set scope=$1 where runtime_id=$2`, encoded, runtime); err != nil {
		t.Fatal(err)
	}
	limits := files.Limits{OrganizationBytes: 1000, UserBytes: 400, SessionBytes: 200, OrganizationFiles: 20, UserFiles: 10, SessionFiles: 4,
		UploadURLTTL: 5 * time.Minute, AbandonAfter: time.Hour, RetainFor: 24 * time.Hour}
	repository, err := NewFileStore(database, limits)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("fixture bytes"))
	return &fileFixture{ctx: ctx, database: database, repository: repository, limits: limits,
		actor: files.Actor{Issuer: "https://id.example.edu", Subject: "owner-subject", DeviceID: "44444444-4444-4444-8444-444444444444", ProofKeyJKT: jkt},
		input: files.UploadRegistration{RequestID: approvalTestUUID(t), RuntimeID: runtime, SessionID: "99999999-9999-4999-8999-999999999999", Name: "PRIVATE_FILE_NAME_资料.txt", SizeBytes: 13, SHA256: hex.EncodeToString(sum[:])}}
}
func (fixture *fileFixture) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := fixture.database.DB.ExecContext(fixture.ctx, query, args...); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresFileRegistrationIsDeviceScopedIdempotentAndStartsOnlyOneScan(t *testing.T) {
	h := newFileFixture(t)
	first, err := h.repository.RegisterUpload(h.ctx, h.actor, h.input)
	if err != nil || first.State != "uploading" || first.ID == "" {
		t.Fatalf("registration=%+v error=%v", first, err)
	}
	retry, err := h.repository.RegisterUpload(h.ctx, h.actor, h.input)
	if err != nil || retry.ID != first.ID || retry.QuarantineAttempt != first.QuarantineAttempt {
		t.Fatalf("retry=%+v error=%v", retry, err)
	}
	changed := h.input
	changed.Name = "another.txt"
	if _, err := h.repository.RegisterUpload(h.ctx, h.actor, changed); !errors.Is(err, files.ErrConflict) {
		t.Fatalf("changed body=%v", err)
	}
	capability, err := h.repository.AuthorizeUpload(h.ctx, h.actor, first.ID)
	if err != nil || capability.ID != first.ID {
		t.Fatalf("upload authority=%v", err)
	}
	for range 2 {
		state, err := h.repository.BeginScan(h.ctx, h.actor, first.ID)
		if err != nil || state.State != "scanning" {
			t.Fatalf("scan admission=%+v error=%v", state, err)
		}
	}
	if _, err := h.repository.AuthorizeUpload(h.ctx, h.actor, first.ID); !errors.Is(err, files.ErrStale) {
		t.Fatalf("scanning object received another upload capability: %v", err)
	}
	var filesCount, objectsCount, quotaCount, audits int
	var reserved int64
	if err := h.database.DB.QueryRowContext(h.ctx, `select (select count(*) from files),(select count(*) from file_objects),(select count(*) from file_quota_usage),(select count(*) from audit_log where action like 'file.%'),(select sum(reserved_bytes) from file_quota_usage)`).Scan(&filesCount, &objectsCount, &quotaCount, &audits, &reserved); err != nil {
		t.Fatal(err)
	}
	if filesCount != 1 || objectsCount != 1 || quotaCount != 3 || audits != 2 || reserved != 39 {
		t.Fatalf("atomic counts=%d/%d/%d/%d/%d", filesCount, objectsCount, quotaCount, audits, reserved)
	}
	status, err := h.repository.Status(h.ctx, h.actor, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(status)
	for _, private := range []string{first.QuarantineAttempt, first.ProofKeyJKT, "object_key", "request_sha256", "remote-files/"} {
		if strings.Contains(string(public), private) {
			t.Fatal("public file status exposed private authority")
		}
	}
	var metadata string
	if err := h.database.DB.QueryRowContext(h.ctx, `select string_agg(metadata::text,'') from audit_log where action like 'file.%'`).Scan(&metadata); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(metadata, h.input.Name) {
		t.Fatal("file name leaked into general audit metadata")
	}
}

func TestPostgresConcurrentFileReservationsAndRetriesCannotOversubscribe(t *testing.T) {
	for _, same := range []bool{false, true} {
		t.Run(map[bool]string{false: "quota", true: "same-id"}[same], func(t *testing.T) {
			h := newFileFixture(t)
			h.limits.SessionBytes = 100
			var err error
			h.repository, err = NewFileStore(h.database, h.limits)
			if err != nil {
				t.Fatal(err)
			}
			input := h.input
			input.SizeBytes = 60
			const workers = 16
			inputs := make([]files.UploadRegistration, workers)
			for i := range inputs {
				inputs[i] = input
				if !same {
					inputs[i].RequestID = approvalTestUUID(t)
				}
			}
			var wait sync.WaitGroup
			results := make(chan files.Record, workers)
			failures := make(chan error, workers)
			for _, input := range inputs {
				wait.Add(1)
				go func(input files.UploadRegistration) {
					defer wait.Done()
					record, err := h.repository.RegisterUpload(h.ctx, h.actor, input)
					if err != nil {
						failures <- err
					} else {
						results <- record
					}
				}(input)
			}
			wait.Wait()
			close(results)
			close(failures)
			var id string
			successes, denied := 0, 0
			for record := range results {
				successes++
				if id != "" && record.ID != id {
					t.Fatal("concurrent same-ID registration created different files")
				}
				id = record.ID
			}
			for err := range failures {
				if !errors.Is(err, files.ErrQuota) {
					t.Fatalf("concurrent admission=%v", err)
				}
				denied++
			}
			if same && successes != workers || !same && (successes != 1 || denied != workers-1) {
				t.Fatalf("success=%d denied=%d", successes, denied)
			}
			var count int
			var bytes int64
			if err := h.database.DB.QueryRowContext(h.ctx, `select reserved_files,reserved_bytes from file_quota_usage where kind='session'`).Scan(&count, &bytes); err != nil || count != 1 || bytes != 60 {
				t.Fatalf("quota=%d/%d error=%v", count, bytes, err)
			}
		})
	}
}

func TestPostgresZeroByteFilesStillConsumeCountQuotaAndAuditFailuresRollBackEverything(t *testing.T) {
	h := newFileFixture(t)
	h.limits.SessionFiles = 2
	var err error
	h.repository, err = NewFileStore(h.database, h.limits)
	if err != nil {
		t.Fatal(err)
	}
	input := h.input
	input.SizeBytes = 0
	for range 2 {
		input.RequestID = approvalTestUUID(t)
		if _, err := h.repository.RegisterUpload(h.ctx, h.actor, input); err != nil {
			t.Fatal(err)
		}
	}
	input.RequestID = approvalTestUUID(t)
	if _, err := h.repository.RegisterUpload(h.ctx, h.actor, input); !errors.Is(err, files.ErrQuota) {
		t.Fatalf("zero-byte quota=%v", err)
	}
	other := newFileFixture(t)
	other.exec(t, `create function fail_file_audit() returns trigger language plpgsql as $$ begin raise exception 'injected file audit failure'; end $$;
	 create trigger file_audit_failure before insert on audit_log for each row when(new.action='file.registered') execute function fail_file_audit()`)
	if _, err := other.repository.RegisterUpload(other.ctx, other.actor, other.input); !errors.Is(err, files.ErrUnavailable) {
		t.Fatalf("failed audit=%v", err)
	}
	for _, table := range []string{"files", "file_transfers", "file_objects", "file_quota_usage"} {
		var count int
		if err := other.database.DB.QueryRowContext(other.ctx, `select count(*) from `+table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("rollback table=%s count=%d error=%v", table, count, err)
		}
	}
}

func TestPostgresFileAuthorizationRechecksResourceDeviceGrantAndArchive(t *testing.T) {
	h := newFileFixture(t)
	for _, variant := range []struct{ name, deny, restore string }{
		{"user", `update users set status='suspended' where subject='owner-subject'`, `update users set status='active' where subject='owner-subject'`},
		{"device", `update devices set revoked_at=clock_timestamp() where id='44444444-4444-4444-8444-444444444444'`, `update devices set revoked_at=null`},
		{"membership", `delete from org_memberships where user_id='22222222-2222-4222-8222-222222222222'`, `insert into org_memberships(org_id,user_id,role) values('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','22222222-2222-4222-8222-222222222222','member')`},
		{"host", `update hosts set state='revoked'`, `update hosts set state='active'`},
		{"installation", `update installations set revoked_at=clock_timestamp()`, `update installations set revoked_at=null`},
		{"runtime", `update runtimes set revoked_at=clock_timestamp()`, `update runtimes set revoked_at=null`},
		{"grant", `update runtime_grants set revoked_at=clock_timestamp()`, `update runtime_grants set revoked_at=null`},
		{"expired", `update runtime_grants set expires_at=clock_timestamp()-interval '1 second'`, `update runtime_grants set expires_at=null`},
		{"viewer", `update runtime_grants set role='viewer'`, `update runtime_grants set role='owner'`},
		{"archived", `update sessions set state='archived'`, `update sessions set state='available'`},
	} {
		t.Run(variant.name, func(t *testing.T) {
			h.exec(t, variant.deny)
			defer h.exec(t, variant.restore)
			if _, err := h.repository.RegisterUpload(h.ctx, h.actor, h.input); !errors.Is(err, files.ErrAccess) {
				t.Fatalf("unauthorized file=%v", err)
			}
		})
	}
	wrong := h.actor
	wrong.ProofKeyJKT = strings.Repeat("A", 43)
	if _, err := h.repository.RegisterUpload(h.ctx, wrong, h.input); !errors.Is(err, files.ErrAccess) {
		t.Fatal("foreign proof key accepted")
	}
	input := h.input
	input.RuntimeID = approvalTestUUID(t)
	if _, err := h.repository.RegisterUpload(h.ctx, h.actor, input); !errors.Is(err, files.ErrAccess) {
		t.Fatal("foreign runtime accepted")
	}
	file, err := h.repository.RegisterUpload(h.ctx, h.actor, h.input)
	if err != nil {
		t.Fatal(err)
	}
	h.exec(t, `update runtime_grants set grant_version=grant_version+1`)
	if _, err := h.repository.BeginScan(h.ctx, h.actor, file.ID); !errors.Is(err, files.ErrAccess) {
		t.Fatal("changed grant revived the original upload intent")
	}
	if _, err := h.repository.Status(h.ctx, h.actor, file.ID); err != nil {
		t.Fatal("current owner could not reconcile original metadata")
	}
	wrong = h.actor
	wrong.DeviceID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	if _, err := h.repository.Status(h.ctx, wrong, file.ID); !errors.Is(err, files.ErrAccess) {
		t.Fatal("another device read private upload metadata")
	}
}

func TestPostgresFileGrantExpiryIsRecheckedAfterQuotaLock(t *testing.T) {
	h := newFileFixture(t)
	if _, err := h.repository.RegisterUpload(h.ctx, h.actor, h.input); err != nil {
		t.Fatal(err)
	}
	blocking, err := h.database.DB.BeginTx(h.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocking.Rollback()
	if _, err := blocking.ExecContext(h.ctx, `select reserved_bytes from file_quota_usage where kind='organization' for update`); err != nil {
		t.Fatal(err)
	}
	h.exec(t, `update runtime_grants set expires_at=clock_timestamp()+interval '500 milliseconds'`)
	input := h.input
	input.RequestID = approvalTestUUID(t)
	done := make(chan error, 1)
	go func() { _, err := h.repository.RegisterUpload(h.ctx, h.actor, input); done <- err }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var waiting int
		if err := h.database.DB.QueryRowContext(h.ctx, `select count(*) from pg_stat_activity where datname=current_database() and wait_event_type='Lock' and query like '%file_quota_usage%'`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("registration never waited on the quota lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
	for {
		var expired bool
		if err := h.database.DB.QueryRowContext(h.ctx, `select expires_at<clock_timestamp() from runtime_grants`).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if expired {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := blocking.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, files.ErrAccess) {
		t.Fatalf("expired grant after waiting=%v", err)
	}
}
