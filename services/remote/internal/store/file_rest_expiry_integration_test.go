package store

import (
	"errors"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
)

func fileAdmissionSnapshot(t *testing.T, h *fileFixture) string {
	t.Helper()
	var snapshot string
	if err := h.database.DB.QueryRowContext(h.ctx, `select jsonb_build_object('ledger',$1::jsonb,
	 'origins',(select jsonb_agg(to_jsonb(e) order by file_id) from file_exports e),
	 'quotas',(select jsonb_agg(to_jsonb(q) order by kind,bucket_id) from file_quota_usage q))::text`, scanMutationSnapshot(t, h)).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestFileRESTDeadlinesCannotSurviveRegistrationCommitOrDownloadAuditWaits(t *testing.T) {
	for _, test := range []struct {
		operation string
		expiries  []string
	}{
		{"upload-register", []string{"grant", "upload", "file", "retain"}},
		{"upload-commit", []string{"grant", "file", "retain"}},
		{"upload-commit-state", []string{"file"}},
		{"export-register", []string{"grant", "credential", "source", "upload", "file", "retain"}},
		{"export-source-audit", []string{"grant"}},
		{"export-commit", []string{"grant", "credential", "source", "upload", "file", "retain"}},
		{"export-commit-state", []string{"source"}},
		{"download-open", []string{"grant", "file", "retain", "permit"}},
		{"download-authorize", []string{"grant"}},
	} {
		for _, expiry := range test.expiries {
			t.Run(test.operation+"/"+expiry, func(t *testing.T) {
				operation := test.operation
				var h *fileFixture
				var exported *exportFixture
				var record files.Record
				fresh := strings.Contains(operation, "register") || operation == "export-source-audit"
				if strings.HasPrefix(operation, "upload-") {
					h = newFileFixture(t)
					if !fresh {
						var err error
						record, err = h.repository.RegisterUpload(h.ctx, h.actor, h.input)
						if err != nil {
							t.Fatal(err)
						}
					}
				} else {
					exported = newExportFixture(t)
					h = exported.fileFixture
					if strings.HasPrefix(operation, "download-") {
						record = exported.clean(t)
					} else if !fresh {
						record = exported.register(t)
					}
				}
				h.exec(t, `create table file_rest_deadline(deadline timestamptz not null)`)
				if fresh && (expiry == "file" || expiry == "upload" || expiry == "retain") {
					table, column := "files", "expires_at"
					if expiry != "file" {
						table, column = "file_transfers", "upload_expires_at"
						if expiry == "retain" {
							column = "retain_until"
						}
					}
					h.exec(t, `create function shorten_file_rest_deadline() returns trigger language plpgsql as $$ begin
					 new.`+column+`=(select deadline from file_rest_deadline);return new;end $$;
					 create trigger shorten_file_rest_deadline before insert on `+table+` for each row execute function shorten_file_rest_deadline()`)
				}
				action := map[string]string{"upload-register": "file.registered", "upload-commit": "file.scan_requested", "export-register": "file.export_registered",
					"export-source-audit": "file.export_source", "export-commit": "file.export_scan_requested", "download-open": "file.export_download"}[operation]
				fragment := "insert into audit_log"
				if strings.HasSuffix(operation, "-state") {
					fragment = "update files set state='scanning'"
					h.exec(t, `create function hold_file_rest_deadline() returns trigger language plpgsql as $$ begin
					 if old.state='uploading' and new.state='scanning' then perform pg_advisory_xact_lock(426968);end if;return new;end $$;
					 create trigger hold_file_rest_deadline before update on files for each row execute function hold_file_rest_deadline()`)
				} else if operation != "download-authorize" {
					h.exec(t, `create function hold_file_rest_deadline() returns trigger language plpgsql as $$ begin
					 if new.action='`+action+`' then perform pg_advisory_xact_lock(426968);end if;return new;end $$;
					 create trigger hold_file_rest_deadline before insert on audit_log for each row execute function hold_file_rest_deadline()`)
				} else {
					fragment = "from file_exports where file_id"
				}
				var deadline time.Time
				if err := h.database.DB.QueryRowContext(h.ctx, `insert into file_rest_deadline values(clock_timestamp()+interval '600 milliseconds') returning deadline`).Scan(&deadline); err != nil {
					t.Fatal(err)
				}
				want := files.ErrAccess
				switch expiry {
				case "grant":
					h.exec(t, `update runtime_grants set expires_at=$1`, deadline)
				case "credential":
					exported.host.CredentialExpiresAt = deadline
					if !fresh {
						h.exec(t, `update file_exports set credential_expires_at=$1 where file_id=$2`, deadline, record.ID)
					}
				case "source":
					want = files.ErrStale
					exported.input.SourceExpiresAt = deadline
					if !fresh {
						h.exec(t, `update file_exports set source_expires_at=$1 where file_id=$2`, deadline, record.ID)
					}
				case "file":
					if !fresh {
						h.exec(t, `update files set expires_at=$1 where id=$2`, deadline, record.ID)
					}
				case "upload":
					want = files.ErrStale
					if !fresh {
						h.exec(t, `update file_transfers set upload_expires_at=$1 where file_id=$2`, deadline, record.ID)
					}
				case "retain":
					if !fresh {
						h.exec(t, `update file_transfers set retain_until=$1 where file_id=$2`, deadline, record.ID)
					}
				}
				var permit files.DownloadPermit
				if operation == "download-open" {
					var err error
					permit, err = h.repository.AuthorizeExportDownload(h.ctx, h.actor, record.ID, fileTestPolicy)
					if err != nil {
						t.Fatal(err)
					}
					if expiry == "permit" {
						permit.LeaseUntil = deadline
					}
				}
				before := fileAdmissionSnapshot(t, h)
				gate, err := h.database.DB.BeginTx(h.ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer gate.Rollback()
				if operation == "download-authorize" {
					_, err = gate.ExecContext(h.ctx, `lock table file_exports in access exclusive mode`)
				} else {
					_, err = gate.ExecContext(h.ctx, `select pg_advisory_xact_lock(426968)`)
				}
				if err != nil {
					t.Fatal(err)
				}
				result := make(chan error, 1)
				go func() {
					var err error
					var current files.Record
					switch operation {
					case "upload-register":
						current, err = h.repository.RegisterUpload(h.ctx, h.actor, h.input)
					case "upload-commit", "upload-commit-state":
						current, err = h.repository.BeginScan(h.ctx, h.actor, record.ID)
					case "export-register", "export-source-audit":
						current, err = h.repository.RegisterExport(h.ctx, h.actor, exported.host, exported.input)
					case "export-commit", "export-commit-state":
						current, err = h.repository.BeginExportScan(h.ctx, h.actor, exported.host, record.ID)
					case "download-open":
						err = h.repository.AuditExportDownload(h.ctx, h.actor, permit, strings.Repeat("a", 32), "opened")
					case "download-authorize":
						var current files.DownloadPermit
						current, err = h.repository.AuthorizeExportDownload(h.ctx, h.actor, record.ID, fileTestPolicy)
						if err != nil && current.File.ID != "" {
							result <- errors.New("expired download returned a permit")
							return
						}
					}
					if err != nil && current.ID != "" {
						result <- errors.New("failed file admission returned an accepted record")
						return
					}
					result <- err
				}()
				waitForGrantLock(t, h.ctx, h.database, fragment)
				waitForGrantDatabaseExpiry(t, h.ctx, h.database, deadline)
				if err := gate.Commit(); err != nil {
					t.Fatal(err)
				}
				if err := <-result; !errors.Is(err, want) {
					t.Fatal("file admission survived expiry during its database wait", err)
				}
				if after := fileAdmissionSnapshot(t, h); after != before {
					t.Fatal("expired file admission left quota, source, scan or audit facts")
				}
			})
		}
	}
}

func TestFileRESTIgnoredRegistrationQuotaAttestationAndAuditWritesRollBack(t *testing.T) {
	for _, fault := range []struct{ operation, table, event, condition string }{
		{"upload-register", "files", "insert", "true"},
		{"upload-register", "file_transfers", "insert", "true"},
		{"upload-register", "file_objects", "insert", "true"},
		{"upload-register", "file_quota_usage", "update", "new.kind='organization' and new.reserved_files>old.reserved_files"},
		{"upload-register", "audit_log", "insert", "new.action='file.registered'"},
		{"upload-commit", "files", "update", "new.state='scanning'"},
		{"upload-commit", "file_transfers", "update", "true"},
		{"upload-commit", "audit_log", "insert", "new.action='file.scan_requested'"},
		{"export-register", "files", "insert", "true"},
		{"export-register", "file_transfers", "insert", "true"},
		{"export-register", "file_exports", "insert", "true"},
		{"export-register", "file_objects", "insert", "true"},
		{"export-register", "file_quota_usage", "update", "new.kind='organization' and new.reserved_files>old.reserved_files"},
		{"export-register", "audit_log", "insert", "new.action='file.export_registered'"},
		{"export-register", "audit_log", "insert", "new.action='file.export_source'"},
		{"export-commit", "files", "update", "new.state='scanning'"},
		{"export-commit", "file_exports", "update", "new.uploaded_at is not null"},
		{"export-commit", "file_transfers", "update", "true"},
		{"export-commit", "audit_log", "insert", "new.action='file.export_scan_requested'"},
		{"download-open", "audit_log", "insert", "new.action='file.export_download'"},
	} {
		t.Run(fault.operation+"/"+fault.table+"/"+fault.condition, func(t *testing.T) {
			var h *fileFixture
			var exported *exportFixture
			var record files.Record
			if strings.HasPrefix(fault.operation, "upload-") {
				h = newFileFixture(t)
				if fault.operation == "upload-commit" {
					var err error
					record, err = h.repository.RegisterUpload(h.ctx, h.actor, h.input)
					if err != nil {
						t.Fatal(err)
					}
				}
			} else {
				exported = newExportFixture(t)
				h = exported.fileFixture
				if fault.operation == "export-commit" {
					record = exported.register(t)
				} else if fault.operation == "download-open" {
					record = exported.clean(t)
				}
			}
			var permit files.DownloadPermit
			if fault.operation == "download-open" {
				var err error
				permit, err = h.repository.AuthorizeExportDownload(h.ctx, h.actor, record.ID, fileTestPolicy)
				if err != nil {
					t.Fatal(err)
				}
			}
			h.exec(t, `create function ignore_file_rest_write() returns trigger language plpgsql as $$ begin
			 if `+fault.condition+` then return null;end if;return new;end $$;
			 create trigger ignore_file_rest_write before `+fault.event+` on `+fault.table+` for each row execute function ignore_file_rest_write()`)
			before := fileAdmissionSnapshot(t, h)
			run := func() error {
				var err error
				var accepted files.Record
				switch fault.operation {
				case "upload-register":
					accepted, err = h.repository.RegisterUpload(h.ctx, h.actor, h.input)
				case "upload-commit":
					accepted, err = h.repository.BeginScan(h.ctx, h.actor, record.ID)
				case "export-register":
					accepted, err = h.repository.RegisterExport(h.ctx, h.actor, exported.host, exported.input)
				case "export-commit":
					accepted, err = h.repository.BeginExportScan(h.ctx, h.actor, exported.host, record.ID)
				case "download-open":
					err = h.repository.AuditExportDownload(h.ctx, h.actor, permit, strings.Repeat("a", 32), "opened")
				}
				if err != nil && accepted.ID != "" {
					return errors.New("ignored write returned an accepted file")
				}
				return err
			}
			if err := run(); !errors.Is(err, files.ErrUnavailable) && !(fault.operation == "upload-register" && fault.table == "file_transfers" && errors.Is(err, files.ErrConflict)) {
				t.Fatal("missing file evidence returned success", err)
			}
			if fileAdmissionSnapshot(t, h) != before {
				t.Fatal("missing file evidence left partial quota, source or scan state")
			}
			h.exec(t, `drop trigger ignore_file_rest_write on `+fault.table+`;drop function ignore_file_rest_write()`)
			if err := run(); err != nil {
				t.Fatal("file admission could not recover after restoring writes", err)
			}
		})
	}
}

func TestFileRESTExpiredPUTDoesNotReopenOrEraseAdmittedBytes(t *testing.T) {
	h := newFileFixture(t)
	record, err := h.repository.RegisterUpload(h.ctx, h.actor, h.input)
	if err != nil {
		t.Fatal(err)
	}
	h.exec(t, `update file_transfers set upload_expires_at=clock_timestamp()-interval '1 second' where file_id=$1`, record.ID)
	if _, err := h.repository.AuthorizeUpload(h.ctx, h.actor, record.ID); !errors.Is(err, files.ErrStale) {
		t.Fatal("expired PUT window issued new upload authority", err)
	}
	if committed, err := h.repository.BeginScan(h.ctx, h.actor, record.ID); err != nil || committed.State != "scanning" {
		t.Fatal("existing bytes could not enter scanning within the live file window", err)
	}
	before := fileAdmissionSnapshot(t, h)
	if _, err := h.repository.BeginScan(h.ctx, h.actor, record.ID); err != nil || fileAdmissionSnapshot(t, h) != before {
		t.Fatal("upload commit retry changed the durable scan request", err)
	}
	// Export attestation retries are history. They cannot issue another source
	// upload, while scanning is independently authorized after the Host leaves.
	e := newExportFixture(t)
	export := e.register(t)
	if _, err := e.repository.BeginExportScan(e.ctx, e.actor, e.host, export.ID); err != nil {
		t.Fatal(err)
	}
	e.exec(t, `update file_exports set source_expires_at=clock_timestamp()-interval '1 second' where file_id=$1`, export.ID)
	before = fileAdmissionSnapshot(t, e.fileFixture)
	if _, err := e.repository.BeginExportScan(e.ctx, e.actor, e.host, export.ID); err != nil || fileAdmissionSnapshot(t, e.fileFixture) != before {
		t.Fatal("historical attestation required an expired source window", err)
	}
	if _, err := e.repository.AuthorizeExportUpload(e.ctx, e.actor, e.host, export.ID); !errors.Is(err, files.ErrStale) {
		t.Fatal("historical attestation reopened source upload", err)
	}
}

func TestFileRESTDownloadOutcomeRemainsAuditableAfterAuthorityEnds(t *testing.T) {
	e := newExportFixture(t)
	record := e.clean(t)
	permit, err := e.repository.AuthorizeExportDownload(e.ctx, e.actor, record.ID, fileTestPolicy)
	if err != nil {
		t.Fatal(err)
	}
	e.exec(t, `update devices set revoked_at=clock_timestamp() where id=$1`, e.actor.DeviceID)
	permit.LeaseUntil = time.Now().Add(-time.Second)
	if err := e.repository.AuditExportDownload(e.ctx, e.actor, permit, strings.Repeat("b", 32), "served"); err != nil {
		t.Fatal("completed download lost its historical audit", err)
	}
	before := fileAdmissionSnapshot(t, e.fileFixture)
	if err := e.repository.AuditExportDownload(e.ctx, e.actor, permit, strings.Repeat("c", 32), "opened"); !errors.Is(err, files.ErrAccess) || fileAdmissionSnapshot(t, e.fileFixture) != before {
		t.Fatal("historical download outcome restored opening authority", err)
	}
}
