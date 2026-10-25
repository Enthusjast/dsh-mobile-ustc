package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/files"
)

type exportFixture struct {
	*fileFixture
	host  files.HostBinding
	input files.ExportRegistration
}

func TestPostgresExportRollbackPreservesCleanupButCannotReviveDownloadAuthority(t *testing.T) {
	h := newExportFixture(t)
	record := h.clean(t)
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("migration path unavailable")
	}
	for _, direction := range []string{"down", "up"} {
		body, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../deploy/sql/012_file_exports."+direction+".sql"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.database.DB.ExecContext(h.ctx, string(body)); err != nil {
			t.Fatal(err)
		}
		var state string
		if err := h.database.DB.QueryRowContext(h.ctx, `select state from files where id=$1`, record.ID).Scan(&state); err != nil || state != "expired" {
			t.Fatal("rollback revived the exported object")
		}
	}
	if _, err := h.repository.AuthorizeExportDownload(h.ctx, h.actor, record.ID, fileTestPolicy); !errors.Is(err, files.ErrAccess) {
		t.Fatal("migration replay recreated source attestation")
	}
	var objects, count int
	if err := h.database.DB.QueryRowContext(h.ctx, `select (select count(*) from file_objects where file_id=$1),reserved_files from file_quota_usage where kind='session'`, record.ID).Scan(&objects, &count); err != nil || objects != 2 || count != 1 {
		t.Fatal("rollback lost object cleanup/quota evidence")
	}
}

func TestPostgresCleanExportsCannotBecomePhoneUploadsOrNativeMessageHandoffs(t *testing.T) {
	h := newExportFixture(t)
	record := h.clean(t)
	if _, err := h.repository.IssueHandoff(h.ctx, h.host, record.ID, fileTestPolicy); !errors.Is(err, files.ErrAccess) {
		t.Fatal("an exported object became a native upload receipt")
	}
	pending, err := h.repository.PendingHandoffFiles(h.ctx, h.host, fileTestPolicy, 32)
	if err != nil || len(pending) != 0 {
		t.Fatal("export object entered the phone-to-Host handoff queue")
	}
	if _, err := h.repository.BeginScan(h.ctx, h.actor, record.ID); !errors.Is(err, files.ErrAccess) {
		t.Fatal("phone commit reopened the exported object")
	}
}

func newExportFixture(t *testing.T) *exportFixture {
	t.Helper()
	h := newFileFixture(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := integrationP256JWK(key)
	if err != nil {
		t.Fatal(err)
	}
	thumb, err := auth.PublicP256JWKThumbprintJSON(public)
	if err != nil {
		t.Fatal(err)
	}
	h.exec(t, `update installations set public_jwk=$1,public_key_thumbprint=$2`, public, thumb)
	connection, err := h.database.AttachRuntimeConnection(h.ctx, RuntimeConnectionInput{InstallationID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", KeyVersion: 1, RuntimeID: h.input.RuntimeID,
		RuntimeEpoch: approvalTestUUID(t), ConnectionID: approvalTestUUID(t), DSHVersion: "0.2.1-rc.2", ApplicationVersion: "file-export-fixture", PluginVersion: "test", ProtocolVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	h.exec(t, `update sessions set state='available' where id=$1`, h.input.SessionID)
	return &exportFixture{fileFixture: h, host: files.HostBinding{InstallationID: connection.InstallationID, KeyVersion: 1, RuntimeID: connection.RuntimeID, RuntimeEpoch: connection.RuntimeEpoch,
		ConnectionID: connection.ConnectionID, CredentialExpiresAt: time.Now().Add(5 * time.Minute)}, input: files.ExportRegistration{RequestID: h.input.RequestID, RuntimeID: h.input.RuntimeID, SessionID: h.input.SessionID,
		SourceID: approvalTestUUID(t), Name: h.input.Name, SizeBytes: h.input.SizeBytes, SHA256: h.input.SHA256, SourceExpiresAt: time.Now().Add(2 * time.Minute)}}
}
func (h *exportFixture) register(t *testing.T) files.Record {
	t.Helper()
	record, err := h.repository.RegisterExport(h.ctx, h.actor, h.host, h.input)
	if err != nil {
		t.Fatal(err)
	}
	return record
}
func (h *exportFixture) clean(t *testing.T) files.Record {
	t.Helper()
	record := h.register(t)
	if _, err := h.repository.BeginExportScan(h.ctx, h.actor, h.host, record.ID); err != nil {
		t.Fatal(err)
	}
	claim := h.claim(t)
	if err := h.repository.CompleteScan(h.ctx, claim); err != nil {
		t.Fatal(err)
	}
	record, err := h.repository.Status(h.ctx, h.actor, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestPostgresExportManifestQuotaAndOriginCommitAtomically(t *testing.T) {
	h := newExportFixture(t)
	first := h.register(t)
	if first.Direction != "from_host" || first.State != "uploading" || first.UploadExpiresAt.After(h.input.SourceExpiresAt) || !first.UploadExpiresAt.Equal(first.ExpiresAt) {
		t.Fatal("export source lifetime/direction changed")
	}
	again := h.register(t)
	if first.ID != again.ID || first.QuarantineAttempt != again.QuarantineAttempt {
		t.Fatal("export retry duplicated its object or identity")
	}
	for _, which := range []string{"source", "name", "size", "hash"} {
		changed := h.input
		switch which {
		case "source":
			changed.SourceID = approvalTestUUID(t)
		case "name":
			changed.Name = "different"
		case "size":
			changed.SizeBytes++
		case "hash":
			changed.SHA256 = strings.Repeat("b", 64)
		}
		if _, err := h.repository.RegisterExport(h.ctx, h.actor, h.host, changed); !errors.Is(err, files.ErrConflict) {
			t.Fatalf("changed %s=%v", which, err)
		}
	}
	if _, err := h.repository.RegisterUpload(h.ctx, h.actor, h.fileFixture.input); !errors.Is(err, files.ErrConflict) {
		t.Fatal("export intent became a phone upload")
	}
	for _, commit := range []bool{false, true} {
		var err error
		if commit {
			_, err = h.repository.BeginScan(h.ctx, h.actor, first.ID)
		} else {
			_, err = h.repository.AuthorizeUpload(h.ctx, h.actor, first.ID)
		}
		if !errors.Is(err, files.ErrAccess) {
			t.Fatal("phone upload/commit admitted an export")
		}
	}
	var entries, objects, origins, count int
	var reserved int64
	if err := h.database.DB.QueryRowContext(h.ctx, `select (select count(*) from files),(select count(*) from file_objects),(select count(*) from file_exports),reserved_files,reserved_bytes from file_quota_usage where kind='session'`).Scan(&entries, &objects, &origins, &count, &reserved); err != nil {
		t.Fatal(err)
	}
	if entries != 1 || objects != 1 || origins != 1 || count != 1 || reserved != h.input.SizeBytes {
		t.Fatal("export reservation was not atomic")
	}
	status, err := h.repository.ExportStatusByRequest(h.ctx, h.actor, h.input.RequestID)
	if err != nil || status.ID != first.ID {
		t.Fatal("original request could not reconcile its file identity")
	}
	raw, _ := json.Marshal(status)
	for _, private := range []string{h.input.SourceID, h.host.ConnectionID, h.host.RuntimeEpoch, first.QuarantineAttempt, "remote-files/"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("export status exposed private provenance")
		}
	}
	var metadata string
	if err := h.database.DB.QueryRowContext(h.ctx, `select string_agg(metadata::text,'') from audit_log where action like 'file.%'`).Scan(&metadata); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(metadata, h.input.Name) {
		t.Fatal("file name entered general audit")
	}
}

func TestPostgresExportUploadAttestationEndsBeforeOfflineScanningAndScopedDownloads(t *testing.T) {
	h := newExportFixture(t)
	record := h.register(t)
	if _, err := h.repository.AuthorizeExportDownload(h.ctx, h.actor, record.ID, fileTestPolicy); !errors.Is(err, files.ErrAccess) {
		t.Fatal("unscanned export was downloadable")
	}
	wrong := h.host
	wrong.ConnectionID = approvalTestUUID(t)
	if _, err := h.repository.BeginExportScan(h.ctx, h.actor, wrong, record.ID); !errors.Is(err, files.ErrAccess) {
		t.Fatal("another Host connection attested the source")
	}
	for range 2 {
		state, err := h.repository.BeginExportScan(h.ctx, h.actor, h.host, record.ID)
		if err != nil || state.State != "scanning" || !state.ExpiresAt.After(record.ExpiresAt) {
			t.Fatal("export scan did not extend only the admitted bytes' retention")
		}
	}
	if err := h.database.DetachRuntimeConnection(h.ctx, h.host.InstallationID, h.host.RuntimeID, h.host.RuntimeEpoch, h.host.ConnectionID); err != nil {
		t.Fatal(err)
	}
	claim := h.claim(t)
	if claim.File.Direction != "from_host" {
		t.Fatal("scan lost export direction")
	}
	changed := claim
	changed.File.Direction = "to_host"
	if err := h.repository.CompleteScan(h.ctx, changed); !errors.Is(err, files.ErrStale) {
		t.Fatal("a scan claim changed transfer direction")
	}
	if err := h.repository.CompleteScan(h.ctx, claim); err != nil {
		t.Fatal(err)
	}
	permit, err := h.repository.AuthorizeExportDownload(h.ctx, h.actor, record.ID, fileTestPolicy)
	if err != nil || permit.File.State != "clean" || permit.LeaseUntil.After(time.Now().Add(5*time.Second)) {
		t.Fatalf("download permit=%v error=%v", permit, err)
	}
	if encoded, _ := json.Marshal(permit); string(encoded) != "{}" {
		t.Fatal("download authority serialized")
	}
	wrongActor := h.actor
	wrongActor.DeviceID = approvalTestUUID(t)
	if _, err := h.repository.AuthorizeExportDownload(h.ctx, wrongActor, record.ID, fileTestPolicy); !errors.Is(err, files.ErrAccess) {
		t.Fatal("another device read a private export")
	}
	if _, err := h.repository.AuthorizeExportDownload(h.ctx, h.actor, record.ID, strings.Repeat("b", 64)); !errors.Is(err, files.ErrAccess) {
		t.Fatal("a different scanner policy admitted the object")
	}
	var scans, events int
	if err := h.database.DB.QueryRowContext(h.ctx, `select (select count(*) from audit_log where action='file.export_scan_requested'),(select count(*) from control_outbox where topic='file.export.clean')`).Scan(&scans, &events); err != nil || scans != 1 || events != 1 {
		t.Fatal("scan retry duplicated admission or event")
	}
	h.exec(t, `update runtime_grants set grant_version=grant_version+1 where runtime_id=$1`, h.input.RuntimeID)
	fresh, err := h.repository.AuthorizeExportDownload(h.ctx, h.actor, record.ID, fileTestPolicy)
	if err != nil || fresh.AuthorizedGrantVersion == permit.AuthorizedGrantVersion {
		t.Fatal("download did not bind its current authorization generation")
	}
	h.exec(t, `update runtime_grants set scope=jsonb_set(scope,'{actions}','["session.read"]'::jsonb) where runtime_id=$1`, h.input.RuntimeID)
	if _, err := h.repository.AuthorizeExportDownload(h.ctx, h.actor, record.ID, fileTestPolicy); !errors.Is(err, files.ErrAccess) {
		t.Fatal("download survived removal of its own action")
	}
}

func TestPostgresExportRequiresReadAndDownloadScopesAndCurrentSourceBinding(t *testing.T) {
	for _, which := range []string{"download", "read", "workspace", "epoch", "device", "expires", "generation"} {
		t.Run(which, func(t *testing.T) {
			h := newExportFixture(t)
			actor, host, input := h.actor, h.host, h.input
			switch which {
			case "download":
				h.exec(t, `update runtime_grants set scope=jsonb_set(scope,'{actions}','["session.read","file.upload"]'::jsonb)`)
			case "read":
				h.exec(t, `update runtime_grants set scope=jsonb_set(scope,'{actions}','["file.download","file.upload"]'::jsonb)`)
			case "workspace":
				h.exec(t, `update runtime_grants set scope=jsonb_set(scope,'{workspaces}','[]'::jsonb)`)
			case "epoch":
				host.RuntimeEpoch = approvalTestUUID(t)
			case "device":
				actor.DeviceID = approvalTestUUID(t)
			case "expires":
				input.SourceExpiresAt = time.Now().Add(-time.Second)
			case "generation":
				record := h.register(t)
				h.exec(t, `update runtime_grants set grant_version=grant_version+1`)
				if _, err := h.repository.BeginExportScan(h.ctx, actor, host, record.ID); !errors.Is(err, files.ErrAccess) {
					t.Fatal("old source upload upgraded its grant")
				}
				return
			}
			if _, err := h.repository.RegisterExport(h.ctx, actor, host, input); !errors.Is(err, files.ErrAccess) && !errors.Is(err, files.ErrStale) {
				t.Fatalf("unauthorized source accepted: %v", err)
			}
		})
	}
}

func TestPostgresExportAuditsRollBackManifestAndUploadAdmission(t *testing.T) {
	for _, phase := range []string{"register", "upload"} {
		t.Run(phase, func(t *testing.T) {
			h := newExportFixture(t)
			var record files.Record
			if phase == "upload" {
				record = h.register(t)
			}
			h.exec(t, `create function reject_export_audit() returns trigger language plpgsql as $$ begin raise exception 'fixture audit rejection'; end $$; create trigger reject_export_audit before insert on audit_log for each row execute function reject_export_audit()`)
			if phase == "register" {
				if _, err := h.repository.RegisterExport(h.ctx, h.actor, h.host, h.input); !errors.Is(err, files.ErrUnavailable) {
					t.Fatal("missing audit did not abort export")
				}
				var count int
				if err := h.database.DB.QueryRowContext(h.ctx, `select (select count(*) from files)+(select count(*) from file_exports)+(select count(*) from file_objects)+(select count(*) from file_quota_usage)`).Scan(&count); err != nil || count != 0 {
					t.Fatal("partial export survived audit rollback")
				}
			} else {
				if _, err := h.repository.BeginExportScan(h.ctx, h.actor, h.host, record.ID); !errors.Is(err, files.ErrUnavailable) {
					t.Fatal("missing upload audit did not abort source attestation")
				}
				var state string
				var uploaded bool
				if err := h.database.DB.QueryRowContext(h.ctx, `select f.state,e.uploaded_at is not null from files f join file_exports e on e.file_id=f.id where f.id=$1`, record.ID).Scan(&state, &uploaded); err != nil || state != "uploading" || uploaded {
					t.Fatal("failed attestation became scan authority")
				}
			}
		})
	}
}

func TestPostgresUploadAndExportShareTheirQuotaAndCannotOversubscribe(t *testing.T) {
	h := newExportFixture(t)
	h.limits.SessionBytes = 100
	var err error
	h.repository, err = NewFileStore(h.database, h.limits)
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	results := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			if index%2 == 0 {
				input := h.input
				input.RequestID = approvalTestUUID(t)
				input.SizeBytes = 60
				_, err := h.repository.RegisterExport(h.ctx, h.actor, h.host, input)
				results <- err
			} else {
				input := h.fileFixture.input
				input.RequestID = approvalTestUUID(t)
				input.SizeBytes = 60
				_, err := h.repository.RegisterUpload(h.ctx, h.actor, input)
				results <- err
			}
		}(i)
	}
	wait.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, files.ErrQuota) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatal("phone uploads and Host exports oversubscribed shared quota")
	}
}

func TestPostgresExportSourceExpiresWhileWaitingForQuotaAndCannotPublishWithoutAttestation(t *testing.T) {
	h := newExportFixture(t)
	authority := fileAuthority{org: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", user: "22222222-2222-4222-8222-222222222222"}
	tx, err := h.database.DB.BeginTx(h.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// Insert quota rows first, then hold them without blocking registration's
	// user/runtime checks. The source expires at the actual locked boundary.
	if _, err := h.repository.lockQuotas(h.ctx, tx, authority, h.input.SessionID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	hold, err := h.database.DB.BeginTx(h.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Rollback()
	if _, err := h.repository.lockQuotas(h.ctx, hold, authority, h.input.SessionID); err != nil {
		t.Fatal(err)
	}
	h.input.SourceExpiresAt = time.Now().Add(100 * time.Millisecond)
	finished := make(chan error, 1)
	go func() { _, err := h.repository.RegisterExport(h.ctx, h.actor, h.host, h.input); finished <- err }()
	time.Sleep(200 * time.Millisecond)
	if err := hold.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-finished; !errors.Is(err, files.ErrStale) {
		t.Fatalf("expired source registered after quota wait: %v", err)
	}
	h.input.SourceExpiresAt = time.Now().Add(time.Minute)
	record := h.register(t)
	h.exec(t, `update files set state='scanning' where id=$1`, record.ID)
	if claim, err := h.repository.ClaimScan(h.ctx, fileTestPolicy); err != nil || claim != nil {
		t.Fatal("a mere scanning flag bypassed Host upload attestation")
	}
	state, err := h.repository.Status(h.ctx, h.actor, record.ID)
	if err != nil || state.State != "rejected" || state.ErrorCode != "access_revoked" {
		t.Fatal("unattested export was not retired")
	}
	_, _ = h.repository.Expire(context.Background(), 1)
}
