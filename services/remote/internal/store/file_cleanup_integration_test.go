package store

import (
	"errors"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/files"
)

func (fixture *fileFixture) expired(t *testing.T, id string) {
	t.Helper()
	fixture.exec(t, `update files set created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' where id=$1`, id)
	count, err := fixture.repository.Expire(fixture.ctx, 128)
	if err != nil || count != 1 {
		t.Fatalf("expiry count=%d error=%v", count, err)
	}
	fixture.exec(t, `update file_objects set cleanup_after=clock_timestamp()-interval '1 second' where file_id=$1`, id)
}
func (fixture *fileFixture) deletion(t *testing.T) files.DeletionClaim {
	t.Helper()
	claim, err := fixture.repository.ClaimDeletion(fixture.ctx)
	if err != nil || claim == nil {
		t.Fatalf("deletion=%v error=%v", claim, err)
	}
	return *claim
}
func (fixture *fileFixture) quota(t *testing.T, bytes, count int64) {
	t.Helper()
	var actualBytes, actualCount int64
	if err := fixture.database.DB.QueryRowContext(fixture.ctx, `select reserved_bytes,reserved_files from file_quota_usage where kind='session'`).Scan(&actualBytes, &actualCount); err != nil || actualBytes != bytes || actualCount != count {
		t.Fatalf("session quota=%d/%d want=%d/%d error=%v", actualBytes, actualCount, bytes, count, err)
	}
}

func TestPostgresFileExpiryWaitsForDeletionAndReconcilesWithoutDoubleQuotaRelease(t *testing.T) {
	h := newFileFixture(t)
	file, err := h.repository.RegisterUpload(h.ctx, h.actor, h.input)
	if err != nil {
		t.Fatal(err)
	}
	h.expired(t, file.ID)
	h.quota(t, h.input.SizeBytes, 1)
	claim := h.deletion(t)
	if claim.Kind != files.Quarantine {
		t.Fatal("wrong source deletion")
	}
	wrong := claim
	wrong.LeaseID = approvalTestUUID(t)
	if err := h.repository.CompleteDeletion(h.ctx, wrong, true); !errors.Is(err, files.ErrStale) {
		t.Fatal("wrong deletion lease accepted")
	}
	if err := h.repository.CompleteDeletion(h.ctx, claim, false); err != nil {
		t.Fatal(err)
	}
	h.quota(t, h.input.SizeBytes, 1)
	h.exec(t, `update file_objects set cleanup_after=clock_timestamp()-interval '1 second' where file_id=$1`, file.ID)
	claim = h.deletion(t)
	if err := h.repository.CompleteDeletion(h.ctx, claim, true); err != nil {
		t.Fatal(err)
	}
	h.quota(t, 0, 0)
	if err := h.repository.CompleteDeletion(h.ctx, claim, true); !errors.Is(err, files.ErrStale) {
		t.Fatal("duplicate deletion proof was reused")
	}
	h.exec(t, `update file_objects set cleanup_after=clock_timestamp()-interval '1 second' where file_id=$1`, file.ID)
	reconcile := h.deletion(t)
	if reconcile.LeaseID == claim.LeaseID {
		t.Fatal("reconciliation reused its proof")
	}
	if err := h.repository.CompleteDeletion(h.ctx, reconcile, true); err != nil {
		t.Fatal(err)
	}
	h.quota(t, 0, 0)
	var released int
	if err := h.database.DB.QueryRowContext(h.ctx, `select count(*) from audit_log where action='file.quota_released'`).Scan(&released); err != nil || released != 1 {
		t.Fatal("quota release was not exactly once")
	}
}

func TestPostgresCleanCandidateIsProtectedAndAllTrackedObjectsMustBeDeleted(t *testing.T) {
	h := newFileFixture(t)
	file := h.scanning(t)
	scan := h.claim(t)
	if err := h.repository.CompleteScan(h.ctx, scan); err != nil {
		t.Fatal(err)
	}
	h.exec(t, `update file_objects set cleanup_after=clock_timestamp()-interval '1 second' where file_id=$1`, file.ID)
	source := h.deletion(t)
	if source.Kind != files.Quarantine {
		t.Fatal("active clean candidate was selected for deletion")
	}
	if err := h.repository.CompleteDeletion(h.ctx, source, true); err != nil {
		t.Fatal(err)
	}
	h.quota(t, h.input.SizeBytes, 1)
	if claim, err := h.repository.ClaimDeletion(h.ctx); err != nil || claim != nil {
		t.Fatal("clean candidate entered GC")
	}
	h.expired(t, file.ID)
	for range 2 {
		claim := h.deletion(t)
		if err := h.repository.CompleteDeletion(h.ctx, claim, true); err != nil {
			t.Fatal(err)
		}
	}
	h.quota(t, 0, 0)
}

func TestPostgresDeletionAuditFailureRollsBackProofAndQuotaTogether(t *testing.T) {
	h := newFileFixture(t)
	file, err := h.repository.RegisterUpload(h.ctx, h.actor, h.input)
	if err != nil {
		t.Fatal(err)
	}
	h.expired(t, file.ID)
	claim := h.deletion(t)
	h.exec(t, `create function fail_file_release_audit() returns trigger language plpgsql as $$ begin raise exception 'injected quota audit failure'; end $$;
	 create trigger file_release_audit_failure before insert on audit_log for each row when(new.action='file.quota_released') execute function fail_file_release_audit()`)
	if err := h.repository.CompleteDeletion(h.ctx, claim, true); !errors.Is(err, files.ErrUnavailable) {
		t.Fatalf("quota audit failure=%v", err)
	}
	h.quota(t, h.input.SizeBytes, 1)
	var deleted bool
	if err := h.database.DB.QueryRowContext(h.ctx, `select deleted_at is not null from file_objects where file_id=$1`, file.ID).Scan(&deleted); err != nil || deleted {
		t.Fatal("failed transaction kept a deletion proof")
	}
	h.exec(t, `drop trigger file_release_audit_failure on audit_log;drop function fail_file_release_audit()`)
	if err := h.repository.CompleteDeletion(h.ctx, claim, true); err != nil {
		t.Fatal(err)
	}
	h.quota(t, 0, 0)
}

func TestPostgresLegacyFileRowsHaveNoDeviceBoundAuthority(t *testing.T) {
	h := newFileFixture(t)
	id := approvalTestUUID(t)
	h.exec(t, `insert into files(id,session_id,uploader_id,direction,name,size_bytes,sha256,object_key,state,expires_at)
	 values($1,$2,'22222222-2222-4222-8222-222222222222','to_host','legacy.txt',1,$3,'legacy-unscanned-object','clean',clock_timestamp()+interval '1 day')`, id, h.input.SessionID, h.input.SHA256)
	if _, err := h.repository.Status(h.ctx, h.actor, id); !errors.Is(err, files.ErrAccess) {
		t.Fatal("legacy clean flag bypassed new proof")
	}
	if _, err := h.repository.BeginScan(h.ctx, h.actor, id); !errors.Is(err, files.ErrAccess) {
		t.Fatal("legacy file acquired device authority")
	}
}
