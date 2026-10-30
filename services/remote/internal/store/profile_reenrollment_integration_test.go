package store

import (
	"errors"
	"os"
	"sync"
	"testing"
)

func TestRetiredProfileReenrollmentRequiresFreshAuthority(t *testing.T) {
	ctx, db, input, old := enrollmentPreviewFixture(t)
	owner := UserIdentity{Issuer: input.Issuer, Subject: input.Subject}
	phone := UserIdentity{Issuer: input.Issuer, Subject: "target-subject"}
	const ownerDevice = "44444444-4444-4444-8444-444444444444"
	const ownerID = "22222222-2222-4222-8222-222222222222"
	const targetID = "66666666-6666-4666-8666-666666666666"
	var proof string
	if err := db.DB.QueryRowContext(ctx, `select proof_key_thumbprint from devices where id=$1`, ownerDevice).Scan(&proof); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ConfirmEnrollmentUser(ctx, phone, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "proof-jkt-target", old.EnrollmentID, input.Code); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, old.EnrollmentID, input.Code, targetID); err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeInstallationRuntime(ctx, owner, ownerDevice, proof, old.InstallationID, old.RuntimeID); err != nil {
		t.Fatal(err)
	}
	// Reusing the old request reconciles that original identity, never creates a replacement.
	replay, err := db.CreateEnrollment(ctx, input)
	if err != nil || replay.RuntimeID != old.RuntimeID || replay.EnrollmentID != old.EnrollmentID {
		t.Fatal("old request changed identity", replay, err)
	}
	input.RequestID = "aaaaaaaa-2222-4222-8222-222222222222"
	input.Code = validEnrollmentInput(t).Code
	fresh, err := db.CreateEnrollment(ctx, input)
	if err != nil {
		t.Fatal("retired profile could not enroll again", err)
	}
	if fresh.RuntimeID == old.RuntimeID || fresh.EnrollmentID == old.EnrollmentID || fresh.InstallationID != old.InstallationID || fresh.HostID != old.HostID || fresh.State != "pending" {
		t.Fatal("replacement inherited identity or activation", fresh)
	}
	for _, workspace := range fresh.Workspaces {
		for _, historical := range old.Workspaces {
			if workspace.ID == historical.ID {
				t.Fatal("replacement reused historical workspace authority")
			}
		}
	}
	var grants int
	if err := db.DB.QueryRowContext(ctx, `select count(*) from runtime_grants where runtime_id=$1`, fresh.RuntimeID).Scan(&grants); err != nil || grants != 0 {
		t.Fatal("replacement inherited grants", grants, err)
	}
	if _, err := db.AttachRuntimeConnection(ctx, enrollmentConnection(fresh)); !errors.Is(err, ErrHostCredentialInvalid) {
		t.Fatal("pending replacement attached", err)
	}
	if _, err := db.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, fresh.EnrollmentID, input.Code, ownerID); !errors.Is(err, ErrEnrollmentInvalid) {
		t.Fatal("replacement skipped phone confirmation", err)
	}
	if _, err := db.ConfirmEnrollmentUser(ctx, owner, ownerDevice, proof, fresh.EnrollmentID, input.Code); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AttachRuntimeConnection(ctx, enrollmentConnection(fresh)); !errors.Is(err, ErrHostCredentialInvalid) {
		t.Fatal("phone-only replacement attached", err)
	}
	if _, err := db.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, fresh.EnrollmentID, input.Code, ownerID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AttachRuntimeConnection(ctx, enrollmentConnection(fresh)); err != nil {
		t.Fatal("freshly confirmed replacement could not attach", err)
	}
	if _, err := db.AttachRuntimeConnection(ctx, enrollmentConnection(old)); !errors.Is(err, ErrHostCredentialInvalid) {
		t.Fatal("replacement revived historical runtime", err)
	}
	if err := assertGrantState(ctx, db.DB, old.RuntimeID, targetID, 2, "owner", true); err != nil {
		t.Fatal("replacement changed historical grant", err)
	}
	if err := assertGrantState(ctx, db.DB, fresh.RuntimeID, ownerID, 1, "owner", false); err != nil {
		t.Fatal("fresh approval did not create new owner grant", err)
	}
	if err := db.DB.QueryRowContext(ctx, `select count(*) from runtime_grants where runtime_id=$1 and user_id=$2`, fresh.RuntimeID, targetID).Scan(&grants); err != nil || grants != 0 {
		t.Fatal("historical confirming user inherited access", grants, err)
	}
	// A delayed retry of the old retirement remains scoped to its UUID.
	if err := db.RevokeInstallationRuntime(ctx, owner, ownerDevice, proof, old.InstallationID, old.RuntimeID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AttachRuntimeConnection(ctx, enrollmentConnection(fresh)); err != nil {
		t.Fatal("old retirement retry affected replacement", err)
	}
	if err := db.RevokeInstallation(ctx, owner, ownerDevice, proof, old.InstallationID); err != nil {
		t.Fatal(err)
	}
	input.RequestID = "aaaaaaaa-3333-4333-8333-333333333333"
	if _, err := db.CreateEnrollment(ctx, input); !errors.Is(err, ErrEnrollmentConflict) {
		t.Fatal("retired installation permitted replacement", err)
	}
}

func TestProfileReenrollmentCannotReplaceUnrevokedRuntime(t *testing.T) {
	for _, state := range []string{"pending", "user_confirmed", "approved", "expired"} {
		t.Run(state, func(t *testing.T) {
			ctx, db, input, old := enrollmentPreviewFixture(t)
			// Even a stale or expired application does not implicitly retire its runtime.
			if _, err := db.DB.ExecContext(ctx, `update enrollments set state=$2 where id=$1`, old.EnrollmentID, state); err != nil {
				t.Fatal(err)
			}
			input.RequestID = "aaaaaaaa-2222-4222-8222-222222222222"
			if _, err := db.CreateEnrollment(ctx, input); !errors.Is(err, ErrEnrollmentConflict) {
				t.Fatal("unrevoked profile was replaced", err)
			}
		})
	}
}

func TestProfileReenrollmentHasOneUnrevokedIdentityUnderContention(t *testing.T) {
	ctx, db, input, old := enrollmentPreviewFixture(t)
	owner := UserIdentity{Issuer: input.Issuer, Subject: input.Subject}
	var proof string
	if err := db.DB.QueryRowContext(ctx, `select proof_key_thumbprint from devices where id='44444444-4444-4444-8444-444444444444'`).Scan(&proof); err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeInstallationRuntime(ctx, owner, "44444444-4444-4444-8444-444444444444", proof, old.InstallationID, old.RuntimeID); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	results := make(chan error, 2)
	for _, requestID := range []string{"aaaaaaaa-2222-4222-8222-222222222222", "aaaaaaaa-3333-4333-8333-333333333333"} {
		attempt := input
		attempt.RequestID = requestID
		attempt.Code = validEnrollmentInput(t).Code
		wait.Go(func() {
			_, err := db.CreateEnrollment(ctx, attempt)
			results <- err
		})
	}
	wait.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrEnrollmentConflict) && !errors.Is(err, ErrDatabaseUnavailable) {
			t.Fatal("unexpected contended enrollment error", err)
		}
	}
	var active, historical int
	if err := db.DB.QueryRowContext(ctx, `select count(*) filter(where revoked_at is null),count(*) filter(where revoked_at is not null) from runtimes where installation_id=$1 and profile_ref=$2`, old.InstallationID, old.ProfileRef).Scan(&active, &historical); err != nil || successes != 1 || active != 1 || historical != 1 {
		t.Fatal("profile uniqueness lost under contention", successes, active, historical, err)
	}
}

func TestProfileReenrollmentMigrationRollbackPreservesHistory(t *testing.T) {
	ctx, db, _, old := enrollmentPreviewFixture(t)
	down, err := os.ReadFile("../../../../deploy/sql/036_profile_reenrollment.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, err := os.ReadFile("../../../../deploy/sql/036_profile_reenrollment.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, string(down)); err != nil {
		t.Fatal("unused migration could not roll back", err)
	}
	if _, err := db.DB.ExecContext(ctx, string(up)); err != nil {
		t.Fatal("migration could not reapply", err)
	}
	if _, err := db.DB.ExecContext(ctx, `update runtimes set revoked_at=clock_timestamp() where id=$1`, old.RuntimeID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `insert into runtimes(installation_id,profile_ref,protocol_version) values($1,$2,1)`, old.InstallationID, old.ProfileRef); err != nil {
		t.Fatal(err)
	}
	connection, err := db.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, rollbackErr := connection.ExecContext(ctx, string(down))
	if _, err := connection.ExecContext(ctx, `rollback`); err != nil {
		t.Fatal(err)
	}
	if rollbackErr == nil {
		t.Fatal("migration rollback discarded duplicate historical references")
	}
	var count int
	if err := db.DB.QueryRowContext(ctx, `select count(*) from runtimes where installation_id=$1 and profile_ref=$2`, old.InstallationID, old.ProfileRef).Scan(&count); err != nil || count != 2 {
		t.Fatal("failed rollback changed historical identities", count, err)
	}
	if _, err := db.DB.ExecContext(ctx, `insert into runtimes(installation_id,profile_ref,protocol_version) values($1,$2,1)`, old.InstallationID, old.ProfileRef); err == nil {
		t.Fatal("failed rollback removed live profile uniqueness")
	}
}
