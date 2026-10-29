package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func enrollmentPreviewFixture(t *testing.T) (context.Context, *Postgres, EnrollmentInput, EnrollmentCreated) {
	t.Helper()
	ctx, postgres := newPostgresIntegrationDatabase(t)
	seedGrantFixture(t, ctx, postgres.DB)
	input := validEnrollmentInput(t)
	input.Subject = "owner-subject"
	input.OrganizationID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	created, err := postgres.CreateEnrollment(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, postgres, input, created
}

func TestEnrollmentPreviewNeedsTheCodeAndDoesNotGrantOrConfirm(t *testing.T) {
	ctx, postgres, input, created := enrollmentPreviewFixture(t)
	owner := UserIdentity{Issuer: input.Issuer, Subject: input.Subject}
	phone := UserIdentity{Issuer: input.Issuer, Subject: "target-subject"}
	outsider := UserIdentity{Issuer: input.Issuer, Subject: "outsider-subject"}
	info, err := postgres.GetEnrollment(ctx, owner, created.EnrollmentID)
	if err != nil || info.InstallationKeyJKT != input.InstallationKeyThumbprint || info.UserConfirmedByMe {
		t.Fatalf("owner status: %+v %v", info, err)
	}
	if _, err := postgres.GetEnrollment(ctx, phone, created.EnrollmentID); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("unconfirmed member status: %v", err)
	}
	for _, code := range []string{"invalid", validEnrollmentInput(t).Code} {
		if _, err := postgres.PreviewEnrollment(ctx, phone, created.EnrollmentID, code); !errors.Is(err, ErrEnrollmentInvalid) {
			t.Fatalf("wrong code preview: %v", err)
		}
	}
	if _, err := postgres.PreviewEnrollment(ctx, outsider, created.EnrollmentID, input.Code); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("cross organization preview: %v", err)
	}
	if _, err := postgres.PreviewEnrollment(ctx, UserIdentity{Issuer: "https://other.example.edu", Subject: phone.Subject}, created.EnrollmentID, input.Code); !errors.Is(err, ErrIdentityNotProvisioned) {
		t.Fatalf("cross issuer preview: %v", err)
	}
	info, err = postgres.PreviewEnrollment(ctx, phone, created.EnrollmentID, input.Code)
	if err != nil || info.HostConfirmed || info.UserConfirmed || info.UserConfirmedByMe || info.State != "pending" {
		t.Fatalf("phone preview: %+v %v", info, err)
	}
	bytes, _ := json.Marshal(info)
	if strings.Contains(string(bytes), input.Code) {
		t.Fatal("preview returned the confirmation secret")
	}
	var grants, confirmations int
	if err := postgres.DB.QueryRowContext(ctx, `select (select count(*) from runtime_grants where runtime_id=$1), (select count(*) from audit_log where action='enrollment.user_confirm' and runtime_id=$1)`, created.RuntimeID).Scan(&grants, &confirmations); err != nil || grants != 0 || confirmations != 0 {
		t.Fatalf("preview mutated authority: grants=%d confirmations=%d err=%v", grants, confirmations, err)
	}
	if _, err := postgres.ConfirmEnrollmentUser(ctx, phone, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "proof-jkt-target", created.EnrollmentID, input.Code); err != nil {
		t.Fatal(err)
	}
	mine, err := postgres.GetEnrollment(ctx, phone, created.EnrollmentID)
	if err != nil || !mine.UserConfirmedByMe || !mine.UserConfirmed || mine.HostConfirmed {
		t.Fatalf("phone attribution: %+v %v", mine, err)
	}
	other, err := postgres.GetEnrollment(ctx, owner, created.EnrollmentID)
	if err != nil || other.UserConfirmedByMe || !other.UserConfirmed {
		t.Fatalf("owner attribution: %+v %v", other, err)
	}
	var ownerProof string
	if err := postgres.DB.QueryRowContext(ctx, `select proof_key_thumbprint from devices where id=$1`, "44444444-4444-4444-8444-444444444444").Scan(&ownerProof); err != nil {
		t.Fatal(err)
	}
	for _, approved := range []bool{false, true} {
		if approved {
			if _, err := postgres.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, created.EnrollmentID, input.Code, "66666666-6666-4666-8666-666666666666"); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := postgres.ConfirmEnrollmentUser(ctx, owner, "44444444-4444-4444-8444-444444444444", ownerProof, created.EnrollmentID, input.Code); !errors.Is(err, ErrEnrollmentInvalid) {
			t.Fatalf("another phone account claimed confirmed=%t: %v", approved, err)
		}
	}
}

func TestHostConfirmationRequiresTheReviewedPhoneIdentity(t *testing.T) {
	ctx, postgres, input, created := enrollmentPreviewFixture(t)
	owner := UserIdentity{Issuer: input.Issuer, Subject: input.Subject}
	phone := UserIdentity{Issuer: input.Issuer, Subject: "target-subject"}
	const phoneID = "66666666-6666-4666-8666-666666666666"
	const ownerID = "22222222-2222-4222-8222-222222222222"
	if _, err := postgres.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, created.EnrollmentID, input.Code, phoneID); !errors.Is(err, ErrEnrollmentInvalid) {
		t.Fatalf("host-first confirmation = %v", err)
	}
	var hostConfirmed bool
	if err := postgres.DB.QueryRowContext(ctx, `select host_confirmed_at is not null from enrollments where id=$1`, created.EnrollmentID).Scan(&hostConfirmed); err != nil || hostConfirmed {
		t.Fatalf("host-first confirmation changed enrollment: confirmed=%t err=%v", hostConfirmed, err)
	}
	// Simulate a pending host-first decision written by an older server.
	if _, err := postgres.DB.ExecContext(ctx, `update enrollments set host_confirmed_at=clock_timestamp() where id=$1`, created.EnrollmentID); err != nil {
		t.Fatal(err)
	}
	legacy, err := postgres.GetEnrollment(ctx, owner, created.EnrollmentID)
	if err != nil || legacy.HostConfirmed || legacy.UserConfirmed {
		t.Fatalf("legacy host-first timestamp appeared as a reviewed confirmation: %+v %v", legacy, err)
	}
	partial, err := postgres.ConfirmEnrollmentUser(ctx, phone, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "proof-jkt-target", created.EnrollmentID, input.Code)
	if err != nil || partial.State != "user_confirmed" || partial.HostConfirmed {
		t.Fatalf("legacy host-first decision survived phone confirmation: %+v %v", partial, err)
	}
	info, err := postgres.GetEnrollment(ctx, owner, created.EnrollmentID)
	if err != nil || !info.HostReviewOwner || info.HostReviewUser == nil || info.HostReviewUser.UserID != phoneID ||
		info.HostReviewUser.Issuer != input.Issuer || info.HostReviewUser.Subject != phone.Subject || !info.HostReviewUser.Eligible {
		t.Fatalf("host review identity: %+v %v", info.HostReviewUser, err)
	}
	ordinary, _ := json.Marshal(info)
	if strings.Contains(string(ordinary), phone.Subject) || strings.Contains(string(ordinary), phoneID) {
		t.Fatal("ordinary enrollment status disclosed host-only identity")
	}
	phoneInfo, err := postgres.GetEnrollment(ctx, phone, created.EnrollmentID)
	if err != nil || phoneInfo.HostReviewOwner || phoneInfo.HostReviewUser != nil {
		t.Fatalf("phone was treated as installation owner: %+v %v", phoneInfo, err)
	}
	if _, err := postgres.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, created.EnrollmentID, input.Code, ownerID); !errors.Is(err, ErrEnrollmentInvalid) {
		t.Fatalf("confirmation accepted an unreviewed user: %v", err)
	}
	if _, err := postgres.DB.ExecContext(ctx, `delete from org_memberships where org_id=$1 and user_id=$2`, input.OrganizationID, phoneID); err != nil {
		t.Fatal(err)
	}
	info, err = postgres.GetEnrollment(ctx, owner, created.EnrollmentID)
	if err != nil || info.HostReviewUser == nil || info.HostReviewUser.Eligible {
		t.Fatalf("removed member remained eligible in review: %+v %v", info.HostReviewUser, err)
	}
	if _, err := postgres.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, created.EnrollmentID, input.Code, phoneID); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("removed member was granted access: %v", err)
	}
	if _, err := postgres.DB.ExecContext(ctx, `insert into org_memberships(org_id,user_id,role) values($1,$2,'member')`, input.OrganizationID, phoneID); err != nil {
		t.Fatal(err)
	}
	approved, err := postgres.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, created.EnrollmentID, input.Code, phoneID)
	if err != nil || approved.State != "approved" || !approved.HostConfirmed || !approved.UserConfirmed {
		t.Fatalf("reviewed confirmation failed: %+v %v", approved, err)
	}
	var metadata string
	if err := postgres.DB.QueryRowContext(ctx, `select metadata::text from audit_log where action='enrollment.host_confirm' and runtime_id=$1`, created.RuntimeID).Scan(&metadata); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(metadata, phoneID) || strings.Contains(metadata, phone.Subject) || strings.Contains(metadata, input.Code) {
		t.Fatalf("host confirmation audit omitted reviewed identity or exposed secret: %s", metadata)
	}
	if _, err := postgres.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, created.EnrollmentID, input.Code, ownerID); !errors.Is(err, ErrEnrollmentInvalid) {
		t.Fatalf("approved retry accepted a different user: %v", err)
	}
}

func TestHostConfirmationRechecksThePhoneDeviceAndKeyVersion(t *testing.T) {
	ctx, postgres, input, created := enrollmentPreviewFixture(t)
	owner := UserIdentity{Issuer: input.Issuer, Subject: input.Subject}
	phone := UserIdentity{Issuer: input.Issuer, Subject: "target-subject"}
	const phoneID = "66666666-6666-4666-8666-666666666666"
	const originalDevice = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	const replacementDevice = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	if _, err := postgres.ConfirmEnrollmentUser(ctx, phone, originalDevice, "wrong-proof-key", created.EnrollmentID, input.Code); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("confirmation accepted an unrelated proof key: %v", err)
	}
	if _, err := postgres.ConfirmEnrollmentUser(ctx, phone, originalDevice, "proof-jkt-target", created.EnrollmentID, input.Code); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.DB.ExecContext(ctx, `update devices set key_version=key_version+1 where id=$1`, originalDevice); err != nil {
		t.Fatal(err)
	}
	info, err := postgres.GetEnrollment(ctx, owner, created.EnrollmentID)
	if err != nil || info.HostReviewUser == nil || info.HostReviewUser.Eligible {
		t.Fatalf("rotated confirmation still eligible: %+v %v", info.HostReviewUser, err)
	}
	if _, err := postgres.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, created.EnrollmentID, input.Code, phoneID); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("rotated device activated a host: %v", err)
	}
	if _, err := postgres.ConfirmEnrollmentUser(ctx, phone, originalDevice, "proof-jkt-target", created.EnrollmentID, input.Code); err != nil {
		t.Fatalf("fresh key version could not reconfirm: %v", err)
	}
	if err := postgres.RevokeDevice(ctx, phone.Issuer, phone.Subject, originalDevice); err != nil {
		t.Fatal(err)
	}
	info, err = postgres.GetEnrollment(ctx, owner, created.EnrollmentID)
	if err != nil || info.HostReviewUser == nil || info.HostReviewUser.Eligible {
		t.Fatalf("revoked confirmation still eligible: %+v %v", info.HostReviewUser, err)
	}
	if _, err := postgres.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, created.EnrollmentID, input.Code, phoneID); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("revoked phone activated a host: %v", err)
	}
	if _, err := postgres.DB.ExecContext(ctx, `insert into devices(id,user_id,name,approval_public_jwk,approval_key_thumbprint,proof_public_jwk,proof_key_thumbprint)
		values($1,$2,'replacement','{}'::jsonb,'approval-jkt-replacement','{}'::jsonb,'proof-jkt-replacement')`, replacementDevice, phoneID); err != nil {
		t.Fatal(err)
	}
	partial, err := postgres.ConfirmEnrollmentUser(ctx, phone, replacementDevice, "proof-jkt-replacement", created.EnrollmentID, input.Code)
	if err != nil || partial.State != "user_confirmed" || partial.HostConfirmed {
		t.Fatalf("replacement phone did not require host review: %+v %v", partial, err)
	}
	info, err = postgres.GetEnrollment(ctx, owner, created.EnrollmentID)
	if err != nil || info.HostReviewUser == nil || !info.HostReviewUser.Eligible {
		t.Fatalf("replacement confirmation is not eligible: %+v %v", info.HostReviewUser, err)
	}
	approved, err := postgres.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, created.EnrollmentID, input.Code, phoneID)
	if err != nil || approved.State != "approved" {
		t.Fatalf("reviewed replacement could not complete enrollment: %+v %v", approved, err)
	}
}

func TestLegacyPhoneConfirmationMustBeReconfirmed(t *testing.T) {
	ctx, postgres, input, created := enrollmentPreviewFixture(t)
	owner := UserIdentity{Issuer: input.Issuer, Subject: input.Subject}
	phone := UserIdentity{Issuer: input.Issuer, Subject: "target-subject"}
	const phoneID = "66666666-6666-4666-8666-666666666666"
	if _, err := postgres.DB.ExecContext(ctx, `update enrollments set state='user_confirmed',user_confirmed_by=$2,user_confirmed_at=clock_timestamp(),host_confirmed_at=clock_timestamp() where id=$1`, created.EnrollmentID, phoneID); err != nil {
		t.Fatal(err)
	}
	info, err := postgres.GetEnrollment(ctx, owner, created.EnrollmentID)
	if err != nil || info.HostConfirmed || info.HostReviewUser == nil || info.HostReviewUser.Eligible {
		t.Fatalf("legacy unbound confirmation appeared eligible: %+v %v", info, err)
	}
	if _, err := postgres.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, created.EnrollmentID, input.Code, phoneID); !errors.Is(err, ErrEnrollmentInvalid) {
		t.Fatalf("legacy unbound phone activated a host: %v", err)
	}
	partial, err := postgres.ConfirmEnrollmentUser(ctx, phone, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "proof-jkt-target", created.EnrollmentID, input.Code)
	if err != nil || partial.State != "user_confirmed" || partial.HostConfirmed {
		t.Fatalf("legacy reconfirmation retained old host decision: %+v %v", partial, err)
	}
	if _, err := postgres.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, created.EnrollmentID, input.Code, phoneID); err != nil {
		t.Fatalf("reconfirmed phone could not be reviewed: %v", err)
	}
}

func TestHostConfirmationCannotRacePastDeviceRevocation(t *testing.T) {
	ctx, postgres, input, created := enrollmentPreviewFixture(t)
	owner := UserIdentity{Issuer: input.Issuer, Subject: input.Subject}
	phone := UserIdentity{Issuer: input.Issuer, Subject: "target-subject"}
	const phoneID = "66666666-6666-4666-8666-666666666666"
	const deviceID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	if _, err := postgres.ConfirmEnrollmentUser(ctx, phone, deviceID, "proof-jkt-target", created.EnrollmentID, input.Code); err != nil {
		t.Fatal(err)
	}
	revocation, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer revocation.Rollback()
	if _, err := revocation.ExecContext(ctx, `update devices set revoked_at=clock_timestamp() where id=$1`, deviceID); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := postgres.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, created.EnrollmentID, input.Code, phoneID)
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("host did not wait for the pending revocation: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	if err := revocation.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("host confirmation passed a committed device revocation")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("host confirmation did not finish after revocation")
	}
	var state string
	var grants int
	if err := postgres.DB.QueryRowContext(ctx, `select e.state,(select count(*) from runtime_grants g where g.runtime_id=e.runtime_id) from enrollments e where e.id=$1`, created.EnrollmentID).Scan(&state, &grants); err != nil || state != "user_confirmed" || grants != 0 {
		t.Fatalf("revocation race granted authority: state=%s grants=%d err=%v", state, grants, err)
	}
}

func TestEnrollmentConfirmationRejectsRevokedTargets(t *testing.T) {
	ctx, postgres, input, created := enrollmentPreviewFixture(t)
	owner := UserIdentity{Issuer: input.Issuer, Subject: input.Subject}
	phone := UserIdentity{Issuer: input.Issuer, Subject: "target-subject"}
	const phoneID = "66666666-6666-4666-8666-666666666666"
	const deviceID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	if _, err := postgres.DB.ExecContext(ctx, `update runtimes set revoked_at=clock_timestamp() where id=$1`, created.RuntimeID); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.ConfirmEnrollmentUser(ctx, phone, deviceID, "proof-jkt-target", created.EnrollmentID, input.Code); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("phone confirmed a revoked runtime: %v", err)
	}
	if _, err := postgres.DB.ExecContext(ctx, `update runtimes set revoked_at=null where id=$1`, created.RuntimeID); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.ConfirmEnrollmentUser(ctx, phone, deviceID, "proof-jkt-target", created.EnrollmentID, input.Code); err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct{ name, revoke, restore, id string }{
		{"host", `update hosts set state='revoked' where id=$1`, `update hosts set state='pending' where id=$1`, created.HostID},
		{"installation", `update installations set revoked_at=clock_timestamp() where id=$1`, `update installations set revoked_at=null where id=$1`, created.InstallationID},
		{"runtime", `update runtimes set revoked_at=clock_timestamp() where id=$1`, `update runtimes set revoked_at=null where id=$1`, created.RuntimeID},
	} {
		t.Run(target.name, func(t *testing.T) {
			if _, err := postgres.DB.ExecContext(ctx, target.revoke, target.id); err != nil {
				t.Fatal(err)
			}
			info, err := postgres.GetEnrollment(ctx, owner, created.EnrollmentID)
			if err != nil || info.HostReviewUser == nil || info.HostReviewUser.Eligible {
				t.Fatalf("revoked target remained eligible: %+v %v", info.HostReviewUser, err)
			}
			if _, err := postgres.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, created.EnrollmentID, input.Code, phoneID); !errors.Is(err, ErrAccessDenied) {
				t.Fatalf("revoked target received a grant: %v", err)
			}
			if _, err := postgres.DB.ExecContext(ctx, target.restore, target.id); err != nil {
				t.Fatal(err)
			}
		})
	}
	approved, err := postgres.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, created.EnrollmentID, input.Code, phoneID)
	if err != nil || approved.State != "approved" {
		t.Fatalf("active enrollment did not complete: %+v %v", approved, err)
	}
}

func TestEnrollmentDeviceMigrationPreventsDestructiveRollback(t *testing.T) {
	ctx, postgres, input, created := enrollmentPreviewFixture(t)
	down, err := os.ReadFile("../../../../deploy/sql/031_enrollment_confirmation_device.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, err := os.ReadFile("../../../../deploy/sql/031_enrollment_confirmation_device.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.DB.ExecContext(ctx, string(down)); err != nil {
		t.Fatalf("empty migration rollback failed: %v", err)
	}
	if _, err := postgres.DB.ExecContext(ctx, string(up)); err != nil {
		t.Fatalf("migration reapply failed: %v", err)
	}
	phone := UserIdentity{Issuer: input.Issuer, Subject: "target-subject"}
	if _, err := postgres.ConfirmEnrollmentUser(ctx, phone, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "proof-jkt-target", created.EnrollmentID, input.Code); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.DB.ExecContext(ctx, string(down)); err == nil || !strings.Contains(err.Error(), "enrollment device confirmations prevent destructive rollback") {
		t.Fatalf("rollback discarded confirmed device provenance: %v", err)
	}
}

func TestExpiredSiblingEnrollmentKeepsAnApprovedProfileAndInstallation(t *testing.T) {
	ctx, postgres, input, first := enrollmentPreviewFixture(t)
	owner := UserIdentity{Issuer: input.Issuer, Subject: input.Subject}
	phone := UserIdentity{Issuer: input.Issuer, Subject: "target-subject"}
	if _, err := postgres.ConfirmEnrollmentUser(ctx, phone, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "proof-jkt-target", first.EnrollmentID, input.Code); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, first.EnrollmentID, input.Code, "66666666-6666-4666-8666-666666666666"); err != nil {
		t.Fatal(err)
	}
	input.RequestID = "aaaaaaaa-2222-4222-8222-222222222222"
	input.ProfileRef = "sibling"
	input.Code = validEnrollmentInput(t).Code
	second, err := postgres.CreateEnrollment(ctx, input)
	if err != nil || second.InstallationID != first.InstallationID {
		t.Fatalf("sibling creation: %+v %v", second, err)
	}
	if _, err := postgres.DB.ExecContext(ctx, `update enrollments set created_at=clock_timestamp()-interval '10 minutes',expires_at=clock_timestamp()-interval '1 second' where id=$1`, second.EnrollmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.ConfirmEnrollmentUser(ctx, phone, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "proof-jkt-target", second.EnrollmentID, input.Code); !errors.Is(err, ErrEnrollmentInvalid) {
		t.Fatalf("expired sibling confirmation: %v", err)
	}
	var host string
	var installationRevoked, firstRevoked, secondRevoked bool
	if err := postgres.DB.QueryRowContext(ctx, `select h.state,i.revoked_at is not null,r1.revoked_at is not null,r2.revoked_at is not null from hosts h join installations i on i.host_id=h.id join runtimes r1 on r1.installation_id=i.id join runtimes r2 on r2.installation_id=i.id where r1.id=$1 and r2.id=$2`, first.RuntimeID, second.RuntimeID).Scan(&host, &installationRevoked, &firstRevoked, &secondRevoked); err != nil {
		t.Fatal(err)
	}
	if host != "active" || installationRevoked || firstRevoked || !secondRevoked {
		t.Fatalf("sibling expiry crossed profile: host=%s installation=%t first=%t second=%t", host, installationRevoked, firstRevoked, secondRevoked)
	}
	if _, err := postgres.CreateHostCredentialChallenge(ctx, owner, input.InstallationKeyThumbprint); err != nil {
		t.Fatalf("surviving installation cannot reconnect: %v", err)
	}
}

func TestExpiredPendingProfileDoesNotPreventItsSiblingFromBinding(t *testing.T) {
	ctx, postgres, input, first := enrollmentPreviewFixture(t)
	owner := UserIdentity{Issuer: input.Issuer, Subject: input.Subject}
	firstCode := input.Code
	input.RequestID = "aaaaaaaa-2222-4222-8222-222222222222"
	input.ProfileRef = "pending-sibling"
	input.Code = validEnrollmentInput(t).Code
	second, err := postgres.CreateEnrollment(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.DB.ExecContext(ctx, `update enrollments set created_at=clock_timestamp()-interval '10 minutes',expires_at=clock_timestamp()-interval '1 second' where id=$1`, first.EnrollmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, first.EnrollmentID, firstCode, "66666666-6666-4666-8666-666666666666"); !errors.Is(err, ErrEnrollmentInvalid) {
		t.Fatalf("expire first pending: %v", err)
	}
	if _, err := postgres.ConfirmEnrollmentUser(ctx, UserIdentity{Issuer: input.Issuer, Subject: "target-subject"}, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "proof-jkt-target", second.EnrollmentID, input.Code); err != nil {
		t.Fatal(err)
	}
	result, err := postgres.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, second.EnrollmentID, input.Code, "66666666-6666-4666-8666-666666666666")
	if err != nil || result.State != "approved" {
		t.Fatalf("pending sibling could not finish: %+v %v", result, err)
	}
}

func TestLastPendingEnrollmentExpiryClosesOnlyItsOwnResources(t *testing.T) {
	ctx, postgres, input, created := enrollmentPreviewFixture(t)
	if _, err := postgres.DB.ExecContext(ctx, `update enrollments set created_at=clock_timestamp()-interval '10 minutes',expires_at=clock_timestamp()-interval '1 second' where id=$1`, created.EnrollmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.PreviewEnrollment(ctx, UserIdentity{Issuer: input.Issuer, Subject: "target-subject"}, created.EnrollmentID, input.Code); !errors.Is(err, ErrEnrollmentInvalid) {
		t.Fatalf("expired code disclosed metadata: %v", err)
	}
	if info, err := postgres.GetEnrollment(ctx, UserIdentity{Issuer: input.Issuer, Subject: input.Subject}, created.EnrollmentID); err != nil || info.State != "expired" {
		t.Fatalf("initiator cannot reconcile expired state: %+v %v", info, err)
	}
	if _, err := postgres.ConfirmEnrollmentHost(ctx, UserIdentity{Issuer: input.Issuer, Subject: input.Subject}, input.InstallationKeyThumbprint, created.EnrollmentID, input.Code, "66666666-6666-4666-8666-666666666666"); !errors.Is(err, ErrEnrollmentInvalid) {
		t.Fatalf("expired confirmation: %v", err)
	}
	var state string
	var installationRevoked, runtimeRevoked bool
	if err := postgres.DB.QueryRowContext(ctx, `select h.state,i.revoked_at is not null,r.revoked_at is not null from hosts h join installations i on i.host_id=h.id join runtimes r on r.installation_id=i.id where r.id=$1`, created.RuntimeID).Scan(&state, &installationRevoked, &runtimeRevoked); err != nil {
		t.Fatal(err)
	}
	if state != "revoked" || !installationRevoked || !runtimeRevoked {
		t.Fatalf("expired private resources remained active: host=%s installation=%t runtime=%t", state, installationRevoked, runtimeRevoked)
	}
	var unaffected string
	if err := postgres.DB.QueryRowContext(ctx, `select state from hosts where id='11111111-1111-4111-8111-111111111111'`).Scan(&unaffected); err != nil || unaffected != "active" {
		t.Fatalf("unrelated installation changed: %s %v", unaffected, err)
	}
}
