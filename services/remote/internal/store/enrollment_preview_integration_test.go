package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
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
	if _, err := postgres.ConfirmEnrollmentUser(ctx, phone, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", created.EnrollmentID, input.Code); err != nil {
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
	for _, approved := range []bool{false, true} {
		if approved {
			if _, err := postgres.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, created.EnrollmentID, input.Code); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := postgres.ConfirmEnrollmentUser(ctx, owner, "44444444-4444-4444-8444-444444444444", created.EnrollmentID, input.Code); !errors.Is(err, ErrEnrollmentInvalid) {
			t.Fatalf("another phone account claimed confirmed=%t: %v", approved, err)
		}
	}
}

func TestExpiredSiblingEnrollmentKeepsAnApprovedProfileAndInstallation(t *testing.T) {
	ctx, postgres, input, first := enrollmentPreviewFixture(t)
	owner := UserIdentity{Issuer: input.Issuer, Subject: input.Subject}
	phone := UserIdentity{Issuer: input.Issuer, Subject: "target-subject"}
	if _, err := postgres.ConfirmEnrollmentUser(ctx, phone, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", first.EnrollmentID, input.Code); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, first.EnrollmentID, input.Code); err != nil {
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
	if _, err := postgres.ConfirmEnrollmentUser(ctx, phone, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", second.EnrollmentID, input.Code); !errors.Is(err, ErrEnrollmentInvalid) {
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
	if _, err := postgres.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, first.EnrollmentID, firstCode); !errors.Is(err, ErrEnrollmentInvalid) {
		t.Fatalf("expire first pending: %v", err)
	}
	if _, err := postgres.ConfirmEnrollmentUser(ctx, UserIdentity{Issuer: input.Issuer, Subject: "target-subject"}, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", second.EnrollmentID, input.Code); err != nil {
		t.Fatal(err)
	}
	result, err := postgres.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, second.EnrollmentID, input.Code)
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
	if _, err := postgres.ConfirmEnrollmentHost(ctx, UserIdentity{Issuer: input.Issuer, Subject: input.Subject}, input.InstallationKeyThumbprint, created.EnrollmentID, input.Code); !errors.Is(err, ErrEnrollmentInvalid) {
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
