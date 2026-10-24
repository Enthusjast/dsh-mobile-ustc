package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func pendingActiveHostFixture(t *testing.T) (context.Context, *Postgres, EnrollmentInput, EnrollmentCreated) {
	t.Helper()
	ctx, postgres := newPostgresIntegrationDatabase(t)
	seedGrantFixture(t, ctx, postgres.DB)
	input := validEnrollmentInput(t)
	input.Subject = "owner-subject"
	input.OrganizationID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	input.HostID = "11111111-1111-4111-8111-111111111111"
	input.Alias = "Test host"
	created, err := postgres.CreateEnrollment(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, postgres, input, created
}
func enrollmentConnection(created EnrollmentCreated) RuntimeConnectionInput {
	return RuntimeConnectionInput{InstallationID: created.InstallationID, KeyVersion: 1, RuntimeID: created.RuntimeID, RuntimeEpoch: "eeeeeeee-1111-4111-8111-111111111111", ConnectionID: "ffffffff-1111-4111-8111-111111111111", DSHVersion: "0.2.1-rc.2", ApplicationVersion: "fixture", PluginVersion: "fixture", ProtocolVersion: 1}
}

func TestAnActiveHostDoesNotActivateAnUnconfirmedInstallationOrGrant(t *testing.T) {
	ctx, postgres, input, created := pendingActiveHostFixture(t)
	owner := UserIdentity{Issuer: input.Issuer, Subject: input.Subject}
	if _, err := postgres.CreateHostCredentialChallenge(ctx, owner, input.InstallationKeyThumbprint); !errors.Is(err, ErrAccessDenied) {
		t.Errorf("unconfirmed installation received a challenge: %v", err)
	}
	if _, err := postgres.AttachRuntimeConnection(ctx, enrollmentConnection(created)); !errors.Is(err, ErrHostCredentialInvalid) {
		t.Errorf("unconfirmed profile attached: %v", err)
	}
	// Represent an unsafe grant left by an older server or manual provisioning.
	// It cannot turn a pending enrollment into an active profile.
	scope := GrantScope{Actions: []string{"grant.manage", "host.list", "session.list", "session.read"}, Workspaces: []string{created.Workspaces[0].ID}, Sessions: []string{}}
	bytes, _ := json.Marshal(scope)
	if _, err := postgres.DB.ExecContext(ctx, `insert into runtime_grants(runtime_id,user_id,role,scope,granted_by) values($1,'22222222-2222-4222-8222-222222222222','owner',$2::jsonb,'22222222-2222-4222-8222-222222222222')`, created.RuntimeID, string(bytes)); err != nil {
		t.Fatal(err)
	}
	runtimes, err := postgres.ListRuntimes(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	for _, runtime := range runtimes {
		if runtime.ID == created.RuntimeID {
			t.Error("unconfirmed profile appeared in directory")
		}
	}
	if _, err := postgres.IssueRealtimeTicket(ctx, owner, "44444444-4444-4444-8444-444444444444", created.RuntimeID, scope); !errors.Is(err, ErrAccessDenied) {
		t.Errorf("early grant issued a ticket: %v", err)
	}
	if _, err := postgres.PutRuntimeGrant(ctx, owner, "44444444-4444-4444-8444-444444444444", created.RuntimeID, "66666666-6666-4666-8666-666666666666", RuntimeGrantInput{Role: "viewer", Scope: GrantScope{Actions: []string{"host.list"}, Workspaces: scope.Workspaces, Sessions: []string{}}}); !errors.Is(err, ErrAccessDenied) {
		t.Errorf("early grant modified another grant: %v", err)
	}
	if _, err := postgres.DB.ExecContext(ctx, `delete from runtime_grants where runtime_id=$1`, created.RuntimeID); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.ConfirmEnrollmentUser(ctx, UserIdentity{Issuer: input.Issuer, Subject: "target-subject"}, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", created.EnrollmentID, input.Code); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.AttachRuntimeConnection(ctx, enrollmentConnection(created)); !errors.Is(err, ErrHostCredentialInvalid) {
		t.Errorf("phone-only confirmation attached: %v", err)
	}
	if _, err := postgres.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, created.EnrollmentID, input.Code); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.CreateHostCredentialChallenge(ctx, owner, input.InstallationKeyThumbprint); err != nil {
		t.Fatalf("confirmed installation cannot acquire credential: %v", err)
	}
	if _, err := postgres.AttachRuntimeConnection(ctx, enrollmentConnection(created)); err != nil {
		t.Fatalf("confirmed profile cannot attach: %v", err)
	}
}

func TestSharedInstallationCannotAttachItsPendingSiblingAndLeasesRecheckEnrollment(t *testing.T) {
	ctx, postgres, input, first := pendingActiveHostFixture(t)
	owner := UserIdentity{Issuer: input.Issuer, Subject: input.Subject}
	if _, err := postgres.ConfirmEnrollmentUser(ctx, owner, "44444444-4444-4444-8444-444444444444", first.EnrollmentID, input.Code); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, first.EnrollmentID, input.Code); err != nil {
		t.Fatal(err)
	}
	connection := enrollmentConnection(first)
	if _, err := postgres.AttachRuntimeConnection(ctx, connection); err != nil {
		t.Fatal(err)
	}
	input.RequestID = "aaaaaaaa-2222-4222-8222-222222222222"
	input.ProfileRef = "pending-sibling"
	input.Code = validEnrollmentInput(t).Code
	second, err := postgres.CreateEnrollment(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.CreateHostCredentialChallenge(ctx, owner, input.InstallationKeyThumbprint); err != nil {
		t.Fatalf("pending sibling blocked approved installation: %v", err)
	}
	if _, err := postgres.AttachRuntimeConnection(ctx, enrollmentConnection(second)); !errors.Is(err, ErrHostCredentialInvalid) {
		t.Fatalf("pending sibling attached through existing key: %v", err)
	}
	lease := RealtimeConnectionLease{Role: "installation", InstallationID: &first.InstallationID, RuntimeID: first.RuntimeID, RuntimeEpoch: &connection.RuntimeEpoch, ConnectionID: connection.ConnectionID, KeyVersion: 1}
	invalid, err := postgres.InvalidRealtimeConnectionLeases(ctx, []RealtimeConnectionLease{lease})
	if err != nil || len(invalid) != 0 {
		t.Fatalf("approved lease rejected: %v %v", invalid, err)
	}
	if _, err := postgres.DB.ExecContext(ctx, `update enrollments set state='denied' where id=$1`, first.EnrollmentID); err != nil {
		t.Fatal(err)
	}
	invalid, err = postgres.InvalidRealtimeConnectionLeases(ctx, []RealtimeConnectionLease{lease})
	if err != nil || len(invalid) != 1 {
		t.Fatalf("lease ignored changed enrollment: %v %v", invalid, err)
	}
	if err := postgres.TouchRuntimeConnection(ctx, first.InstallationID, first.RuntimeID, connection.RuntimeEpoch, connection.ConnectionID); !errors.Is(err, ErrRuntimeConnectionStale) {
		t.Fatalf("denied profile refreshed connection: %v", err)
	}
	if _, err := postgres.CreateHostCredentialChallenge(ctx, owner, input.InstallationKeyThumbprint); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("only denied/pending profiles acquired credential: %v", err)
	}
}
