package store

import (
	"errors"
	"testing"
	"time"
)

func TestAppReleaseAccessBindsCurrentAccountOrganizationAndDeviceWithoutRuntimeGrants(t *testing.T) {
	ctx, database := newPostgresIntegrationDatabase(t)
	proof := seedGrantFixture(t, ctx, database.DB)
	identity := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	const device = "44444444-4444-4444-8444-444444444444"
	const organization = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	until := time.Now().Add(time.Minute)
	if _, err := database.DB.ExecContext(ctx, `delete from runtime_grants`); err != nil {
		t.Fatal(err)
	}
	read := func() (string, error) {
		return database.AppReleaseAccess(ctx, identity, device, proof, organization, until)
	}
	user, err := read()
	if err != nil || user != "22222222-2222-4222-8222-222222222222" {
		t.Fatal("update lookup incorrectly required a runtime grant", err)
	}
	for _, test := range []struct {
		identity                    UserIdentity
		device, proof, organization string
		until                       time.Time
	}{
		{UserIdentity{Issuer: identity.Issuer, Subject: "outsider-subject"}, device, proof, organization, until},
		{identity, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", proof, organization, until},
		{identity, device, "another-proof", organization, until},
		{identity, device, proof, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", until},
		{identity, device, proof, organization, time.Now().Add(-time.Second)},
	} {
		if _, err := database.AppReleaseAccess(ctx, test.identity, test.device, test.proof, test.organization, test.until); !errors.Is(err, ErrAccessDenied) {
			t.Fatal("release actor crossed an identity boundary", err)
		}
	}
	for _, mutation := range []string{
		`update users set status='suspended'`,
		`update users set status='active'; update devices set revoked_at=clock_timestamp()`,
		`update devices set revoked_at=null; delete from org_memberships`,
	} {
		if _, err := database.DB.ExecContext(ctx, mutation); err != nil {
			t.Fatal(err)
		}
		if _, err := read(); !errors.Is(err, ErrAccessDenied) {
			t.Fatal("revoked release actor remained eligible", err)
		}
	}
}
