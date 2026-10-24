package store

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestAccountIdentityUsesActiveIssuerSubjectAndCurrentMemberships(t *testing.T) {
	ctx, postgres := newPostgresIntegrationDatabase(t)
	const (
		issuer    = "https://id.example.edu"
		userID    = "11111111-1111-4111-8111-111111111111"
		otherUser = "22222222-2222-4222-8222-222222222222"
		orgID     = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		otherOrg  = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	)
	if _, err := postgres.DB.ExecContext(ctx, `
		insert into users (id, issuer, subject) values
		($1, $3, 'opaque-school-subject'), ($2, 'https://another.example.edu', 'opaque-school-subject')`, userID, otherUser, issuer); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.DB.ExecContext(ctx, `insert into orgs (id, slug, name) values ($1, 'school', 'School'), ($2, 'other', 'Other')`, orgID, otherOrg); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.DB.ExecContext(ctx, `insert into org_memberships (org_id, user_id, role) values ($1, $3, 'member'), ($2, $4, 'admin')`, orgID, otherOrg, userID, otherUser); err != nil {
		t.Fatal(err)
	}
	identity := UserIdentity{Issuer: issuer, Subject: "opaque-school-subject"}
	account, err := postgres.AccountIdentity(ctx, identity)
	if err != nil || account.UserID != userID || !reflect.DeepEqual(account.Memberships, []OrganizationMembership{{OrganizationID: orgID, Role: "member"}}) {
		t.Fatalf("account mapping = %#v, %v", account, err)
	}
	other, err := postgres.AccountIdentity(ctx, UserIdentity{Issuer: "https://another.example.edu", Subject: identity.Subject})
	if err != nil || other.UserID != otherUser || !reflect.DeepEqual(other.Memberships, []OrganizationMembership{{OrganizationID: otherOrg, Role: "admin"}}) {
		t.Fatalf("same subject crossed issuer boundary: %#v, %v", other, err)
	}
	for _, absent := range []UserIdentity{{Issuer: issuer, Subject: "unknown"}, {Issuer: "https://absent.example.edu", Subject: identity.Subject}, {Issuer: issuer, Subject: userID}} {
		if _, err := postgres.AccountIdentity(ctx, absent); !errors.Is(err, ErrIdentityNotProvisioned) {
			t.Fatalf("absent identity resolved: %v", err)
		}
	}
	if _, err := postgres.DB.ExecContext(ctx, `insert into org_memberships (org_id, user_id, role) values ($1, $2, 'admin')`, otherOrg, userID); err != nil {
		t.Fatal(err)
	}
	updated, err := postgres.AccountIdentity(ctx, identity)
	if err != nil || len(updated.Memberships) != 2 || updated.Memberships[1].Role != "admin" {
		t.Fatalf("new membership missing: %#v, %v", updated, err)
	}
	if _, err := postgres.DB.ExecContext(ctx, `delete from org_memberships where user_id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	empty, err := postgres.AccountIdentity(ctx, identity)
	encoded, marshalErr := json.Marshal(empty)
	if err != nil || marshalErr != nil || empty.UserID != userID || len(empty.Memberships) != 0 || !strings.Contains(string(encoded), `"memberships":[]`) {
		t.Fatalf("removed memberships persisted or empty account was lost: %#v, %v, %v", empty, err, marshalErr)
	}
	for _, status := range []string{"suspended", "deleted"} {
		if _, err := postgres.DB.ExecContext(ctx, `update users set status = $1 where id = $2`, status, userID); err != nil {
			t.Fatal(err)
		}
		if _, err := postgres.AccountIdentity(ctx, identity); !errors.Is(err, ErrIdentityNotProvisioned) {
			t.Fatalf("inactive user resolved: %v", err)
		}
	}
	var users, devices, grants int
	if err := postgres.DB.QueryRowContext(ctx, `select (select count(*) from users), (select count(*) from devices), (select count(*) from runtime_grants)`).Scan(&users, &devices, &grants); err != nil || users != 2 || devices != 0 || grants != 0 {
		t.Fatalf("identity reads provisioned authority: users=%d devices=%d grants=%d err=%v", users, devices, grants, err)
	}
	if err := postgres.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.AccountIdentity(ctx, identity); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatalf("database outage accepted: %v", err)
	}
}
