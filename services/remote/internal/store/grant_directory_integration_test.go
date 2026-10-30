package store

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const directoryRuntime = "55555555-5555-4555-8555-555555555555"
const directoryOwner = "22222222-2222-4222-8222-222222222222"
const directoryTarget = "66666666-6666-4666-8666-666666666666"

func TestRuntimeGrantDirectoryPaginatesRecordedGrantsAndCurrentRecipientState(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	proof := seedGrantFixture(t, ctx, db.DB)
	identity := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	input := RuntimeGrantInput{Role: "viewer", Scope: GrantScope{Actions: []string{"host.list"}, Workspaces: []string{}, Sessions: []string{}}}
	if _, err := db.PutRuntimeGrant(ctx, identity, managingDevice, proof, directoryRuntime, directoryTarget, input); err != nil {
		t.Fatal(err)
	}
	first, err := db.ListRuntimeGrants(ctx, identity, managingDevice, proof, directoryRuntime, 1, "")
	if err != nil || len(first.Items) != 1 || first.Items[0].UserID != directoryOwner || first.NextCursor == nil || first.RuntimeID != directoryRuntime {
		t.Fatal("manager could not page its runtime grants", first, err)
	}
	if _, err := db.DB.ExecContext(ctx, `update runtime_grants set expires_at=clock_timestamp()-interval '1 second' where user_id=$1`, directoryTarget); err != nil {
		t.Fatal(err)
	}
	second, err := db.ListRuntimeGrants(ctx, identity, managingDevice, proof, directoryRuntime, 1, *first.NextCursor)
	if err != nil || len(second.Items) != 1 || second.Items[0].UserID != directoryTarget || second.Items[0].State != "expired" || second.Items[0].Version != 1 || second.Items[0].GrantedBy != directoryOwner || second.NextCursor != nil {
		t.Fatal("page did not reflect the current expired grant", second, err)
	}
	if _, err := db.RevokeRuntimeGrant(ctx, identity, managingDevice, proof, directoryRuntime, directoryTarget); err != nil {
		t.Fatal(err)
	}
	second, err = db.ListRuntimeGrants(ctx, identity, managingDevice, proof, directoryRuntime, 100, *first.NextCursor)
	if err != nil || second.Items[0].State != "revoked" || second.Items[0].Version != 2 || second.Items[0].RevokedAt == nil {
		t.Fatal("revoked grant or version disappeared", second, err)
	}
	for _, query := range []string{`update runtime_grants set revoked_at=null,expires_at=null where user_id=$1`, `update users set status='suspended' where id=$1`} {
		if _, err := db.DB.ExecContext(ctx, query, directoryTarget); err != nil {
			t.Fatal(err)
		}
	}
	second, err = db.ListRuntimeGrants(ctx, identity, managingDevice, proof, directoryRuntime, 100, *first.NextCursor)
	if err != nil || second.Items[0].State != "inactive" {
		t.Fatal("suspended recipient appeared active", err)
	}
	for _, query := range []string{`update users set status='active' where id=$1`, `delete from org_memberships where user_id=$1`} {
		if _, err := db.DB.ExecContext(ctx, query, directoryTarget); err != nil {
			t.Fatal(err)
		}
	}
	second, err = db.ListRuntimeGrants(ctx, identity, managingDevice, proof, directoryRuntime, 100, *first.NextCursor)
	if err != nil || second.Items[0].State != "inactive" {
		t.Fatal("former member appeared active", err)
	}
	raw, _ := json.Marshal(first)
	for _, forbidden := range []string{"owner-subject", "issuer", "public_jwk", "thumbprint", "workspace-test", "opaque-dsh-session"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("directory exported private identity or local references")
		}
	}
}

func TestRuntimeGrantDirectoryRechecksManagerAuthorityAndProofOnEveryPage(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	proof := seedGrantFixture(t, ctx, db.DB)
	identity := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	if _, err := db.PutRuntimeGrant(ctx, identity, managingDevice, proof, directoryRuntime, directoryTarget, RuntimeGrantInput{Role: "viewer", Scope: GrantScope{Actions: []string{"host.list"}, Workspaces: []string{}, Sessions: []string{}}}); err != nil {
		t.Fatal(err)
	}
	first, err := db.ListRuntimeGrants(ctx, identity, managingDevice, proof, directoryRuntime, 1, "")
	if err != nil || first.NextCursor == nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct{ name, change, restore string }{
		{"proof", `update devices set proof_key_thumbprint='stale' where id='44444444-4444-4444-8444-444444444444'`, `update devices set proof_key_thumbprint=$1 where id='44444444-4444-4444-8444-444444444444'`},
		{"device", `update devices set revoked_at=clock_timestamp()`, `update devices set revoked_at=null where proof_key_thumbprint=$1`},
		{"account", `update users set status='suspended' where id='22222222-2222-4222-8222-222222222222'`, `update users set status='active' where id='22222222-2222-4222-8222-222222222222'`},
		{"grant expiry", `update runtime_grants set expires_at=clock_timestamp()-interval '1 second'`, `update runtime_grants set expires_at=null`},
		{"grant revocation", `update runtime_grants set revoked_at=clock_timestamp()`, `update runtime_grants set revoked_at=null`},
		{"owner role", `update runtime_grants set role='operator'`, `update runtime_grants set role='owner' where user_id='22222222-2222-4222-8222-222222222222'`},
		{"manage action", `update runtime_grants set scope=jsonb_set(scope,'{actions}','["host.list"]') where user_id='22222222-2222-4222-8222-222222222222'`, `update runtime_grants set scope=jsonb_set(scope,'{actions}','["grant.manage","host.list"]') where user_id='22222222-2222-4222-8222-222222222222'`},
		{"membership", `delete from org_memberships where user_id='22222222-2222-4222-8222-222222222222'`, `insert into org_memberships(org_id,user_id,role) select 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','22222222-2222-4222-8222-222222222222','member'`},
		{"runtime", `update runtimes set revoked_at=clock_timestamp()`, `update runtimes set revoked_at=null`},
		{"installation", `update installations set revoked_at=clock_timestamp()`, `update installations set revoked_at=null`},
		{"host", `update hosts set state='revoked'`, `update hosts set state='active'`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			if _, err := db.DB.ExecContext(ctx, mutation.change); err != nil {
				t.Fatal(err)
			}
			for _, cursor := range []string{"", *first.NextCursor} {
				if _, err := db.ListRuntimeGrants(ctx, identity, managingDevice, proof, directoryRuntime, 1, cursor); !errors.Is(err, ErrAccessDenied) {
					t.Fatal("prior cursor preserved lost management authority", err)
				}
			}
			var restoreArgs []any
			if strings.Contains(mutation.restore, "$1") {
				restoreArgs = []any{proof}
			}
			if _, err := db.DB.ExecContext(ctx, mutation.restore, restoreArgs...); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, err := db.ListRuntimeGrants(ctx, identity, managingDevice, proof, secondProfile, 1, *first.NextCursor); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("cursor moved to another runtime", err)
	}
	if _, err := db.ListRuntimeGrants(ctx, identity, managingDevice, proof, secondProfile, 1, ""); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("missing runtime disclosed records", err)
	}
	var cursor grantDirectoryCursor
	raw, _ := base64.RawURLEncoding.DecodeString(*first.NextCursor)
	json.Unmarshal(raw, &cursor)
	cursor.UserID = directoryTarget
	raw, _ = json.Marshal(cursor)
	if _, err := db.ListRuntimeGrants(ctx, identity, managingDevice, proof, directoryRuntime, 1, base64.RawURLEncoding.EncodeToString(raw)); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("cursor bound to another actor accepted", err)
	}
}

func TestRuntimeGrantDirectoryAdminRequiresCurrentOrganization(t *testing.T) {
	ctx, db, proof := installationManagementFixture(t)
	identity := UserIdentity{Issuer: "https://id.example.edu", Subject: "target-subject"}
	device := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	targetProof := strings.Repeat("B", 43)
	if _, err := db.ListRuntimeGrants(ctx, identity, device, targetProof, directoryRuntime, 100, ""); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("ordinary member enumerated grants", err)
	}
	if _, err := db.DB.ExecContext(ctx, `update org_memberships set role='admin' where user_id=$1`, directoryTarget); err != nil {
		t.Fatal(err)
	}
	if page, err := db.ListRuntimeGrants(ctx, identity, device, targetProof, directoryRuntime, 100, ""); err != nil || len(page.Items) != 1 {
		t.Fatal("current admin without runtime grant could not list", page, err)
	}
	if _, err := db.ListRuntimeGrants(ctx, identity, device, targetProof, secondProfile, 100, ""); err != nil {
		t.Fatal("admin could not inspect another profile", err)
	}
	if _, err := db.DB.ExecContext(ctx, `insert into runtimes(id,installation_id,profile_ref) values('12121212-3434-4343-8343-121212121212','abababab-abab-4bab-8bab-abababababab','foreign-profile')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ListRuntimeGrants(ctx, identity, device, targetProof, "12121212-3434-4343-8343-121212121212", 100, ""); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("organization administrator enumerated another organization", err)
	}
	if _, err := db.DB.ExecContext(ctx, `update org_memberships set role='member' where user_id=$1`, directoryTarget); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ListRuntimeGrants(ctx, identity, device, targetProof, directoryRuntime, 100, ""); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("former administrator retained enumeration", err)
	}
	// Installation ownership does not authorize a profile with a viewer grant.
	if _, err := db.ListRuntimeGrants(ctx, UserIdentity{Issuer: identity.Issuer, Subject: "owner-subject"}, managingDevice, proof, secondProfile, 100, ""); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("installation owner bypassed grant management", err)
	}
}

func TestRuntimeGrantDirectoryRejectsUnapprovedProfileEvenForAdmin(t *testing.T) {
	ctx, db, input, created := pendingActiveHostFixture(t)
	if _, err := db.DB.ExecContext(ctx, `update org_memberships set role='admin' where user_id='22222222-2222-4222-8222-222222222222'`); err != nil {
		t.Fatal(err)
	}
	var proof string
	if err := db.DB.QueryRowContext(ctx, `select proof_key_thumbprint from devices where id=$1`, managingDevice).Scan(&proof); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ListRuntimeGrants(ctx, UserIdentity{Issuer: input.Issuer, Subject: input.Subject}, managingDevice, proof, created.RuntimeID, 100, ""); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("organization admin enumerated an unapproved profile", err)
	}
}
