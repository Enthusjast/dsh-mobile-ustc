package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func resourceDirectoryFixture(t *testing.T) (context.Context, *Postgres, string) {
	t.Helper()
	ctx, db, proof := installationManagementFixture(t)
	_, err := db.DB.ExecContext(ctx, `insert into hosts(id,org_id,alias,state) values
	 ('88888888-1111-4111-8111-111111111111','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','Other authorized host','active');
	 insert into installations(id,host_id,owner_user_id,public_jwk,public_key_thumbprint) values
	 ('88888888-2222-4222-8222-222222222222','88888888-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222','{}','directory-extra-key');
	 insert into runtimes(id,installation_id,profile_ref) values
	 ('88888888-3333-4333-8333-333333333333','88888888-2222-4222-8222-222222222222','PRIVATE_EXTRA_PROFILE'),
	 ('abababab-3333-4333-8333-abababababab','abababab-abab-4bab-8bab-abababababab','PRIVATE_FOREIGN_PROFILE');
	 insert into runtime_grants(runtime_id,user_id,role,scope,granted_by) values
	 ('88888888-3333-4333-8333-333333333333','22222222-2222-4222-8222-222222222222','viewer','{"actions":["host.list"],"workspaces":[],"sessions":[]}','22222222-2222-4222-8222-222222222222'),
	 ('abababab-3333-4333-8333-abababababab','22222222-2222-4222-8222-222222222222','viewer','{"actions":["host.list"],"workspaces":[],"sessions":[]}','22222222-2222-4222-8222-222222222222')`)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, db, proof
}

func TestResourceDirectoriesPageVisibleUUIDsAndDeduplicateHosts(t *testing.T) {
	ctx, db, proof := resourceDirectoryFixture(t)
	actor := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	hosts, err := db.HostDirectory(ctx, actor, managingDevice, proof, 1, "")
	if err != nil || len(hosts.Items) != 1 || hosts.NextCursor == nil || hosts.Items[0].ID != "11111111-1111-4111-8111-111111111111" {
		t.Fatal("host directory not paged", hosts, err)
	}
	firstHosts := hosts
	if _, err := db.DB.ExecContext(ctx, `update hosts set alias='ZZZ renamed host' where id='11111111-1111-4111-8111-111111111111'`); err != nil {
		t.Fatal(err)
	}
	hosts, err = db.HostDirectory(ctx, actor, managingDevice, proof, 1, *hosts.NextCursor)
	if err != nil || len(hosts.Items) != 1 || hosts.Items[0].ID != "88888888-1111-4111-8111-111111111111" || hosts.NextCursor != nil {
		t.Fatal("alias changes repeated or skipped a host", hosts, err)
	}
	runtimes, err := db.RuntimeDirectory(ctx, actor, managingDevice, proof, 1, "")
	if err != nil || len(runtimes.Items) != 1 || runtimes.NextCursor == nil || runtimes.Items[0].ID != directoryRuntime {
		t.Fatal("runtime directory not paged", runtimes, err)
	}
	firstRuntimes := runtimes
	ids := []string{runtimes.Items[0].ID}
	for runtimes.NextCursor != nil {
		runtimes, err = db.RuntimeDirectory(ctx, actor, managingDevice, proof, 1, *runtimes.NextCursor)
		if err != nil || len(runtimes.Items) != 1 || len(ids) > 10 {
			t.Fatal("invalid runtime page", runtimes, err)
		}
		ids = append(ids, runtimes.Items[0].ID)
	}
	if !reflect.DeepEqual(ids, []string{directoryRuntime, "88888888-3333-4333-8333-333333333333", secondProfile}) {
		t.Fatal("directory leaked foreign membership or omitted a visible profile", ids)
	}
	legacy, err := db.ListRuntimes(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	legacyIDs := []string{}
	for _, item := range legacy {
		legacyIDs = append(legacyIDs, item.ID)
	}
	sort.Strings(legacyIDs)
	if !reflect.DeepEqual(ids, legacyIDs) {
		t.Fatal("legacy and paged visibility policies differ", ids, legacyIDs)
	}
	all, err := db.RuntimeDirectory(ctx, actor, managingDevice, proof, 100, "")
	if err != nil || all.Items[0].Access == nil || all.Items[0].Access.Role != "owner" || all.Items[0].Access.GrantVersion != 1 {
		t.Fatal("current grant metadata lost", all, err)
	}
	raw, _ := json.Marshal(all)
	for _, private := range []string{"PRIVATE_", "profile_ref", "public_jwk", "owner-subject", "connection_id", "workspace-test"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("directory exported native identity or credentials")
		}
	}
	if _, err := db.DB.ExecContext(ctx, `update runtime_grants set scope='{"actions":["session.read"],"workspaces":[],"sessions":[]}',grant_version=2 where runtime_id='88888888-3333-4333-8333-333333333333'`); err != nil {
		t.Fatal(err)
	}
	hidden, err := db.HostDirectory(ctx, actor, managingDevice, proof, 100, *firstHosts.NextCursor)
	if err != nil || len(hidden.Items) != 0 {
		t.Fatal("old host cursor preserved withdrawn enumeration", hidden, err)
	}
	narrowed, err := db.RuntimeDirectory(ctx, actor, managingDevice, proof, 100, *firstRuntimes.NextCursor)
	if err != nil || len(narrowed.Items) != 1 || narrowed.Items[0].ID != secondProfile {
		t.Fatal("old runtime cursor retained prior actions", narrowed, err)
	}
}

func TestResourceDirectoriesRecheckActorAndCurrentMembershipGrantAndProfile(t *testing.T) {
	ctx, db, proof := resourceDirectoryFixture(t)
	actor := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	hosts, _ := db.HostDirectory(ctx, actor, managingDevice, proof, 1, "")
	runtimes, _ := db.RuntimeDirectory(ctx, actor, managingDevice, proof, 1, "")
	if hosts.NextCursor == nil || runtimes.NextCursor == nil {
		t.Fatal("fixture must have both continuation cursors")
	}
	for _, change := range []struct {
		name, mutate, restore string
		denyActor             bool
	}{
		{"device", `update devices set revoked_at=clock_timestamp()`, `update devices set revoked_at=null`, true},
		{"account", `update users set status='suspended'`, `update users set status='active'`, true},
		{"grant", `update runtime_grants set revoked_at=clock_timestamp()`, `update runtime_grants set revoked_at=null`, false},
		{"expiry", `update runtime_grants set expires_at=clock_timestamp()-interval '1 second'`, `update runtime_grants set expires_at=null`, false},
		{"runtime", `update runtimes set revoked_at=clock_timestamp()`, `update runtimes set revoked_at=null`, false},
		{"installation", `update installations set revoked_at=clock_timestamp()`, `update installations set revoked_at=null`, false},
		{"host", `update hosts set state='revoked'`, `update hosts set state='active'`, false},
		{"membership", `delete from org_memberships where user_id='22222222-2222-4222-8222-222222222222'`, `insert into org_memberships(org_id,user_id,role) values('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','22222222-2222-4222-8222-222222222222','member')`, false},
	} {
		t.Run(change.name, func(t *testing.T) {
			if _, err := db.DB.ExecContext(ctx, change.mutate); err != nil {
				t.Fatal(err)
			}
			for _, continued := range []bool{false, true} {
				hostCursor, runtimeCursor := "", ""
				if continued {
					hostCursor, runtimeCursor = *hosts.NextCursor, *runtimes.NextCursor
				}
				hostPage, hostErr := db.HostDirectory(ctx, actor, managingDevice, proof, 100, hostCursor)
				runtimePage, runtimeErr := db.RuntimeDirectory(ctx, actor, managingDevice, proof, 100, runtimeCursor)
				if change.denyActor {
					if !errors.Is(hostErr, ErrAccessDenied) || !errors.Is(runtimeErr, ErrAccessDenied) {
						t.Fatal("lost actor remained authorized", hostErr, runtimeErr)
					}
				} else if hostErr != nil || runtimeErr != nil || len(hostPage.Items) != 0 || len(runtimePage.Items) != 0 {
					t.Fatal("directory retained withdrawn visibility", hostPage, runtimePage, hostErr, runtimeErr)
				}
			}
			if _, err := db.DB.ExecContext(ctx, change.restore); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, err := db.HostDirectory(ctx, actor, managingDevice, proof, 1, *runtimes.NextCursor); !errors.Is(err, ErrResourceDirectoryInvalid) {
		t.Fatal("runtime cursor was usable for hosts", err)
	}
	if _, err := db.RuntimeDirectory(ctx, actor, managingDevice, strings.Repeat("A", 43), 1, *runtimes.NextCursor); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("another proof key reused runtime cursor", err)
	}
	cursor, _ := parseResourceDirectoryCursor(*runtimes.NextCursor, "runtime-directory-v1")
	cursor.UserID = directoryTarget
	raw, _ := json.Marshal(cursor)
	if _, err := db.RuntimeDirectory(ctx, actor, managingDevice, proof, 1, base64.RawURLEncoding.EncodeToString(raw)); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("cursor selected another user", err)
	}
}

func TestResourceDirectoryActionsAndEmptyAccountDoNotInheritAccess(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	proof := seedGrantFixture(t, ctx, db.DB)
	actor := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	for _, variant := range []struct {
		scope   string
		visible int
	}{
		{`{"actions":["session.read","grant.manage"],"workspaces":["77777777-7777-4777-8777-777777777777"],"sessions":[]}`, 0},
		{`{"actions":["session.list","grant.manage"],"workspaces":["77777777-7777-4777-8777-777777777777"],"sessions":[]}`, 1},
		{`{"actions":["session.list","grant.manage"],"workspaces":[],"sessions":[]}`, 0},
		{`{"actions":["host.list","grant.manage"],"workspaces":[],"sessions":[]}`, 1},
	} {
		if _, err := db.DB.ExecContext(ctx, `update runtime_grants set scope=$1`, variant.scope); err != nil {
			t.Fatal(err)
		}
		hosts, hostErr := db.HostDirectory(ctx, actor, managingDevice, proof, 50, "")
		runtimes, runtimeErr := db.RuntimeDirectory(ctx, actor, managingDevice, proof, 50, "")
		if hostErr != nil || runtimeErr != nil || len(hosts.Items) != variant.visible || len(runtimes.Items) != variant.visible {
			t.Fatal("directory action implied unexpected visibility", hosts, runtimes, hostErr, runtimeErr)
		}
	}
	if _, err := db.DB.ExecContext(ctx, `delete from runtime_grants;update org_memberships set role='admin'`); err != nil {
		t.Fatal(err)
	}
	hosts, hostErr := db.HostDirectory(ctx, actor, managingDevice, proof, 50, "")
	runtimes, runtimeErr := db.RuntimeDirectory(ctx, actor, managingDevice, proof, 50, "")
	if hostErr != nil || runtimeErr != nil || len(hosts.Items) != 0 || len(runtimes.Items) != 0 {
		t.Fatal("admin/installation ownership enumerated without a runtime grant", hostErr, runtimeErr)
	}
}
