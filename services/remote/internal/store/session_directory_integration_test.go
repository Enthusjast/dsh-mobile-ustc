package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func sessionDirectoryFixture(t *testing.T) (context.Context, *Postgres, string) {
	t.Helper()
	ctx, db, proof := installationManagementFixture(t)
	_, err := db.DB.ExecContext(ctx, `insert into workspaces(id,runtime_id,workspace_ref) values
	 ('88888888-7777-4777-8777-777777777777','55555555-5555-4555-8555-555555555555','PRIVATE_OTHER_WORKSPACE');
	 insert into sessions(id,runtime_id,workspace_id,dsh_session_id,state) values
	 ('11111111-9999-4999-8999-999999999999','55555555-5555-4555-8555-555555555555','77777777-7777-4777-8777-777777777777','PRIVATE_NATIVE_FIRST','available'),
	 ('22222222-9999-4999-8999-999999999999','55555555-5555-4555-8555-555555555555','88888888-7777-4777-8777-777777777777','PRIVATE_HIDDEN_NATIVE','available'),
	 ('33333333-9999-4999-8999-999999999999','55555555-5555-4555-8555-555555555555',null,'PRIVATE_EXPLICIT_NATIVE','archived'),
	 ('44444444-9999-4999-8999-999999999999','55555555-5555-4555-8555-555555555555','77777777-7777-4777-8777-777777777777','PRIVATE_OFFLINE_NATIVE','unavailable'),
	 ('55555555-9999-4999-8999-999999999999','aaaaaaaa-3333-4333-8333-aaaaaaaaaaaa',null,'PRIVATE_SIBLING_NATIVE','available');
	 update runtime_grants set scope=jsonb_set(scope,'{sessions}','["33333333-9999-4999-8999-999999999999","99999999-9999-4999-8999-999999999999"]')
	 where runtime_id='55555555-5555-4555-8555-555555555555'`)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, db, proof
}

func TestSessionDirectoryPagesOnlyCurrentResourcesInStableOrder(t *testing.T) {
	ctx, db, proof := sessionDirectoryFixture(t)
	actor := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	page, err := db.SessionDirectory(ctx, actor, managingDevice, proof, directoryRuntime, 1, "")
	if err != nil || len(page.Items) != 1 || page.NextCursor == nil || page.Items[0].ID != "11111111-9999-4999-8999-999999999999" {
		t.Fatal("scoped session directory did not begin at its first UUID", page, err)
	}
	first := page
	// Activity ordering must not move rows across the keyset boundary.
	if _, err := db.DB.ExecContext(ctx, `update sessions set updated_at=clock_timestamp()+interval '1 day' where runtime_id=$1`, directoryRuntime); err != nil {
		t.Fatal(err)
	}
	ids := []string{page.Items[0].ID}
	for page.NextCursor != nil {
		page, err = db.SessionDirectory(ctx, actor, managingDevice, proof, directoryRuntime, 1, *page.NextCursor)
		if err != nil || len(page.Items) != 1 || len(ids) > 10 {
			t.Fatal("session page failed or crossed scope", page, err)
		}
		ids = append(ids, page.Items[0].ID)
	}
	if !reflect.DeepEqual(ids, []string{"11111111-9999-4999-8999-999999999999", "33333333-9999-4999-8999-999999999999", "44444444-9999-4999-8999-999999999999", "99999999-9999-4999-8999-999999999999"}) {
		t.Fatal("directory leaked, skipped or duplicated sessions", ids)
	}
	all, err := db.SessionDirectory(ctx, actor, managingDevice, proof, directoryRuntime, 100, "")
	if err != nil || all.Items[1].State != "archived" || all.Items[1].WorkspaceID != nil || all.Items[2].State != "unavailable" || all.NextCursor != nil {
		t.Fatal("directory hid actual archived/offline metadata", all, err)
	}
	raw, _ := json.Marshal(all)
	for _, private := range []string{"PRIVATE_", "dsh_session_id", "subject", "public_jwk", "workspace-test", "connection_id"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("session directory exposed native identity or private metadata")
		}
	}
	// Narrowing the grant between pages takes effect with the old cursor too.
	if _, err := db.DB.ExecContext(ctx, `update runtime_grants set scope='{"actions":["session.list"],"workspaces":[],"sessions":["99999999-9999-4999-8999-999999999999"]}',grant_version=grant_version+1 where runtime_id=$1`, directoryRuntime); err != nil {
		t.Fatal(err)
	}
	narrow, err := db.SessionDirectory(ctx, actor, managingDevice, proof, directoryRuntime, 100, *first.NextCursor)
	if err != nil || len(narrow.Items) != 1 || narrow.Items[0].ID != "99999999-9999-4999-8999-999999999999" {
		t.Fatal("old cursor retained a broader grant", narrow, err)
	}
	if _, err := db.DB.ExecContext(ctx, `update runtime_grants set scope='{"actions":["session.list"],"workspaces":[],"sessions":[]}' where runtime_id=$1`, directoryRuntime); err != nil {
		t.Fatal(err)
	}
	empty, err := db.SessionDirectory(ctx, actor, managingDevice, proof, directoryRuntime, 100, "")
	if err != nil || len(empty.Items) != 0 || empty.NextCursor != nil {
		t.Fatal("empty resource arrays conferred enumeration", empty, err)
	}
}

func TestSessionDirectoryCursorCannotPreserveLostDeviceOrRuntimeAuthority(t *testing.T) {
	ctx, db, proof := sessionDirectoryFixture(t)
	actor := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	page, err := db.SessionDirectory(ctx, actor, managingDevice, proof, directoryRuntime, 1, "")
	if err != nil || page.NextCursor == nil {
		t.Fatal(err)
	}
	for _, change := range []struct{ name, mutate, restore string }{
		{"device", `update devices set revoked_at=clock_timestamp()`, `update devices set revoked_at=null`},
		{"account", `update users set status='suspended' where id='22222222-2222-4222-8222-222222222222'`, `update users set status='active'`},
		{"grant", `update runtime_grants set revoked_at=clock_timestamp()`, `update runtime_grants set revoked_at=null`},
		{"expiry", `update runtime_grants set expires_at=clock_timestamp()-interval '1 second'`, `update runtime_grants set expires_at=null`},
		{"read without list", `update runtime_grants set scope=jsonb_set(scope,'{actions}','["session.read"]')`, `update runtime_grants set scope=jsonb_set(scope,'{actions}','["session.list"]')`},
		{"runtime", `update runtimes set revoked_at=clock_timestamp()`, `update runtimes set revoked_at=null`},
		{"installation", `update installations set revoked_at=clock_timestamp()`, `update installations set revoked_at=null`},
		{"host", `update hosts set state='revoked'`, `update hosts set state='active'`},
		{"membership", `delete from org_memberships where user_id='22222222-2222-4222-8222-222222222222'`, `insert into org_memberships(org_id,user_id,role) values('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','22222222-2222-4222-8222-222222222222','member')`},
	} {
		t.Run(change.name, func(t *testing.T) {
			if _, err := db.DB.ExecContext(ctx, change.mutate); err != nil {
				t.Fatal(err)
			}
			for _, cursor := range []string{"", *page.NextCursor} {
				if _, err := db.SessionDirectory(ctx, actor, managingDevice, proof, directoryRuntime, 1, cursor); !errors.Is(err, ErrAccessDenied) {
					t.Fatal("old cursor or earlier middleware lookup preserved lost authority", err)
				}
			}
			if _, err := db.DB.ExecContext(ctx, change.restore); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, other := range []struct {
		identity     UserIdentity
		key, runtime string
	}{
		{actor, strings.Repeat("A", 43), directoryRuntime},
		{actor, proof, secondProfile},
		{UserIdentity{Issuer: actor.Issuer, Subject: "target-subject"}, proof, directoryRuntime},
	} {
		if _, err := db.SessionDirectory(ctx, other.identity, managingDevice, other.key, other.runtime, 1, *page.NextCursor); !errors.Is(err, ErrAccessDenied) {
			t.Fatal("directory cursor changed account/key/runtime", err)
		}
	}
	cursor, _ := parseSessionDirectoryCursor(*page.NextCursor)
	cursor.UserID = directoryTarget
	raw, _ := json.Marshal(cursor)
	if _, err := db.SessionDirectory(ctx, actor, managingDevice, proof, directoryRuntime, 1, base64.RawURLEncoding.EncodeToString(raw)); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("cursor selected another actor", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := db.SessionDirectory(cancelled, actor, managingDevice, proof, directoryRuntime, 50, ""); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatal("database read failure became an empty authorized page", err)
	}
}
