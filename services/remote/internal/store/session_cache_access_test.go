package store

import (
	"errors"
	"testing"
	"time"
)

func TestSessionCacheReadAccessChecksCurrentMembershipWhileHostIsOffline(t *testing.T) {
	ctx, postgres := newPostgresIntegrationDatabase(t)
	proof := seedGrantFixture(t, ctx, postgres.DB)
	identity := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	const device = "44444444-4444-4444-8444-444444444444"
	const runtime = "55555555-5555-4555-8555-555555555555"
	const session = "99999999-9999-4999-8999-999999999999"
	const workspace = "77777777-7777-4777-8777-777777777777"
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := postgres.DB.ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	read := func() (SessionReadAccess, error) {
		return postgres.SessionCacheReadAccess(ctx, identity, device, proof, runtime, session, time.Now().Add(time.Hour))
	}
	if _, err := read(); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("directory-only scope authorized body cache: %v", err)
	}
	exec(`update runtime_grants set role='viewer',scope=$1::jsonb where runtime_id=$2`, `{"actions":["session.read"],"workspaces":["`+workspace+`"],"sessions":[]}`, runtime)
	exec(`update sessions set state='unavailable' where id=$1`, session)
	access, err := read()
	if err != nil || access.WorkspaceID == nil || *access.WorkspaceID != workspace || access.GrantVersion != 1 || !access.ExpiresAt.After(access.IssuedAt) || access.ExpiresAt.Sub(access.IssuedAt) > 5*time.Minute {
		t.Fatalf("offline read authority invalid: %+v %v", access, err)
	}
	credentialUntil := time.Now().Add(20 * time.Second)
	access, err = postgres.SessionCacheReadAccess(ctx, identity, device, proof, runtime, session, credentialUntil)
	if err != nil || access.ExpiresAt.After(credentialUntil) || access.ExpiresAt.Before(credentialUntil.Add(-time.Millisecond)) {
		t.Fatalf("credential expiry was not respected: %+v %v", access, err)
	}
	grantUntil := time.Now().Add(10 * time.Second)
	exec(`update runtime_grants set expires_at=$1 where runtime_id=$2`, grantUntil, runtime)
	access, err = read()
	if err != nil || access.ExpiresAt.After(grantUntil) || access.ExpiresAt.Before(grantUntil.Add(-time.Millisecond)) {
		t.Fatalf("grant expiry was not respected: %+v %v", access, err)
	}
	exec(`update runtime_grants set expires_at=null where runtime_id=$1`, runtime)
	for _, denied := range []struct {
		identity                        UserIdentity
		device, proof, runtime, session string
		until                           time.Time
	}{
		{identity, device, "wrong-current-key", runtime, session, credentialUntil},
		{UserIdentity{Issuer: identity.Issuer, Subject: "target-subject"}, device, proof, runtime, session, credentialUntil},
		{identity, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", proof, runtime, session, credentialUntil},
		{identity, device, proof, "88888888-8888-4888-8888-888888888888", session, credentialUntil},
		{identity, device, proof, runtime, "88888888-8888-4888-8888-888888888888", credentialUntil},
		{identity, device, proof, runtime, session, time.Now().Add(-time.Second)},
	} {
		if _, err := postgres.SessionCacheReadAccess(ctx, denied.identity, denied.device, denied.proof, denied.runtime, denied.session, denied.until); !errors.Is(err, ErrAccessDenied) {
			t.Fatalf("wrong identity/resource/key or expiry was accepted: %v", err)
		}
	}
	const moved = "88888888-8888-4888-8888-888888888888"
	exec(`insert into workspaces(id,runtime_id,workspace_ref) values($1,$2,'moved')`, moved, runtime)
	exec(`update sessions set workspace_id=$1 where id=$2`, moved, session)
	if _, err := read(); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("old workspace still authorized moved session: %v", err)
	}
	exec(`update runtime_grants set scope=$1::jsonb,grant_version=4 where runtime_id=$2`, `{"actions":["session.read"],"workspaces":[],"sessions":["`+session+`"]}`, runtime)
	access, err = read()
	if err != nil || access.WorkspaceID == nil || *access.WorkspaceID != moved || access.GrantVersion != 4 {
		t.Fatalf("literal-session scope or current version lost: %+v %v", access, err)
	}
	for _, change := range []struct{ name, apply, undo string }{
		{"device revocation", `update devices set revoked_at=now() where id='` + device + `'`, `update devices set revoked_at=null where id='` + device + `'`},
		{"grant revocation", `update runtime_grants set revoked_at=now()`, `update runtime_grants set revoked_at=null`},
		{"membership removal", `delete from org_memberships where user_id='22222222-2222-4222-8222-222222222222'`, `insert into org_memberships(org_id,user_id,role) values('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','22222222-2222-4222-8222-222222222222','member')`},
		{"host suspension", `update hosts set state='pending'`, `update hosts set state='active'`},
		{"installation revocation", `update installations set revoked_at=now()`, `update installations set revoked_at=null`},
		{"runtime revocation", `update runtimes set revoked_at=now()`, `update runtimes set revoked_at=null`},
		{"user suspension", `update users set status='suspended' where subject='owner-subject'`, `update users set status='active' where subject='owner-subject'`},
		{"empty scope", `update runtime_grants set scope='{"actions":["session.read"],"sessions":[],"workspaces":[]}'::jsonb`, `update runtime_grants set scope='{"actions":["session.read"],"sessions":["` + session + `"],"workspaces":[]}'::jsonb`},
	} {
		t.Run(change.name, func(t *testing.T) {
			if _, err := postgres.DB.ExecContext(ctx, change.apply); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := postgres.DB.ExecContext(ctx, change.undo); err != nil {
					t.Fatal(err)
				}
			}()
			if _, err := read(); !errors.Is(err, ErrAccessDenied) {
				t.Fatalf("revoked cache authority survived: %v", err)
			}
		})
	}
	if err := postgres.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := read(); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatalf("database outage did not fail closed: %v", err)
	}
}
