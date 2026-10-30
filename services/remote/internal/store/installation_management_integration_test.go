package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

const managedInstallation = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
const siblingInstallation = "ffffffff-ffff-4fff-8fff-ffffffffffff"
const pendingInstallation = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
const secondProfile = "aaaaaaaa-3333-4333-8333-aaaaaaaaaaaa"
const siblingProfile = "bbbbbbbb-3333-4333-8333-bbbbbbbbbbbb"
const managingDevice = "44444444-4444-4444-8444-444444444444"

func installationManagementFixture(t *testing.T) (context.Context, *Postgres, string) {
	t.Helper()
	ctx, db := newPostgresIntegrationDatabase(t)
	proof := seedGrantFixture(t, ctx, db.DB)
	_, err := db.DB.ExecContext(ctx, `update devices set proof_key_thumbprint='BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' where id='dddddddd-dddd-4ddd-8ddd-dddddddddddd';
	 insert into installations(id,host_id,owner_user_id,public_jwk,public_key_thumbprint) values
	 ('ffffffff-ffff-4fff-8fff-ffffffffffff','11111111-1111-4111-8111-111111111111','66666666-6666-4666-8666-666666666666','{"private":"PRIVATE_INSTALLATION_KEY"}','sibling-installation-key'),
	 ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222','{}','pending-installation-key');
	 insert into hosts(id,org_id,alias,state) values('12121212-1212-4212-8212-121212121212','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','Foreign host','active');
	 insert into installations(id,host_id,owner_user_id,public_jwk,public_key_thumbprint) values('abababab-abab-4bab-8bab-abababababab','12121212-1212-4212-8212-121212121212','33333333-3333-4333-8333-333333333333','{}','foreign-installation-key');
	 insert into runtimes(id,installation_id,profile_ref,protocol_version) values
	 ('aaaaaaaa-3333-4333-8333-aaaaaaaaaaaa','cccccccc-cccc-4ccc-8ccc-cccccccccccc','second-profile',1),
	 ('bbbbbbbb-3333-4333-8333-bbbbbbbbbbbb','ffffffff-ffff-4fff-8fff-ffffffffffff','sibling-profile',1);
	 insert into runtime_grants(runtime_id,user_id,role,scope,granted_by) values
	 ('aaaaaaaa-3333-4333-8333-aaaaaaaaaaaa','22222222-2222-4222-8222-222222222222','viewer','{"actions":["host.list"],"workspaces":[],"sessions":[]}','22222222-2222-4222-8222-222222222222'),
	 ('bbbbbbbb-3333-4333-8333-bbbbbbbbbbbb','66666666-6666-4666-8666-666666666666','viewer','{"actions":["host.list"],"workspaces":[],"sessions":[]}','66666666-6666-4666-8666-666666666666');
	 update installations set created_at='2026-01-01T00:00:00Z'`)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, db, proof
}

func TestInstallationManagementDirectoryAndAuthorizationRespectOwnershipAndCurrentOrganization(t *testing.T) {
	ctx, db, proof := installationManagementFixture(t)
	owner := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	page, err := db.ListInstallations(ctx, owner, managingDevice, proof, 1, "")
	if err != nil || len(page.Items) != 1 || page.NextCursor == nil || page.Items[0].ID != pendingInstallation || page.Items[0].State != "pending" {
		t.Fatal("owned installations were not paged", page, err)
	}
	last, err := db.ListInstallations(ctx, owner, managingDevice, proof, 1, *page.NextCursor)
	if err != nil || len(last.Items) != 1 || last.NextCursor != nil || last.Items[0].ID != managedInstallation || last.Items[0].State != "active" || last.Items[0].RuntimeCount != 2 || !last.Items[0].IsOwner {
		t.Fatal("owned installation boundary failed", last, err)
	}
	target := UserIdentity{Issuer: owner.Issuer, Subject: "target-subject"}
	targetDevice := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	targetProof := strings.Repeat("B", 43)
	if _, err := db.DB.ExecContext(ctx, `insert into runtime_grants(runtime_id,user_id,role,scope,granted_by) values('55555555-5555-4555-8555-555555555555','66666666-6666-4666-8666-666666666666','owner','{"actions":["grant.manage"],"workspaces":[],"sessions":[]}','22222222-2222-4222-8222-222222222222')`); err != nil {
		t.Fatal(err)
	}
	targets, err := db.ListInstallations(ctx, target, targetDevice, targetProof, 100, "")
	if err != nil || len(targets.Items) != 1 || targets.Items[0].ID != siblingInstallation {
		t.Fatal("ordinary member enumerated other installations", err)
	}
	if err := db.RevokeInstallation(ctx, target, targetDevice, targetProof, managedInstallation); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("member revoked another owner's profiles", err)
	}
	if _, err := db.ListInstallations(ctx, target, targetDevice, targetProof, 1, *page.NextCursor); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("other key reused an installation cursor", err)
	}
	if _, err := db.DB.ExecContext(ctx, `update org_memberships set role='admin' where user_id='66666666-6666-4666-8666-666666666666'`); err != nil {
		t.Fatal(err)
	}
	admin, err := db.ListInstallations(ctx, target, targetDevice, targetProof, 100, "")
	if err != nil || len(admin.Items) != 3 {
		t.Fatal("current organization administrator could not discover installations", err)
	}
	if err := db.RevokeInstallation(ctx, target, targetDevice, targetProof, "abababab-abab-4bab-8bab-abababababab"); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("organization administrator retired another organization's installation", err)
	}
	adminFirst, err := db.ListInstallations(ctx, target, targetDevice, targetProof, 1, "")
	if err != nil || adminFirst.NextCursor == nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `update org_memberships set role='member' where user_id='66666666-6666-4666-8666-666666666666'`); err != nil {
		t.Fatal(err)
	}
	adminNext, err := db.ListInstallations(ctx, target, targetDevice, targetProof, 1, *adminFirst.NextCursor)
	if err != nil || len(adminNext.Items) != 0 {
		t.Fatal("earlier administrator cursor preserved lost authority", adminNext, err)
	}
	if _, err := db.DB.ExecContext(ctx, `update org_memberships set role='admin' where user_id='66666666-6666-4666-8666-666666666666'`); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(admin)
	if strings.Contains(string(raw), "PRIVATE_INSTALLATION_KEY") || strings.Contains(string(raw), "public_jwk") || strings.Contains(string(raw), "public_key_thumbprint") {
		t.Fatal("installation directory exported keys")
	}
	if err := db.RevokeInstallation(ctx, target, targetDevice, targetProof, pendingInstallation); err != nil {
		t.Fatal("administrator could not retire an unapproved installation", err)
	}
	if _, err := db.DB.ExecContext(ctx, `delete from org_memberships where user_id='22222222-2222-4222-8222-222222222222'`); err != nil {
		t.Fatal(err)
	}
	withoutMembership, err := db.ListInstallations(ctx, owner, managingDevice, proof, 100, "")
	if err != nil || len(withoutMembership.Items) != 0 {
		t.Fatal("former organization member retained installation visibility", err)
	}
	if err := db.RevokeInstallation(ctx, owner, managingDevice, proof, managedInstallation); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("former member retained installation management", err)
	}
}

func TestInstallationManagementRevokesEveryProfileAndCredentialWithoutAffectingSiblingInstallations(t *testing.T) {
	ctx, db, proof := installationManagementFixture(t)
	owner := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	secret := strings.Repeat("A", 43)
	digest := sha256.Sum256([]byte(secret))
	if _, err := db.DB.ExecContext(ctx, `insert into host_connection_credentials(token_sha256,installation_id,key_version,expires_at) values($1,$2,1,clock_timestamp()+interval '1 minute')`, digest[:], managedInstallation); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `insert into installation_challenges(installation_id,key_version,challenge_sha256,expires_at) values($1,1,$2,clock_timestamp()+interval '1 minute')`, managedInstallation, digest[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.LookupHostConnectionCredential(ctx, secret); err != nil {
		t.Fatal("fixture credential was not initially valid", err)
	}
	for range 2 {
		if err := db.RevokeInstallation(ctx, owner, managingDevice, proof, managedInstallation); err != nil {
			t.Fatal(err)
		}
	}
	var preserved bool
	if err := db.DB.QueryRowContext(ctx, `select
	 (select revoked_at is not null from installations where id='cccccccc-cccc-4ccc-8ccc-cccccccccccc') and
	 (select count(*)=2 from runtimes where installation_id='cccccccc-cccc-4ccc-8ccc-cccccccccccc' and revoked_at is not null) and
	 (select count(*)=2 from runtime_grants g join runtimes r on r.id=g.runtime_id where r.installation_id='cccccccc-cccc-4ccc-8ccc-cccccccccccc' and g.revoked_at is not null and grant_version=2) and
	 (select consumed_at is not null from installation_challenges where installation_id='cccccccc-cccc-4ccc-8ccc-cccccccccccc') and
	 (select state='unavailable' from sessions where id='99999999-9999-4999-8999-999999999999') and
	 (select revoked_at is null from installations where id='ffffffff-ffff-4fff-8fff-ffffffffffff') and
	 (select revoked_at is null from runtimes where id='bbbbbbbb-3333-4333-8333-bbbbbbbbbbbb') and
	 (select revoked_at is null from devices where id='44444444-4444-4444-8444-444444444444') and
	 (select state='active' from hosts where id='11111111-1111-4111-8111-111111111111')`).Scan(&preserved); err != nil || !preserved {
		t.Fatal("installation retirement crossed identity or sibling boundaries", err)
	}
	if _, err := db.LookupHostConnectionCredential(ctx, secret); !errors.Is(err, ErrHostCredentialInvalid) {
		t.Fatal("retired cached credential remained usable", err)
	}
	events, err := db.PendingControlEvents(ctx, 128)
	if err != nil {
		t.Fatal(err)
	}
	runtimes, grants := 0, 0
	for _, event := range events {
		if event.Topic == "runtime.revoked" {
			runtimes++
			if event.RuntimeID != "55555555-5555-4555-8555-555555555555" && event.RuntimeID != secondProfile {
				t.Fatal("unrelated runtime retired")
			}
		} else if event.Topic == "runtime_grant.revoked" {
			grants++
		}
	}
	if runtimes != 2 || grants != 2 {
		t.Fatal("revocation notifications were omitted or repeated", runtimes, grants)
	}
	var audits int
	if err := db.DB.QueryRowContext(ctx, `select count(*) from audit_log where action='installation.revoke'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("idempotent revoke repeated installation audit", err)
	}
	listed, err := db.ListInstallations(ctx, owner, managingDevice, proof, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range listed.Items {
		if item.ID == managedInstallation && item.State != "revoked" {
			t.Fatal("directory did not reconcile revocation")
		}
	}
}

func TestInstallationManagementFailuresRollBackAndRecheckCurrentProof(t *testing.T) {
	ctx, db, proof := installationManagementFixture(t)
	owner := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	if _, err := db.DB.ExecContext(ctx, `create function fail_installation_audit() returns trigger language plpgsql as $$ begin if new.action='installation.revoke' then raise exception 'PRIVATE_INSTALLATION_AUDIT';end if;return new;end $$;create trigger fail_installation_audit before insert on audit_log for each row execute function fail_installation_audit()`); err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeInstallation(ctx, owner, managingDevice, proof, managedInstallation); err == nil || strings.Contains(err.Error(), "PRIVATE_INSTALLATION_AUDIT") {
		t.Fatal("failed audit committed or leaked", err)
	}
	var unchanged bool
	if err := db.DB.QueryRowContext(ctx, `select (select revoked_at is null from installations where id='cccccccc-cccc-4ccc-8ccc-cccccccccccc') and (select count(*)=0 from control_outbox) and (select count(*)=0 from runtime_grants where revoked_at is not null)`).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("failed revocation partially committed", err)
	}
	if _, err := db.DB.ExecContext(ctx, `drop trigger fail_installation_audit on audit_log;drop function fail_installation_audit();create function fail_installation_event() returns trigger language plpgsql as $$ begin raise exception 'PRIVATE_INSTALLATION_EVENT';end $$;create trigger fail_installation_event before insert on control_outbox for each row execute function fail_installation_event()`); err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeInstallation(ctx, owner, managingDevice, proof, managedInstallation); err == nil || strings.Contains(err.Error(), "PRIVATE_INSTALLATION_EVENT") {
		t.Fatal("failed event committed or leaked", err)
	}
	if err := db.DB.QueryRowContext(ctx, `select (select revoked_at is null from installations where id='cccccccc-cccc-4ccc-8ccc-cccccccccccc') and (select count(*)=0 from audit_log)`).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("failed event left partial authority or audit", err)
	}
	if err := db.RevokeInstallation(ctx, owner, managingDevice, strings.Repeat("A", 43), managedInstallation); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("stale proof selected installation owner", err)
	}
	if _, err := db.DB.ExecContext(ctx, `update devices set revoked_at=clock_timestamp() where id='44444444-4444-4444-8444-444444444444'`); err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeInstallation(ctx, owner, managingDevice, proof, managedInstallation); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("earlier active-device check survived revocation", err)
	}
}

func TestInstallationManagementSerializesExactConcurrentRevocation(t *testing.T) {
	ctx, db, proof := installationManagementFixture(t)
	owner := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	var group sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			results <- db.RevokeInstallation(ctx, owner, managingDevice, proof, managedInstallation)
		}()
	}
	group.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	var audits int
	if err := db.DB.QueryRowContext(ctx, `select count(*) from audit_log where action='installation.revoke'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("concurrent revoke was not idempotent", err)
	}
}

func TestInstallationManagementFencesGrantCommittedWhileWaiting(t *testing.T) {
	ctx, db, proof := installationManagementFixture(t)
	owner := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	if _, err := db.DB.ExecContext(ctx, `create function hold_installation_grant() returns trigger language plpgsql as $$ begin if new.user_id='66666666-6666-4666-8666-666666666666' then perform pg_advisory_xact_lock(426934);end if;return new;end $$;create trigger hold_installation_grant before insert on runtime_grants for each row execute function hold_installation_grant()`); err != nil {
		t.Fatal(err)
	}
	gate, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback()
	if _, err = gate.ExecContext(ctx, `select pg_advisory_xact_lock(426934)`); err != nil {
		t.Fatal(err)
	}
	granted := make(chan error, 1)
	go func() {
		_, err := db.PutRuntimeGrant(ctx, owner, managingDevice, "55555555-5555-4555-8555-555555555555", "66666666-6666-4666-8666-666666666666", RuntimeGrantInput{Role: "viewer", Scope: GrantScope{Actions: []string{"host.list"}, Workspaces: []string{}, Sessions: []string{}}})
		granted <- err
	}()
	wait := func(fragment string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			var waiting bool
			if err := db.DB.QueryRowContext(ctx, `select exists(select 1 from pg_stat_activity where datname=current_database() and wait_event_type='Lock' and query like $1)`, "%"+fragment+"%").Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("expected installation lock was not observed")
	}
	wait("insert into runtime_grants")
	retired := make(chan error, 1)
	go func() { retired <- db.RevokeInstallation(ctx, owner, managingDevice, proof, managedInstallation) }()
	wait("installation_revoke_fence")
	if err = gate.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = <-granted; err != nil {
		t.Fatal("grant failed before retirement", err)
	}
	if err = <-retired; err != nil {
		t.Fatal(err)
	}
	if err = assertGrantState(ctx, db.DB, "55555555-5555-4555-8555-555555555555", "66666666-6666-4666-8666-666666666666", 2, "viewer", true); err != nil {
		t.Fatal("retirement missed a grant committed during its lock wait", err)
	}
}
