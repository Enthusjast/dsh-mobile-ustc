package store

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestInstallationRuntimeDirectoryAndSingleProfileRetirement(t *testing.T) {
	ctx, db, proof := installationManagementFixture(t)
	actor := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	first, err := db.ListInstallationRuntimes(ctx, actor, managingDevice, proof, managedInstallation, 1, "")
	if err != nil || len(first.Items) != 1 || first.Items[0].ID != directoryRuntime || first.NextCursor == nil {
		t.Fatal("owned profile directory not paged", first, err)
	}
	second, err := db.ListInstallationRuntimes(ctx, actor, managingDevice, proof, managedInstallation, 1, *first.NextCursor)
	if err != nil || len(second.Items) != 1 || second.Items[0].ID != secondProfile || second.NextCursor != nil {
		t.Fatal("directory crossed installation or page boundary", second, err)
	}
	secret := strings.Repeat("A", 43)
	digest := sha256.Sum256([]byte(secret))
	if _, err := db.DB.ExecContext(ctx, `insert into host_connection_credentials(token_sha256,installation_id,key_version,expires_at) values($1,$2,1,clock_timestamp()+interval '1 minute')`, digest[:], managedInstallation); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := db.RevokeInstallationRuntime(ctx, actor, managingDevice, proof, managedInstallation, directoryRuntime); err != nil {
			t.Fatal(err)
		}
	}
	var scoped bool
	if err := db.DB.QueryRowContext(ctx, `select
	 (select revoked_at is not null from runtimes where id=$1) and
	 (select revoked_at is null from runtimes where id=$2) and
	 (select revoked_at is null from installations where id=$3) and
	 (select count(*)=1 from runtime_grants where runtime_id=$1 and revoked_at is not null and grant_version=2) and
	 (select count(*)=1 from runtime_grants where runtime_id=$2 and revoked_at is null and grant_version=1) and
	 (select state='unavailable' from sessions where runtime_id=$1) and
	 (select state='active' from hosts where id='11111111-1111-4111-8111-111111111111')`, directoryRuntime, secondProfile, managedInstallation).Scan(&scoped); err != nil || !scoped {
		t.Fatal("single-profile retirement changed sibling authority", err)
	}
	if _, err := db.LookupHostConnectionCredential(ctx, secret); err != nil {
		t.Fatal("shared installation credential no longer supports active sibling", err)
	}
	connection := RuntimeConnectionInput{InstallationID: managedInstallation, KeyVersion: 1, RuntimeID: directoryRuntime,
		RuntimeEpoch: "eeeeeeee-1111-4111-8111-111111111111", ConnectionID: "ffffffff-1111-4111-8111-111111111111",
		DSHVersion: "0.2.1-rc.2", ApplicationVersion: "fixture", PluginVersion: "fixture", ProtocolVersion: 1}
	if _, err := db.AttachRuntimeConnection(ctx, connection); !errors.Is(err, ErrHostCredentialInvalid) {
		t.Fatal("shared credential reattached a retired runtime", err)
	}
	connection.RuntimeID = secondProfile
	if _, err := db.AttachRuntimeConnection(ctx, connection); err != nil {
		t.Fatal("shared credential could not attach its surviving sibling", err)
	}
	if err := assertGrantState(ctx, db.DB, directoryRuntime, directoryOwner, 2, "owner", true); err != nil {
		t.Fatal(err)
	}
	var audits, events int
	if err := db.DB.QueryRowContext(ctx, `select (select count(*) from audit_log where action='runtime.revoke' and runtime_id=$1),(select count(*) from control_outbox where topic='runtime.revoked' and payload->>'runtime_id'=$1::text)`, directoryRuntime).Scan(&audits, &events); err != nil || audits != 1 || events != 1 {
		t.Fatal("runtime retirement repeated or omitted its durable metadata", audits, events, err)
	}
	page, err := db.ListInstallationRuntimes(ctx, actor, managingDevice, proof, managedInstallation, 100, "")
	if err != nil || page.Items[0].State != "revoked" || page.Items[0].RevokedAt == nil || page.Items[1].State != "active" {
		t.Fatal("current profile directory hid retirement or changed sibling", page, err)
	}
	raw, _ := json.Marshal(page)
	for _, private := range []string{"profile_ref", "second-profile", "public_jwk", "owner-subject", "connection_id"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("management directory exposed local or credential metadata")
		}
	}
	// The full-installation path must still retire the remaining sibling.
	if err := db.RevokeInstallation(ctx, actor, managingDevice, proof, managedInstallation); err != nil {
		t.Fatal(err)
	}
	if err := assertGrantState(ctx, db.DB, secondProfile, directoryOwner, 2, "viewer", true); err != nil {
		t.Fatal(err)
	}
}

func TestInstallationRuntimeManagementRechecksOwnerAdminAndCurrentKey(t *testing.T) {
	ctx, db, proof := installationManagementFixture(t)
	owner := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	other := UserIdentity{Issuer: owner.Issuer, Subject: "target-subject"}
	otherDevice, otherProof := "dddddddd-dddd-4ddd-8ddd-dddddddddddd", strings.Repeat("B", 43)
	if _, err := db.DB.ExecContext(ctx, `insert into runtime_grants(runtime_id,user_id,role,scope,granted_by) values($1,$2,'owner','{"actions":["grant.manage"],"workspaces":[],"sessions":[]}',$3)`, directoryRuntime, directoryTarget, directoryOwner); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ListInstallationRuntimes(ctx, other, otherDevice, otherProof, managedInstallation, 100, ""); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("runtime owner enumerated another account's installation profiles", err)
	}
	if err := db.RevokeInstallationRuntime(ctx, other, otherDevice, otherProof, managedInstallation, directoryRuntime); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("runtime grant conferred installation retirement", err)
	}
	first, err := db.ListInstallationRuntimes(ctx, owner, managingDevice, proof, managedInstallation, 1, "")
	if err != nil || first.NextCursor == nil {
		t.Fatal(err)
	}
	for _, invalid := range []struct{ installation, key string }{{siblingInstallation, proof}, {managedInstallation, otherProof}} {
		if _, err := db.ListInstallationRuntimes(ctx, owner, managingDevice, invalid.key, invalid.installation, 1, *first.NextCursor); !errors.Is(err, ErrAccessDenied) {
			t.Fatal("cursor moved to another installation/key", err)
		}
	}
	cursor, _ := parseInstallationRuntimeCursor(*first.NextCursor)
	cursor.UserID = directoryTarget
	raw, _ := json.Marshal(cursor)
	if _, err := db.ListInstallationRuntimes(ctx, owner, managingDevice, proof, managedInstallation, 1, base64.RawURLEncoding.EncodeToString(raw)); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("cursor selected another manager", err)
	}
	if err := db.RevokeInstallationRuntime(ctx, owner, managingDevice, proof, managedInstallation, siblingProfile); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("runtime ID bypassed installation ownership chain", err)
	}
	if _, err := db.DB.ExecContext(ctx, `update org_memberships set role='admin' where user_id=$1`, directoryTarget); err != nil {
		t.Fatal(err)
	}
	admin, err := db.ListInstallationRuntimes(ctx, other, otherDevice, otherProof, managedInstallation, 1, "")
	if err != nil || admin.NextCursor == nil {
		t.Fatal("current admin could not list profiles", err)
	}
	if _, err := db.DB.ExecContext(ctx, `update org_memberships set role='member' where user_id=$1`, directoryTarget); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ListInstallationRuntimes(ctx, other, otherDevice, otherProof, managedInstallation, 1, *admin.NextCursor); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("earlier cursor kept lost admin authority", err)
	}
	if _, err := db.DB.ExecContext(ctx, `delete from org_memberships where user_id=$1`, directoryOwner); err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeInstallationRuntime(ctx, owner, managingDevice, proof, managedInstallation, directoryRuntime); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("former member retired its old profile", err)
	}
	if _, err := db.ListInstallationRuntimes(ctx, owner, managingDevice, proof, managedInstallation, 1, *first.NextCursor); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("former member retained its directory cursor", err)
	}
}

func TestInstallationRuntimeRetirementConcurrentRetriesAndAuditRollback(t *testing.T) {
	ctx, db, proof := installationManagementFixture(t)
	actor := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	if _, err := db.DB.ExecContext(ctx, `create function fail_profile_audit() returns trigger language plpgsql as $$ begin
	 if new.action='runtime.revoke' then raise exception 'PRIVATE_PROFILE_AUDIT';end if;return new;end $$;
	 create trigger fail_profile_audit before insert on audit_log for each row execute function fail_profile_audit()`); err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeInstallationRuntime(ctx, actor, managingDevice, proof, managedInstallation, directoryRuntime); !errors.Is(err, ErrDatabaseUnavailable) || strings.Contains(err.Error(), "PRIVATE_PROFILE_AUDIT") {
		t.Fatal("audit failure committed or leaked", err)
	}
	if err := assertGrantState(ctx, db.DB, directoryRuntime, directoryOwner, 1, "owner", false); err != nil {
		t.Fatal(err)
	}
	if err := assertChangeCounts(ctx, db.DB, 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `drop trigger fail_profile_audit on audit_log;drop function fail_profile_audit()`); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			results <- db.RevokeInstallationRuntime(ctx, actor, managingDevice, proof, managedInstallation, directoryRuntime)
		}()
	}
	group.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := assertChangeCounts(ctx, db.DB, 2, 2); err != nil {
		t.Fatal("concurrent retry repeated profile retirement", err)
	}
}

func TestInstallationRuntimeRetirementFencesGrantCommittedDuringLockWait(t *testing.T) {
	ctx, db, proof := installationManagementFixture(t)
	actor := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	if _, err := db.DB.ExecContext(ctx, `create function hold_profile_grant() returns trigger language plpgsql as $$ begin
 if new.user_id='66666666-6666-4666-8666-666666666666' then perform pg_advisory_xact_lock(426948);end if;return new;end $$;
 create trigger hold_profile_grant before insert on runtime_grants for each row execute function hold_profile_grant()`); err != nil {
		t.Fatal(err)
	}
	gate, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback()
	if _, err := gate.ExecContext(ctx, `select pg_advisory_xact_lock(426948)`); err != nil {
		t.Fatal(err)
	}
	granted := make(chan error, 1)
	go func() {
		_, err := db.PutRuntimeGrant(ctx, actor, managingDevice, proof, directoryRuntime, directoryTarget, RuntimeGrantInput{Role: "viewer", Scope: GrantScope{Actions: []string{"host.list"}, Workspaces: []string{}, Sessions: []string{}}})
		granted <- err
	}()
	waitForGrantLock(t, ctx, db, "insert into runtime_grants")
	retired := make(chan error, 1)
	go func() {
		retired <- db.RevokeInstallationRuntime(ctx, actor, managingDevice, proof, managedInstallation, directoryRuntime)
	}()
	waitForGrantLock(t, ctx, db, "profile_revoke_fence")
	if err := gate.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-granted; err != nil {
		t.Fatal(err)
	}
	if err := <-retired; err != nil {
		t.Fatal(err)
	}
	if err := assertGrantState(ctx, db.DB, directoryRuntime, directoryTarget, 2, "viewer", true); err != nil {
		t.Fatal("profile retirement missed the newly committed grant", err)
	}
	if err := assertGrantState(ctx, db.DB, secondProfile, directoryOwner, 1, "viewer", false); err != nil {
		t.Fatal(err)
	}
}

func TestInstallationRuntimeRetirementInvalidatesTicketsAndStagedFiles(t *testing.T) {
	h := newMessageFileFixture(t)
	offer := h.stage(t, h.file)
	actor := UserIdentity{Issuer: h.actor.Issuer, Subject: h.actor.Subject}
	ticket, err := h.database.IssueRealtimeTicket(h.ctx, actor, h.actor.DeviceID, h.file.RuntimeID, GrantScope{Actions: []string{"session.read"}, Workspaces: []string{"77777777-7777-4777-8777-777777777777"}, Sessions: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.database.RevokeInstallationRuntime(h.ctx, actor, h.actor.DeviceID, h.actor.ProofKeyJKT, h.host.InstallationID, h.host.RuntimeID); err != nil {
		t.Fatal(err)
	}
	var invalid bool
	if err := h.database.DB.QueryRowContext(h.ctx, `select state='invalidated' and staged_name is null and ended_at is not null from file_handoffs where id=$1`, offer.HandoffID).Scan(&invalid); err != nil || !invalid {
		t.Fatal("retired profile retained a staged receipt", err)
	}
	if _, err := h.database.PrepareRealtimeTicket(h.ctx, ticket.Token); !errors.Is(err, ErrTicketInvalid) {
		t.Fatal("retired profile retained a realtime ticket", err)
	}
}

func TestInstallationRuntimeAdminAndPendingProfileRetirement(t *testing.T) {
	ctx, db, input, created := pendingActiveHostFixture(t)
	actor := UserIdentity{Issuer: input.Issuer, Subject: input.Subject}
	var proof string
	if err := db.DB.QueryRowContext(ctx, `select proof_key_thumbprint from devices where id=$1`, managingDevice).Scan(&proof); err != nil {
		t.Fatal(err)
	}
	page, err := db.ListInstallationRuntimes(ctx, actor, managingDevice, proof, created.InstallationID, 100, "")
	if err != nil || len(page.Items) != 1 || page.Items[0].State != "pending" {
		t.Fatal("pending profile not manageable", page, err)
	}
	// An admin without installation ownership or a runtime grant may retire it.
	if _, err := db.DB.ExecContext(ctx, `update org_memberships set role='admin' where user_id=$1;`, directoryTarget); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `update devices set proof_key_thumbprint=$1 where id='dddddddd-dddd-4ddd-8ddd-dddddddddddd'`, strings.Repeat("B", 43)); err != nil {
		t.Fatal(err)
	}
	admin := UserIdentity{Issuer: input.Issuer, Subject: "target-subject"}
	if err := db.RevokeInstallationRuntime(ctx, admin, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", strings.Repeat("B", 43), created.InstallationID, created.RuntimeID); err != nil {
		t.Fatal(err)
	}
	var cancelled bool
	if err := db.DB.QueryRowContext(ctx, `select (select state='cancelled' from enrollments where id=$1) and (select revoked_at is null from installations where id=$2) and (select revoked_at is null from runtimes where id=$3)`, created.EnrollmentID, created.InstallationID, directoryRuntime).Scan(&cancelled); err != nil || !cancelled {
		t.Fatal("pending profile retirement changed its installation or sibling", err)
	}
}
