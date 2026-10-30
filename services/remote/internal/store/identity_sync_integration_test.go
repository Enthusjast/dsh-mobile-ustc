package store

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIdentitySyncProvisionsStableMappingsAndReconcilesExpiredExactRetries(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	snapshot := identitySnapshotFixture(t, 1)
	snapshot.ExpiresAt = time.Now().UTC().Add(time.Second).Truncate(time.Microsecond)
	first, err := db.ApplyIdentitySnapshot(ctx, snapshot.DatabaseEpoch, snapshot.Issuer, snapshot)
	if err != nil || first.Revision != 1 || first.Counts["users_created"] != 3 {
		t.Fatal("initial provisioning failed", first, err)
	}
	var owner string
	if err := db.DB.QueryRowContext(ctx, `select id::text from users where issuer=$1 and subject='owner-subject'`, snapshot.Issuer).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(snapshot.ExpiresAt) + 20*time.Millisecond)
	retried, err := db.ApplyIdentitySnapshot(ctx, snapshot.DatabaseEpoch, snapshot.Issuer, snapshot)
	if err != nil || !reflect.DeepEqual(first, retried) {
		t.Fatal("exact retry changed a committed synchronization", err)
	}
	changed := snapshot
	changed.Users = append([]RecoveryUser{}, snapshot.Users...)
	changed.Users[0].Status = "suspended"
	changed.Users[0].Memberships = []RecoveryMembership{}
	if _, err = db.ApplyIdentitySnapshot(ctx, changed.DatabaseEpoch, changed.Issuer, changed); !errors.Is(err, ErrIdentitySyncConflict) {
		t.Fatal("changed retry accepted", err)
	}
	next := identitySnapshotFixture(t, 2)
	next.Users[0].Memberships[0].Role = "admin"
	if _, err = db.ApplyIdentitySnapshot(ctx, next.DatabaseEpoch, next.Issuer, next); err != nil {
		t.Fatal(err)
	}
	var sameID string
	if err := db.DB.QueryRowContext(ctx, `select id::text from users where issuer=$1 and subject='owner-subject'`, snapshot.Issuer).Scan(&sameID); err != nil || sameID != owner {
		t.Fatal("identity UUID changed", err)
	}
	state, err := db.IdentitySyncStatus(ctx, snapshot.DatabaseEpoch, snapshot.Issuer)
	if err != nil || state.Revision != 2 || state.OperationID == nil || *state.OperationID != next.OperationID {
		t.Fatal("unexpected current source", state, err)
	}
	var retained string
	if err := db.DB.QueryRowContext(ctx, `select coalesce(json_agg(s)::text,'') from identity_sync_runs s`).Scan(&retained); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(retained, "owner-subject") {
		t.Fatal("receipt retained a subject snapshot")
	}
}

func TestIdentitySyncSuspensionRevokesAuthorityWithoutReactivationAndKeepsForeignIssuer(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	seedGrantFixture(t, ctx, db.DB)
	_, err := db.DB.ExecContext(ctx, `insert into users(issuer,subject) values('https://other.example.edu','owner-subject');
	 insert into org_memberships(org_id,user_id,role) select 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',id,'admin' from users where issuer='https://other.example.edu';
	 insert into runtime_grants(runtime_id,user_id,role,scope,granted_by) values('55555555-5555-4555-8555-555555555555','66666666-6666-4666-8666-666666666666','viewer','{"actions":["host.list"],"workspaces":[],"sessions":[]}','22222222-2222-4222-8222-222222222222')`)
	if err != nil {
		t.Fatal(err)
	}
	baseline := identitySnapshotFixture(t, 1)
	if _, err = db.ApplyIdentitySnapshot(ctx, baseline.DatabaseEpoch, baseline.Issuer, baseline); err != nil {
		t.Fatal(err)
	}
	stop := identitySnapshotFixture(t, 2)
	stop.Users[0].Status = "suspended"
	stop.Users[0].Memberships = []RecoveryMembership{}
	run, err := db.ApplyIdentitySnapshot(ctx, stop.DatabaseEpoch, stop.Issuer, stop)
	if err != nil || run.Counts["devices_revoked"] != 1 || run.Counts["installations_revoked"] != 1 || run.Counts["grants_revoked"] != 2 {
		t.Fatal("authority was not retired", run, err)
	}
	if run.Counts["user_audits"] != 1 || run.Counts["membership_audits"] != 1 || run.Counts["device_audits"] != 1 || run.Counts["installation_audits"] != 1 || run.Counts["grant_audits"] != 2 {
		t.Fatal("resource changes are not traceable to the synchronization", run.Counts)
	}
	var auditJSON string
	if err := db.DB.QueryRowContext(ctx, `select coalesce(json_agg(a)::text,'') from audit_log a where actor_id=$1`, run.ID).Scan(&auditJSON); err != nil {
		t.Fatal(err)
	}
	for _, subject := range []string{"owner-subject", "target-subject", "outsider-subject"} {
		if strings.Contains(auditJSON, subject) {
			t.Fatal("synchronization audit retained a source identity string")
		}
	}
	var okay bool
	if err := db.DB.QueryRowContext(ctx, `select
	 (select status='active' from users where issuer='https://other.example.edu') and
	 (select count(*)=1 from org_memberships m join users u on u.id=m.user_id where u.issuer='https://other.example.edu') and
	 (select revoked_at is null from devices where id='dddddddd-dddd-4ddd-8ddd-dddddddddddd') and
	 (select revoked_at is not null from devices where id='44444444-4444-4444-8444-444444444444') and
	 (select revoked_at is not null from installations where id='cccccccc-cccc-4ccc-8ccc-cccccccccccc')`).Scan(&okay); err != nil || !okay {
		t.Fatal("identity scope crossed boundaries", err)
	}
	reenable := identitySnapshotFixture(t, 3)
	if _, err = db.ApplyIdentitySnapshot(ctx, reenable.DatabaseEpoch, reenable.Issuer, reenable); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRowContext(ctx, `select (select status='active' from users where subject='owner-subject' and issuer='https://id.example.edu') and
	 (select count(*)=0 from runtime_grants where revoked_at is null) and
	 (select revoked_at is not null from devices where id='44444444-4444-4444-8444-444444444444') and
	 (select revoked_at is not null from installations where id='cccccccc-cccc-4ccc-8ccc-cccccccccccc')`).Scan(&okay); err != nil || !okay {
		t.Fatal("reenabling identity revived credentials", err)
	}
	if _, err := db.ApplyIdentitySnapshot(ctx, stop.DatabaseEpoch, stop.Issuer, stop); err != nil {
		t.Fatal("historical operation could not be reconciled", err)
	}
	state, err := db.IdentitySyncStatus(ctx, stop.DatabaseEpoch, stop.Issuer)
	if err != nil || state.Revision != 3 {
		t.Fatal("historical retry rewound the current source", state, err)
	}
	var ownerStatus string
	if err := db.DB.QueryRowContext(ctx, `select status from users where subject='owner-subject' and issuer='https://id.example.edu'`).Scan(&ownerStatus); err != nil || ownerStatus != "active" {
		t.Fatal("historical retry reapplied suspension", err)
	}
	var events int
	if err := db.DB.QueryRowContext(ctx, `select count(*) from control_outbox where topic in('device.revoked','runtime_grant.revoked')`).Scan(&events); err != nil || events != 3 {
		t.Fatal("revocation events missing or repeated", events, err)
	}
}

func TestIdentitySyncMembershipLossRetiresOnlyAffectedGrants(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	seedGrantFixture(t, ctx, db.DB)
	if _, err := db.DB.ExecContext(ctx, `insert into runtime_grants(runtime_id,user_id,role,scope,granted_by) values('55555555-5555-4555-8555-555555555555','66666666-6666-4666-8666-666666666666','viewer','{"actions":["host.list"],"workspaces":[],"sessions":[]}','22222222-2222-4222-8222-222222222222')`); err != nil {
		t.Fatal(err)
	}
	base := identitySnapshotFixture(t, 1)
	if _, err := db.ApplyIdentitySnapshot(ctx, base.DatabaseEpoch, base.Issuer, base); err != nil {
		t.Fatal(err)
	}
	lost := identitySnapshotFixture(t, 2)
	lost.Users[1].Memberships = []RecoveryMembership{}
	run, err := db.ApplyIdentitySnapshot(ctx, lost.DatabaseEpoch, lost.Issuer, lost)
	if err != nil || run.Counts["grants_revoked"] != 1 || run.Counts["installations_revoked"] != 0 || run.Counts["devices_revoked"] != 0 {
		t.Fatal("membership loss widened revocation", run, err)
	}
	if err := assertGrantState(ctx, db.DB, "55555555-5555-4555-8555-555555555555", "22222222-2222-4222-8222-222222222222", 1, "owner", false); err != nil {
		t.Fatal(err)
	}
	if err := assertGrantState(ctx, db.DB, "55555555-5555-4555-8555-555555555555", "66666666-6666-4666-8666-666666666666", 2, "viewer", true); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ApplyIdentitySnapshot(ctx, OriginalDatabaseEpoch, base.Issuer, identitySnapshotFixture(t, 3)); err != nil {
		t.Fatal(err)
	}
	if err := assertGrantState(ctx, db.DB, "55555555-5555-4555-8555-555555555555", "66666666-6666-4666-8666-666666666666", 2, "viewer", true); err != nil {
		t.Fatal("readded membership revived grant", err)
	}
}

func TestIdentitySyncRollsBackFailedAuditAndRejectsStaleOrDeletedAuthority(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	seedGrantFixture(t, ctx, db.DB)
	base := identitySnapshotFixture(t, 1)
	if _, err := db.ApplyIdentitySnapshot(ctx, base.DatabaseEpoch, base.Issuer, base); err != nil {
		t.Fatal(err)
	}
	next := identitySnapshotFixture(t, 2)
	next.Users = []RecoveryUser{}
	if _, err := db.DB.ExecContext(ctx, `create function fail_identity_sync() returns trigger language plpgsql as $$ begin if new.action='identity.sync' then raise exception 'PRIVATE_SYNC_AUDIT';end if;return new;end $$;create trigger fail_identity_sync before insert on audit_log for each row execute function fail_identity_sync()`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ApplyIdentitySnapshot(ctx, next.DatabaseEpoch, next.Issuer, next); err == nil || strings.Contains(err.Error(), "PRIVATE_SYNC_AUDIT") {
		t.Fatal("failed audit accepted or leaked", err)
	}
	var preserved bool
	if err := db.DB.QueryRowContext(ctx, `select (select count(*)=3 from users where status='active') and (select count(*)=0 from devices where revoked_at is not null) and (select revision=1 from identity_sync_sources) and (select count(*)=1 from identity_sync_runs) and (select count(*)=0 from control_outbox)`).Scan(&preserved); err != nil || !preserved {
		t.Fatal("failed synchronization partially committed", err)
	}
	if _, err := db.DB.ExecContext(ctx, `drop trigger fail_identity_sync on audit_log;drop function fail_identity_sync();
	 create function fail_identity_outbox() returns trigger language plpgsql as $$ begin raise exception 'PRIVATE_SYNC_OUTBOX';end $$;
	 create trigger fail_identity_outbox before insert on control_outbox for each row execute function fail_identity_outbox()`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ApplyIdentitySnapshot(ctx, next.DatabaseEpoch, next.Issuer, next); err == nil || strings.Contains(err.Error(), "PRIVATE_SYNC_OUTBOX") {
		t.Fatal("failed outbox accepted or leaked", err)
	}
	if err := db.DB.QueryRowContext(ctx, `select (select count(*)=3 from users where status='active') and (select count(*)=0 from devices where revoked_at is not null) and (select revision=1 from identity_sync_sources) and (select count(*)=1 from identity_sync_runs)`).Scan(&preserved); err != nil || !preserved {
		t.Fatal("failed outbox partially committed", err)
	}
	if _, err := db.DB.ExecContext(ctx, `drop trigger fail_identity_outbox on control_outbox;drop function fail_identity_outbox();update users set status='deleted' where subject='target-subject'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ApplyIdentitySnapshot(ctx, base.DatabaseEpoch, base.Issuer, identitySnapshotFixture(t, 2)); !errors.Is(err, ErrIdentitySyncConflict) {
		t.Fatal("deleted subject reactivated", err)
	}
	stale := identitySnapshotFixture(t, 1)
	if _, err := db.ApplyIdentitySnapshot(ctx, stale.DatabaseEpoch, stale.Issuer, stale); !errors.Is(err, ErrIdentitySyncConflict) {
		t.Fatal("stale revision accepted", err)
	}
	expired := identitySnapshotFixture(t, 2)
	expired.CapturedAt = time.Now().Add(-500 * time.Millisecond)
	expired.ExpiresAt = time.Now().Add(-100 * time.Millisecond)
	if _, err := db.ApplyIdentitySnapshot(ctx, expired.DatabaseEpoch, expired.Issuer, expired); !errors.Is(err, ErrIdentitySnapshot) {
		t.Fatal("expired snapshot accepted", err)
	}
	wrong := identitySnapshotFixture(t, 2)
	wrong.DatabaseEpoch = approvalTestUUID(t)
	if _, err := db.ApplyIdentitySnapshot(ctx, wrong.DatabaseEpoch, wrong.Issuer, wrong); !errors.Is(err, ErrRecoveryUnavailable) {
		t.Fatal("restored epoch accepted old authority", err)
	}
	down, err := os.ReadFile("../../../../deploy/sql/032_identity_sync.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.DB.ExecContext(ctx, string(down)); err == nil {
		t.Fatal("rollback discarded identity receipts")
	}
	// Failed explicit BEGIN scripts leave the session in a failed transaction.
	_, _ = db.DB.ExecContext(ctx, `rollback`)
}

func TestIdentitySyncOmissionAndAdministrativeDowngradeRetireOldAuthority(t *testing.T) {
	for _, mode := range []string{"omitted", "membership_removed", "admin_downgraded"} {
		t.Run(mode, func(t *testing.T) {
			ctx, db := newPostgresIntegrationDatabase(t)
			seedGrantFixture(t, ctx, db.DB)
			base := identitySnapshotFixture(t, 1)
			if mode == "admin_downgraded" {
				base.Users[0].Memberships[0].Role = "admin"
			}
			if _, err := db.ApplyIdentitySnapshot(ctx, base.DatabaseEpoch, base.Issuer, base); err != nil {
				t.Fatal(err)
			}
			next := identitySnapshotFixture(t, 2)
			if mode == "omitted" {
				next.Users = next.Users[1:]
			} else if mode == "membership_removed" {
				next.Users[0].Memberships = []RecoveryMembership{}
			}
			run, err := db.ApplyIdentitySnapshot(ctx, next.DatabaseEpoch, next.Issuer, next)
			if err != nil {
				t.Fatal(err)
			}
			if run.Counts["grants_revoked"] != 1 {
				t.Fatal("old grant survived identity authority loss", run.Counts)
			}
			wantDevices, wantInstallations := int64(0), int64(1)
			if mode == "omitted" {
				wantDevices = 1
			}
			if mode == "admin_downgraded" {
				wantInstallations = 0
			}
			if run.Counts["devices_revoked"] != wantDevices || run.Counts["installations_revoked"] != wantInstallations {
				t.Fatal("identity loss crossed resource boundaries", run.Counts)
			}
		})
	}
}

func TestIdentitySyncConcurrentRevisionsHaveOneCommittedWinner(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	first, second := identitySnapshotFixture(t, 1), identitySnapshotFixture(t, 1)
	var group sync.WaitGroup
	results := make(chan error, 2)
	for _, s := range []IdentitySnapshot{first, second} {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := db.ApplyIdentitySnapshot(ctx, s.DatabaseEpoch, s.Issuer, s)
			results <- err
		}()
	}
	group.Wait()
	close(results)
	winners, conflicts := 0, 0
	for err := range results {
		if err == nil {
			winners++
		} else if errors.Is(err, ErrIdentitySyncConflict) {
			conflicts++
		} else {
			t.Fatal("unexpected concurrency failure", err)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatal("concurrent snapshots both applied", winners, conflicts)
	}
}

func TestIdentitySyncConcurrentExactRetriesReturnTheSameReceipt(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	snapshot := identitySnapshotFixture(t, 1)
	type result struct {
		run IdentitySyncRun
		err error
	}
	results := make(chan result, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			run, err := db.ApplyIdentitySnapshot(ctx, snapshot.DatabaseEpoch, snapshot.Issuer, snapshot)
			results <- result{run, err}
		}()
	}
	group.Wait()
	close(results)
	var first *IdentitySyncRun
	for value := range results {
		if value.err != nil {
			t.Fatal("exact concurrent retry failed", value.err)
		}
		if first == nil {
			first = &value.run
		} else if !reflect.DeepEqual(*first, value.run) {
			t.Fatal("concurrent retry returned a different receipt")
		}
	}
	var receipts int
	if err := db.DB.QueryRowContext(ctx, `select count(*) from identity_sync_runs`).Scan(&receipts); err != nil || receipts != 1 {
		t.Fatal("concurrent retry duplicated the operation", err)
	}
}

func TestIdentitySyncRetiresRegistrationCommittedWhileWaitingForUserFence(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	seedGrantFixture(t, ctx, db.DB)
	if _, err := db.DB.ExecContext(ctx, `create function hold_racing_registration() returns trigger language plpgsql as $$ begin if new.name='racing registration' then perform pg_advisory_xact_lock(426932);end if;return new;end $$;create trigger hold_racing_registration before insert on devices for each row execute function hold_racing_registration()`); err != nil {
		t.Fatal(err)
	}
	gate, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback()
	if _, err = gate.ExecContext(ctx, `select pg_advisory_xact_lock(426932)`); err != nil {
		t.Fatal(err)
	}
	type registrationResult struct {
		id  string
		err error
	}
	registered := make(chan registrationResult, 1)
	go func() {
		id, err := db.RegisterDevice(ctx, DeviceRegistration{Issuer: "https://id.example.edu", Subject: "owner-subject", Name: "racing registration", ApprovalPublicJWK: []byte(`{}`), ProofPublicJWK: []byte(`{}`), ApprovalKeyThumbprint: "racing-approval", ProofKeyThumbprint: "racing-proof"})
		registered <- registrationResult{id, err}
	}()
	waitForLock := func(fragment string) {
		t.Helper()
		deadline := time.NewTimer(3 * time.Second)
		defer deadline.Stop()
		ticks := time.NewTicker(10 * time.Millisecond)
		defer ticks.Stop()
		for {
			var waiting bool
			if err := db.DB.QueryRowContext(ctx, `select exists(select 1 from pg_stat_activity where datname=current_database() and wait_event_type='Lock' and query like $1)`, "%"+fragment+"%").Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				return
			}
			select {
			case <-ticks.C:
			case <-deadline.C:
				t.Fatal("expected authority lock was not observed")
			}
		}
	}
	waitForLock("insert into devices")
	snapshot := identitySnapshotFixture(t, 1)
	snapshot.Users[0].Status = "suspended"
	snapshot.Users[0].Memberships = []RecoveryMembership{}
	type syncResult struct {
		run IdentitySyncRun
		err error
	}
	synced := make(chan syncResult, 1)
	go func() {
		run, err := db.ApplyIdentitySnapshot(ctx, snapshot.DatabaseEpoch, snapshot.Issuer, snapshot)
		synced <- syncResult{run, err}
	}()
	waitForLock("identity_sync_user_fence")
	if err = gate.Commit(); err != nil {
		t.Fatal(err)
	}
	registration := <-registered
	if registration.err != nil {
		t.Fatal("racing registration failed before synchronization", registration.err)
	}
	result := <-synced
	if result.err != nil || result.run.Counts["devices_revoked"] != 2 {
		t.Fatal("synchronization missed a registration committed during its wait", result.run.Counts, result.err)
	}
	var revoked bool
	if err := db.DB.QueryRowContext(ctx, `select revoked_at is not null from devices where id=$1`, registration.id).Scan(&revoked); err != nil || !revoked {
		t.Fatal("late old-identity registration survived", err)
	}
}
