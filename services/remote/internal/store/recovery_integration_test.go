package store

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
)

func TestRecoveryAcrossActualClusterRestoreFencesAuthorityAndPreservesHistory(t *testing.T) {
	ctx, source := newPostgresIntegrationDatabase(t)
	jkt := seedGrantFixture(t, ctx, source.DB)
	const runtimeID = "55555555-5555-4555-8555-555555555555"
	const deviceID = "44444444-4444-4444-8444-444444444444"
	const installationID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	const orgID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	const userID = "22222222-2222-4222-8222-222222222222"
	operation, epoch := approvalTestUUID(t), approvalTestUUID(t)
	consumer, err := source.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	first := insertConsumerEvent(t, ctx, source.DB)
	_ = insertConsumerEvent(t, ctx, source.DB)
	if err := consumer.MarkControlEventPublished(ctx, first); err != nil {
		t.Fatal(err)
	}
	scope, err := auth.ProofScope("https://id.example.edu", "urn:recovery-test", "https://remote.example.edu")
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := NewPostgresProofStore(ctx, source.DB, scope, 64)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := proofs.Challenge(ctx, jkt)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := source.IssueRealtimeTicket(ctx, UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}, deviceID, runtimeID, GrantScope{Actions: []string{"host.list"}, Workspaces: []string{}, Sessions: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	hostToken := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	hostDigest := sha256.Sum256([]byte(hostToken))
	if _, err := source.DB.ExecContext(ctx, `insert into host_connection_credentials(token_sha256,installation_id,key_version,expires_at) values($1,$2,1,clock_timestamp()+interval '5 minutes')`, hostDigest[:], installationID); err != nil {
		t.Fatal(err)
	}
	if _, err := source.DB.ExecContext(ctx, `insert into commands(device_id,request_id,user_id,runtime_id,session_id,payload_sha256,state) values($1,$2,$3,$4,'99999999-9999-4999-8999-999999999999',repeat('a',64),'host_accepted')`, deviceID, approvalTestUUID(t), userID, runtimeID); err != nil {
		t.Fatal(err)
	}
	restoredCtx, db, _ := testsupport.RestoredPostgresDatabase(t, source.DB)
	restored := &Postgres{DB: db}
	// These facts occurred after the backup; the restored copy has neither.
	if result, err := proofs.ConsumeAndRotate(ctx, jkt, "post-backup-proof-00000001", nonce, time.Now().Add(time.Minute)); err != nil || !result.Accepted {
		t.Fatal(err)
	}
	if _, err := source.DB.ExecContext(ctx, `update devices set revoked_at=clock_timestamp() where id=$1`, deviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := source.DB.ExecContext(ctx, `update runtime_grants set revoked_at=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	var resurrected bool
	if err := db.QueryRowContext(restoredCtx, `select d.revoked_at is null and g.revoked_at is null from devices d,runtime_grants g where d.id=$1`, deviceID).Scan(&resurrected); err != nil || !resurrected {
		t.Fatal("fixture did not restore old authority", err)
	}
	oldGuard, err := restored.NewRecoveryGuard(restoredCtx, OriginalDatabaseEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restored.NewRecoveryGuard(restoredCtx, epoch); !errors.Is(err, ErrRecoveryUnavailable) {
		t.Fatal("external epoch admitted restored old database", err)
	}
	var oldEvents, oldAcks, oldProofs int
	for _, check := range []struct {
		query  string
		target *int
	}{{`select count(*) from control_outbox`, &oldEvents}, {`select count(*) from control_event_acks`, &oldAcks}, {`select count(*) from dpop_proof_entries`, &oldProofs}} {
		if err := db.QueryRowContext(restoredCtx, check.query).Scan(check.target); err != nil {
			t.Fatal(err)
		}
	}
	run, err := restored.QuarantineRecovery(restoredCtx, operation, OriginalDatabaseEpoch, epoch)
	if err != nil {
		t.Fatal("quarantine", err)
	}
	if run.Phase != "quarantined" || run.Counts["devices"] != 2 || run.Counts["grants"] != 1 {
		t.Fatal("quarantine omitted active authority", run.Counts)
	}
	if err := oldGuard.Check(restoredCtx); !errors.Is(err, ErrRecoveryUnavailable) {
		t.Fatal("old deployment stayed ready", err)
	}
	reached := false
	w := httptest.NewRecorder()
	oldGuard.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })).ServeHTTP(w, httptest.NewRequest("POST", "/v1/devices", nil))
	if reached || w.Code != 503 {
		t.Fatal("quarantined handler ran")
	}
	if _, err := restored.NewRecoveryGuard(restoredCtx, epoch); !errors.Is(err, ErrRecoveryUnavailable) {
		t.Fatal("new epoch bypassed authority resync", err)
	}
	if _, err := restored.NewControlConsumer(restoredCtx, controlNodeB); !errors.Is(err, ErrRecoveryUnavailable) {
		t.Fatal("consumer started in quarantine", err)
	}
	if _, err := restored.PrepareRealtimeTicket(restoredCtx, ticket.Token); err == nil {
		t.Fatal("old ticket survived quarantine")
	}
	if _, err := restored.LookupHostConnectionCredential(restoredCtx, hostToken); err == nil {
		t.Fatal("old host credential survived quarantine")
	}
	var unknown int
	if err := db.QueryRowContext(restoredCtx, `select count(*) from commands where state='outcome_unknown'`).Scan(&unknown); err != nil || unknown != 1 {
		t.Fatal("uncertain command became replayable", err)
	}
	for _, check := range []struct {
		query    string
		expected int
	}{{`select count(*) from control_outbox`, oldEvents}, {`select count(*) from control_event_acks`, oldAcks}, {`select count(*) from dpop_proof_entries`, oldProofs}} {
		var count int
		if err := db.QueryRowContext(restoredCtx, check.query).Scan(&count); err != nil || count != check.expected {
			t.Fatal("recovery deleted security history", err)
		}
	}
	authority := RecoveryAuthority{Version: 1, Complete: true, RecoveryID: operation, DatabaseEpoch: epoch, Issuer: "https://id.example.edu", CapturedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(5 * time.Minute).UTC(), Users: []RecoveryUser{
		{Subject: "owner-subject", Status: "suspended", Memberships: []RecoveryMembership{}},
		{Subject: "target-subject", Status: "active", Memberships: []RecoveryMembership{{OrganizationID: orgID, Role: "admin"}}},
	}}
	stale := authority
	stale.CapturedAt = run.PreparedAt.Add(-time.Second)
	if _, err := restored.ReleaseRecovery(restoredCtx, epoch, authority.Issuer, stale); !errors.Is(err, ErrRecoveryAuthority) {
		t.Fatal("pre-backup authority snapshot accepted", err)
	}
	wrongOrg := authority
	wrongOrg.Users = []RecoveryUser{{Subject: "new-user", Status: "active", Memberships: []RecoveryMembership{{OrganizationID: approvalTestUUID(t), Role: "member"}}}}
	if _, err := restored.ReleaseRecovery(restoredCtx, epoch, authority.Issuer, wrongOrg); err == nil {
		t.Fatal("unknown organization partially released recovery")
	}
	var leaked int
	if err := db.QueryRowContext(restoredCtx, `select count(*) from users where subject='new-user'`).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatal("failed release committed partial identity", err)
	}
	released, err := restored.ReleaseRecovery(restoredCtx, epoch, authority.Issuer, authority)
	if err != nil || released.Phase != "ready" {
		t.Fatal("fresh authority release", err)
	}
	guard, err := restored.NewRecoveryGuard(restoredCtx, epoch)
	if err != nil || guard.TokenNotBefore().IsZero() {
		t.Fatal("new deployment cannot start after resync", err)
	}
	if _, err := restored.NewRecoveryGuard(restoredCtx, ""); !errors.Is(err, ErrRecoveryUnavailable) {
		t.Fatal("omitted deployment epoch bypassed fence", err)
	}
	var memberships, revoked int
	if err := db.QueryRowContext(restoredCtx, `select count(*) from org_memberships where user_id='22222222-2222-4222-8222-222222222222'`).Scan(&memberships); err != nil || memberships != 0 {
		t.Fatal("old membership came back", err)
	}
	if err := db.QueryRowContext(restoredCtx, `select count(*) from runtime_grants where revoked_at is not null`).Scan(&revoked); err != nil || revoked != 1 {
		t.Fatal("identity sync reactivated old grants", err)
	}
	newScope, err := auth.ProofScopeInEpoch(scope, epoch)
	if err != nil {
		t.Fatal(err)
	}
	newProofs, err := NewPostgresProofStore(restoredCtx, db, newScope, 64)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := newProofs.ConsumeAndRotate(restoredCtx, jkt, "post-backup-proof-00000001", nonce, time.Now().Add(time.Minute)); err != nil || result.Accepted {
		t.Fatal("restored consumed nonce replayed in new epoch", err)
	}
	newConsumer, err := restored.NewControlConsumer(restoredCtx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	if events, err := newConsumer.PendingControlEvents(restoredCtx, 128); err != nil || len(events) != 0 {
		t.Fatal("foreign history snapshot replayed old events", err)
	}
	current := insertConsumerEvent(t, restoredCtx, db)
	if ids := consumerPendingIDs(t, restoredCtx, newConsumer, 128); len(ids) != 1 || !ids[current] {
		t.Fatal("new epoch event was lost", ids)
	}
	if err := newConsumer.MarkControlEventPublished(restoredCtx, first); !errors.Is(err, ErrGrantInvalid) {
		t.Fatal("new epoch acknowledged old history", err)
	}
	if err := newConsumer.MarkControlEventPublished(restoredCtx, current); err != nil {
		t.Fatal(err)
	}
	if _, err := restored.QuarantineRecovery(restoredCtx, operation, OriginalDatabaseEpoch, epoch); err != nil {
		t.Fatal("idempotent reconciliation failed", err)
	}
	if err := guard.Check(restoredCtx); err != nil {
		t.Fatal("old prepare retry requarantined released state", err)
	}
	down, err := os.ReadFile("../../../../deploy/sql/021_recovery_epochs.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(restoredCtx, string(down)); err == nil {
		t.Fatal("migration rollback erased an established recovery epoch")
	}
	if err := guard.Check(restoredCtx); err != nil {
		t.Fatal("rejected rollback changed current recovery state", err)
	}
	if _, err := restored.ReleaseRecovery(restoredCtx, epoch, authority.Issuer, authority); err != nil {
		t.Fatal("same release result was not reconcilable", err)
	}
	changed := authority
	changed.Complete = false
	if _, err := restored.ReleaseRecovery(restoredCtx, epoch, authority.Issuer, changed); err == nil {
		t.Fatal("changed release manifest was accepted")
	}
}

func TestRecoveryFailedPreparationRollsBackEveryAuthorityChange(t *testing.T) {
	ctx, postgres := newPostgresIntegrationDatabase(t)
	seedGrantFixture(t, ctx, postgres.DB)
	locked, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer locked.Rollback()
	if _, err := locked.ExecContext(ctx, `select id from devices for update`); err != nil {
		t.Fatal(err)
	}
	deadline, cancel := context.WithTimeout(ctx, 40*time.Millisecond)
	_, err = postgres.QuarantineRecovery(deadline, approvalTestUUID(t), OriginalDatabaseEpoch, approvalTestUUID(t))
	cancel()
	if err == nil {
		t.Fatal("preparation bypassed held authority lock")
	}
	if err := locked.Rollback(); err != nil {
		t.Fatal(err)
	}
	state, err := postgres.RecoveryStatus(ctx)
	if err != nil || state.Phase != "ready" || state.Epoch != OriginalDatabaseEpoch {
		t.Fatal("failed preparation committed quarantine", state, err)
	}
	var revoked, runs int
	if err := postgres.DB.QueryRowContext(ctx, `select (select count(*) from devices where revoked_at is not null),(select count(*) from remote_recovery_runs)`).Scan(&revoked, &runs); err != nil || revoked != 0 || runs != 0 {
		t.Fatal("failed preparation changed state", err)
	}
}
