package store

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

func connectionLimitFixture(t *testing.T, limits ConnectionLimits) (context.Context, *Postgres, TicketRedemption, *ControlConsumer, *RelayDirectory, *RelayDirectory) {
	t.Helper()
	ctx, db, ticket := commandDeadlineFixture(t)
	if err := db.ConfigureConnectionLimits(ctx, limits); err != nil {
		t.Fatal(err)
	}
	a, err := db.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	left, err := a.NewRelayDirectory(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := db.NewControlConsumer(ctx, controlNodeB)
	if err != nil {
		t.Fatal(err)
	}
	right, err := b.NewRelayDirectory(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Release(ctx); _ = a.Release(ctx) })
	return ctx, db, ticket, a, left, right
}
func connectionLimitsForTest() ConnectionLimits { return ConnectionLimits{1, 10, 10, 10, 10, 4} }
func quotaHostInput(t *testing.T, ticket TicketRedemption) RuntimeConnectionInput {
	return RuntimeConnectionInput{InstallationID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", KeyVersion: 1, RuntimeID: ticket.RuntimeID, RuntimeEpoch: approvalTestUUID(t), ConnectionID: approvalTestUUID(t), DSHVersion: "0.2.1-rc.2", ApplicationVersion: "fixture", PluginVersion: "fixture", ProtocolVersion: 1}
}

func TestSharedConnectionLimitsCountAcrossNodesAndReleaseExactLease(t *testing.T) {
	for _, kind := range []string{"total", "user", "device", "installation"} {
		t.Run(kind, func(t *testing.T) {
			limits := connectionLimitsForTest()
			switch kind {
			case "total":
				limits.Total = 1
				limits.User = 1
				limits.Device = 1
				limits.Installation = 1
			case "user":
				limits.User = 1
			case "device":
				limits.Device = 1
			case "installation":
				limits.Installation = 1
			}
			ctx, db, ticket, _, left, right := connectionLimitFixture(t, limits)
			id := approvalTestUUID(t)
			if err := left.ClaimDeviceConnection(ctx, ticket, id, time.Now().Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			if err := right.ClaimDeviceConnection(ctx, ticket, approvalTestUUID(t), time.Now().Add(time.Minute)); !errors.Is(err, ErrConnectionLimit) {
				t.Fatal("shared connection cap was bypassed", kind, err)
			}
			if err := right.ReleaseDeviceConnection(ctx, id); err != nil {
				t.Fatal(err)
			}
			var count int
			if err := db.DB.QueryRowContext(ctx, `select count(*) from realtime_device_connections`).Scan(&count); err != nil || count != 1 {
				t.Fatal("foreign node removed lease", count, err)
			}
			if err := left.ReleaseDeviceConnection(ctx, id); err != nil {
				t.Fatal(err)
			}
			if err := right.ClaimDeviceConnection(ctx, ticket, approvalTestUUID(t), time.Now().Add(time.Minute)); err != nil {
				t.Fatal("released capacity did not become available", err)
			}
		})
	}
}

func TestConnectionLimitsCountHostsAndPreserveOldHostOnFailedAttach(t *testing.T) {
	limits := connectionLimitsForTest()
	limits.Installation = 2
	ctx, db, ticket, _, left, right := connectionLimitFixture(t, limits)
	input := quotaHostInput(t, ticket)
	if _, err := left.AttachRuntimeConnection(ctx, input); err != nil {
		t.Fatal(err)
	}
	if err := right.ClaimDeviceConnection(ctx, ticket, approvalTestUUID(t), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := left.ClaimDeviceConnection(ctx, ticket, approvalTestUUID(t), time.Now().Add(time.Minute)); !errors.Is(err, ErrConnectionLimit) {
		t.Fatal("host did not share installation capacity", err)
	}
	next := input
	next.RuntimeID = approvalTestUUID(t)
	next.ConnectionID = approvalTestUUID(t)
	next.RuntimeEpoch = approvalTestUUID(t)
	if _, err := db.DB.ExecContext(ctx, `insert into runtimes(id,installation_id,profile_ref,protocol_version) values($1,$2,'quota-sibling',1)`, next.RuntimeID, next.InstallationID); err != nil {
		t.Fatal(err)
	}
	if _, err := right.AttachRuntimeConnection(ctx, next); !errors.Is(err, ErrConnectionLimit) {
		t.Fatal("sibling host bypassed installation cap", err)
	}
	var connection string
	if err := db.DB.QueryRowContext(ctx, `select connection_id::text from runtimes where id=$1`, input.RuntimeID).Scan(&connection); err != nil || connection != input.ConnectionID {
		t.Fatal("rejected attach changed original host", connection, err)
	}
	replacement := input
	replacement.ConnectionID = approvalTestUUID(t)
	replacement.RuntimeEpoch = approvalTestUUID(t)
	if _, err := right.AttachRuntimeConnection(ctx, replacement); err != nil {
		t.Fatal("same-runtime replacement needed a second host slot", err)
	}
	if err := left.DetachRuntimeConnection(ctx, input.InstallationID, input.RuntimeID, input.RuntimeEpoch, input.ConnectionID); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRowContext(ctx, `select connection_id::text from runtimes where id=$1`, input.RuntimeID).Scan(&connection); err != nil || connection != replacement.ConnectionID {
		t.Fatal("old cleanup erased replacement", connection, err)
	}
}

func TestConnectionLimitsConcurrentClaimsCannotOverspendAndExpireWithNodeGeneration(t *testing.T) {
	limits := connectionLimitsForTest()
	limits.Device = 2
	ctx, db, ticket, node, left, right := connectionLimitFixture(t, limits)
	results := make(chan error, 8)
	var wait sync.WaitGroup
	for index := range 8 {
		id := approvalTestUUID(t)
		wait.Go(func() {
			directory := left
			if index%2 == 1 {
				directory = right
			}
			results <- directory.ClaimDeviceConnection(ctx, ticket, id, time.Now().Add(time.Minute))
		})
	}
	wait.Wait()
	close(results)
	allowed, limited := 0, 0
	for err := range results {
		if err == nil {
			allowed++
		} else if errors.Is(err, ErrConnectionLimit) {
			limited++
		} else {
			t.Fatal(err)
		}
	}
	if allowed != 2 || limited != 6 {
		t.Fatal("concurrent claims overspent", allowed, limited)
	}
	if err := node.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `update control_consumers set lease_until=clock_timestamp()-interval '1 second' where node_id=$1`, controlNodeB); err != nil {
		t.Fatal(err)
	}
	restarted, err := db.NewControlConsumer(ctx, controlNodeB)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Release(ctx)
	fresh, err := restarted.NewRelayDirectory(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.ClaimDeviceConnection(ctx, ticket, approvalTestUUID(t), time.Now().Add(time.Minute)); err != nil {
		t.Fatal("stale node occupancy blocked fresh generation", err)
	}
	var count int
	if err := db.DB.QueryRowContext(ctx, `select count(*) from realtime_device_connections`).Scan(&count); err != nil || count != 1 {
		t.Fatal("stale occupancy was not boundedly removed", count, err)
	}
}

func TestConnectionLimitsRejectCurrentAuthorityPolicyDriftAndExpiredHostCredential(t *testing.T) {
	ctx, db, ticket, _, left, _ := connectionLimitFixture(t, connectionLimitsForTest())
	wrong := ticket
	wrong.DeviceKeyVersion++
	if err := left.ClaimDeviceConnection(ctx, wrong, approvalTestUUID(t), time.Now().Add(time.Minute)); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("stale proof created occupancy", err)
	}
	input := quotaHostInput(t, ticket)
	input.CredentialExpiresAt = time.Now().Add(-time.Minute)
	if _, err := left.AttachRuntimeConnection(ctx, input); !errors.Is(err, ErrHostCredentialInvalid) {
		t.Fatal("expired host credential attached", err)
	}
	if _, err := db.DB.ExecContext(ctx, `update realtime_connection_policy set policy_sha256=decode(repeat('00',32),'hex')`); err != nil {
		t.Fatal(err)
	}
	if err := left.ClaimDeviceConnection(ctx, ticket, approvalTestUUID(t), time.Now().Add(time.Minute)); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatal("connection policy drift fell back to unlimited", err)
	}
}

func TestConnectionLimitsProtectCapacityThroughCredentialAuditWaitAndMigration(t *testing.T) {
	ctx, db, ticket, _, left, _ := connectionLimitFixture(t, connectionLimitsForTest())
	input := quotaHostInput(t, ticket)
	if _, err := db.AttachRuntimeConnection(ctx, input); !errors.Is(err, ErrDatabaseConfig) {
		t.Fatal("configured quota used unowned library attach", err)
	}
	if _, err := db.DB.ExecContext(ctx, `create function hold_quota_attach_audit() returns trigger language plpgsql as $$ begin if new.action='host.runtime.connect' then perform pg_advisory_xact_lock(426964);end if;return new;end $$;create trigger hold_quota_attach_audit before insert on audit_log for each row execute function hold_quota_attach_audit()`); err != nil {
		t.Fatal(err)
	}
	gate, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback()
	if _, err := gate.ExecContext(ctx, `select pg_advisory_xact_lock(426964)`); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRowContext(ctx, `select clock_timestamp()+interval '600 milliseconds'`).Scan(&input.CredentialExpiresAt); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := left.AttachRuntimeConnection(ctx, input); result <- err }()
	waitForGrantLock(t, ctx, db, "insert into audit_log")
	waitForGrantDatabaseExpiry(t, ctx, db, input.CredentialExpiresAt)
	if err := gate.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrHostCredentialInvalid) {
		t.Fatal("expired host credential committed after audit wait", err)
	}
	var rows int
	if err := db.DB.QueryRowContext(ctx, `select count(*) from relay_runtime_routes`).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("expired attachment retained routing", rows, err)
	}
	for _, direction := range []string{"down", "up"} {
		raw, err := os.ReadFile("../../../../deploy/sql/041_connection_limits." + direction + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.ExecContext(ctx, string(raw)); err != nil {
			t.Fatal("empty quota migration could not round trip", direction, err)
		}
	}
}

func TestConnectionLimitsDoNotDropAnUnseenRenewalDuringCapacityLockWait(t *testing.T) {
	limits := connectionLimitsForTest()
	limits.Device = 1
	ctx, db, ticket, _, left, right := connectionLimitFixture(t, limits)
	if err := left.ClaimDeviceConnection(ctx, ticket, approvalTestUUID(t), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var expires time.Time
	if err := db.DB.QueryRowContext(ctx, `update control_consumers set lease_until=clock_timestamp()+interval '400 milliseconds' where node_id=$1 returning lease_until`, controlNodeA).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	gate, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback()
	if _, err := gate.ExecContext(ctx, `select 1 from realtime_connection_policy for share`); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- right.ClaimDeviceConnection(ctx, ticket, approvalTestUUID(t), time.Now().Add(time.Minute))
	}()
	waitForGrantLock(t, ctx, db, "update realtime_connection_policy")
	if _, err := db.DB.ExecContext(ctx, `update control_consumers set lease_until=clock_timestamp()+interval '10 seconds' where node_id=$1`, controlNodeA); err != nil {
		t.Fatal(err)
	}
	waitForGrantDatabaseExpiry(t, ctx, db, expires)
	if err := gate.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrConnectionLimit) {
		t.Fatal("unseen renewal freed an occupied device slot", err)
	}
	var count int
	if err := db.DB.QueryRowContext(ctx, `select count(*) from realtime_device_connections`).Scan(&count); err != nil || count != 1 {
		t.Fatal("cleanup deleted renewed occupancy", count, err)
	}
}

func TestConnectionLimitsDoNotRecreateMissingPolicyWhileHostOccupiesCapacity(t *testing.T) {
	ctx, db, ticket, _, left, _ := connectionLimitFixture(t, connectionLimitsForTest())
	if _, err := left.AttachRuntimeConnection(ctx, quotaHostInput(t, ticket)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `delete from realtime_connection_policy`); err != nil {
		t.Fatal(err)
	}
	newNode := &Postgres{DB: db.DB}
	if err := newNode.ConfigureConnectionLimits(ctx, connectionLimitsForTest()); err == nil {
		t.Fatal("missing policy was recreated with existing Host occupancy")
	}
}
