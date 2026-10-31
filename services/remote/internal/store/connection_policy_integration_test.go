package store

import (
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

func connectionPolicyHash(t *testing.T, limits ConnectionLimits) string {
	t.Helper()
	digest, err := limits.PolicyDigest()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(digest[:])
}

func TestConnectionPolicyReplacementRetainsOccupancyAndHistoricalReceipts(t *testing.T) {
	limits := connectionLimitsForTest()
	ctx, db, ticket, leftConsumer, left, right := connectionLimitFixture(t, limits)
	if err := left.ClaimDeviceConnection(ctx, ticket, approvalTestUUID(t), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := left.AttachRuntimeConnection(ctx, quotaHostInput(t, ticket)); err != nil {
		t.Fatal(err)
	}
	status, err := db.ConnectionPolicyStatus(ctx, OriginalDatabaseEpoch)
	if err != nil || status.Policy == nil || *status.Policy != limits || status.ActiveConsumers != 2 || !status.OccupancyRetained {
		t.Fatal("connection policy status incorrect", status, err)
	}
	updated := limits
	updated.Device--
	id, expected := approvalTestUUID(t), connectionPolicyHash(t, limits)
	if _, err := db.ReplaceConnectionPolicy(ctx, OriginalDatabaseEpoch, id, expected, updated); !errors.Is(err, ErrConnectionPolicyBusy) {
		t.Fatal("live nodes allowed connection policy change", err)
	}
	if err := leftConsumer.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if err := right.consumer.Release(ctx); err != nil {
		t.Fatal(err)
	}
	var before, after string
	snapshot := func(target *string) {
		t.Helper()
		if err := db.DB.QueryRowContext(ctx, `select jsonb_build_object('devices',(select jsonb_agg(to_jsonb(c) order by connection_id) from realtime_device_connections c),'routes',(select jsonb_agg(to_jsonb(r) order by runtime_id) from relay_runtime_routes r))::text`).Scan(target); err != nil {
			t.Fatal(err)
		}
	}
	snapshot(&before)
	first, err := db.ReplaceConnectionPolicy(ctx, OriginalDatabaseEpoch, id, expected, updated)
	if err != nil || first.Policy != updated || first.PolicySHA256 != connectionPolicyHash(t, updated) {
		t.Fatal("drained replacement failed", first, err)
	}
	snapshot(&after)
	if after != before {
		t.Fatal("replacement changed retained occupancy")
	}
	newer := updated
	newer.PendingHandshakes++
	if _, err := db.ReplaceConnectionPolicy(ctx, OriginalDatabaseEpoch, approvalTestUUID(t), first.PolicySHA256, newer); err != nil {
		t.Fatal(err)
	}
	consumer, err := db.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Release(ctx)
	replay, err := db.ReplaceConnectionPolicy(ctx, OriginalDatabaseEpoch, id, expected, updated)
	if err != nil || replay != first {
		t.Fatal("online historical replay changed receipt", replay, err)
	}
	status, err = db.ConnectionPolicyStatus(ctx, OriginalDatabaseEpoch)
	if err != nil || status.Policy == nil || *status.Policy != newer || status.ActiveConsumers != 1 {
		t.Fatal("historical replay rewound policy", status, err)
	}
	var changes, audits int
	if err := db.DB.QueryRowContext(ctx, `select (select count(*) from realtime_connection_policy_changes),(select count(*) from audit_log where action='connection_policy.replace')`).Scan(&changes, &audits); err != nil || changes != 2 || audits != 2 {
		t.Fatal("policy evidence repeated", changes, audits, err)
	}
}

func TestConnectionPolicyCASRecoveryAndAtomicFailureBoundaries(t *testing.T) {
	for _, failure := range []string{"stale", "audit", "update", "epoch"} {
		t.Run(failure, func(t *testing.T) {
			limits := connectionLimitsForTest()
			ctx, db, _, a, _, right := connectionLimitFixture(t, limits)
			_ = a.Release(ctx)
			_ = right.consumer.Release(ctx)
			updated := limits
			updated.Device--
			epoch, expected := OriginalDatabaseEpoch, connectionPolicyHash(t, limits)
			want := ErrConnectionPolicyConflict
			if failure == "stale" {
				expected = connectionPolicyHash(t, updated)
				want = ErrConnectionPolicyConflict
			}
			if failure == "epoch" {
				epoch = approvalTestUUID(t)
				want = ErrRecoveryUnavailable
			}
			if failure == "audit" {
				want = ErrDatabaseUnavailable
				if _, err := db.DB.ExecContext(ctx, `create function fail_connection_policy() returns trigger language plpgsql as $$ begin if new.action='connection_policy.replace' then raise exception 'fixture';end if;return new;end $$;create trigger fail_connection_policy before insert on audit_log for each row execute function fail_connection_policy()`); err != nil {
					t.Fatal(err)
				}
			}
			if failure == "update" {
				want = ErrDatabaseUnavailable
				if _, err := db.DB.ExecContext(ctx, `create function fail_connection_policy() returns trigger language plpgsql as $$ begin return null;end $$;create trigger fail_connection_policy before update on realtime_connection_policy for each row execute function fail_connection_policy()`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.ReplaceConnectionPolicy(ctx, epoch, approvalTestUUID(t), expected, updated); !errors.Is(err, want) {
				t.Fatal("replacement failure changed result", failure, err)
			}
			status, err := db.ConnectionPolicyStatus(ctx, OriginalDatabaseEpoch)
			if err != nil || status.Policy == nil || *status.Policy != limits {
				t.Fatal("failed replacement changed policy", status, err)
			}
			var count int
			if err := db.DB.QueryRowContext(ctx, `select count(*) from realtime_connection_policy_changes`).Scan(&count); err != nil || count != 0 {
				t.Fatal("failed replacement wrote evidence", count, err)
			}
		})
	}
}

func TestConnectionPolicyConcurrentCASImmutableEvidenceAndMigration(t *testing.T) {
	limits := connectionLimitsForTest()
	ctx, db, _, a, _, right := connectionLimitFixture(t, limits)
	_ = a.Release(ctx)
	_ = right.consumer.Release(ctx)
	updated := limits
	updated.Device--
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		id := approvalTestUUID(t)
		wait.Go(func() {
			_, err := db.ReplaceConnectionPolicy(ctx, OriginalDatabaseEpoch, id, connectionPolicyHash(t, limits), updated)
			results <- err
		})
	}
	wait.Wait()
	close(results)
	allowed, conflicts := 0, 0
	for err := range results {
		if err == nil {
			allowed++
		} else if errors.Is(err, ErrConnectionPolicyConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if allowed != 1 || conflicts != 1 {
		t.Fatal("concurrent connection CAS overspent", allowed, conflicts)
	}
	for _, query := range []string{`update realtime_connection_policy_changes set changed_at=clock_timestamp()`, `delete from realtime_connection_policy_changes`} {
		if _, err := db.DB.ExecContext(ctx, query); err == nil {
			t.Fatal("connection policy evidence was mutable")
		}
	}
	raw, err := os.ReadFile("../../../../deploy/sql/043_connection_policy_changes.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	connection, err := db.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, rollbackErr := connection.ExecContext(ctx, string(raw))
	_, err = connection.ExecContext(ctx, `rollback`)
	_ = connection.Close()
	if rollbackErr == nil || err != nil {
		t.Fatal("rollback erased connection policy evidence", rollbackErr, err)
	}
}

func TestConnectionPolicyStatusIsReadOnlyAndEmptyMigrationRoundTrips(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	status, err := db.ConnectionPolicyStatus(ctx, OriginalDatabaseEpoch)
	if err != nil || status.Configured || status.Policy != nil || status.PolicySHA256 != nil || status.OccupancyRetained {
		t.Fatal("status fabricated connection policy", status, err)
	}
	for _, name := range []string{"043_connection_policy_changes.down", "041_connection_limits.down", "041_connection_limits.up", "043_connection_policy_changes.up"} {
		raw, err := os.ReadFile("../../../../deploy/sql/" + name + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.ExecContext(ctx, string(raw)); err != nil {
			t.Fatal("empty connection migration failed", name, err)
		}
	}
}
