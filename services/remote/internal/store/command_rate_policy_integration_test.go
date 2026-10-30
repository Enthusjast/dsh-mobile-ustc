package store

import (
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"testing"
)

func policyHash(t *testing.T, limits CommandRateLimits) string {
	t.Helper()
	digest, err := limits.PolicyDigest()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(digest[:])
}

func TestCommandPolicyReplacementPreservesBudgetsAndReconcilesHistoricalOperation(t *testing.T) {
	limits := rateLimitsForTest()
	limits.Device = 2
	ctx, db, ticket, _ := commandRateFixture(t, limits)
	if err := rateMessage(ctx, db, ticket, approvalTestUUID(t)); err != nil {
		t.Fatal(err)
	}
	var before, after string
	readCounters := func(target *string) {
		t.Helper()
		if err := db.DB.QueryRowContext(ctx, `select jsonb_agg(to_jsonb(c) order by kind,subject_id)::text from command_rate_counters c`).Scan(target); err != nil {
			t.Fatal(err)
		}
	}
	readCounters(&before)
	newLimits := limits
	newLimits.Device = 3
	id := approvalTestUUID(t)
	first, err := db.ReplaceCommandRatePolicy(ctx, OriginalDatabaseEpoch, id, policyHash(t, limits), newLimits)
	if err != nil || first.Policy != newLimits || first.PreviousSHA256 != policyHash(t, limits) || first.PolicySHA256 != policyHash(t, newLimits) {
		t.Fatal("policy replacement failed", first, err)
	}
	readCounters(&after)
	if after != before {
		t.Fatal("replacement reset retained budget")
	}
	if err := rateMessage(ctx, db, ticket, approvalTestUUID(t)); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatal("old repository continued on stale policy", err)
	}
	restarted := &Postgres{DB: db.DB}
	if err := restarted.ConfigureCommandRateLimits(ctx, newLimits); err != nil {
		t.Fatal(err)
	}
	if err := rateMessage(ctx, restarted, ticket, approvalTestUUID(t)); err != nil {
		t.Fatal("new policy could not use retained budget", err)
	}
	tight := newLimits
	tight.Device = 1
	if _, err := db.ReplaceCommandRatePolicy(ctx, OriginalDatabaseEpoch, approvalTestUUID(t), policyHash(t, newLimits), tight); err != nil {
		t.Fatal(err)
	}
	current := &Postgres{DB: db.DB}
	if err := current.ConfigureCommandRateLimits(ctx, tight); err != nil {
		t.Fatal(err)
	}
	if err := rateMessage(ctx, current, ticket, approvalTestUUID(t)); !errors.Is(err, ErrCommandRateLimited) {
		t.Fatal("tightening discarded previous usage", err)
	}
	consumer, err := db.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Release(ctx)
	replay, err := db.ReplaceCommandRatePolicy(ctx, OriginalDatabaseEpoch, id, policyHash(t, limits), newLimits)
	if err != nil || replay != first {
		t.Fatal("historical retry rewrote its receipt or required another drain", replay, err)
	}
	status, err := db.CommandRatePolicyStatus(ctx, OriginalDatabaseEpoch)
	if err != nil || !status.Configured || !status.BudgetsRetained || status.ActiveConsumers != 1 || status.Policy == nil || *status.Policy != tight {
		t.Fatal("historical retry rewound current policy", status, err)
	}
	var changes, audits int
	if err := db.DB.QueryRowContext(ctx, `select (select count(*) from command_rate_policy_changes),(select count(*) from audit_log where action='command_rate.policy.replace')`).Scan(&changes, &audits); err != nil || changes != 2 || audits != 2 {
		t.Fatal("policy evidence repeated", changes, audits, err)
	}
}

func TestCommandPolicyReplacementRejectsLiveConsumersStaleInputsAndRecoveryIsolation(t *testing.T) {
	limits := rateLimitsForTest()
	ctx, db, _, _ := commandRateFixture(t, limits)
	updated := limits
	updated.Device++
	consumer, err := db.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	id := approvalTestUUID(t)
	if _, err := db.ReplaceCommandRatePolicy(ctx, OriginalDatabaseEpoch, id, policyHash(t, limits), updated); !errors.Is(err, ErrCommandRatePolicyBusy) {
		t.Fatal("active consumer allowed replacement", err)
	}
	if err := consumer.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReplaceCommandRatePolicy(ctx, OriginalDatabaseEpoch, id, policyHash(t, updated), updated); !errors.Is(err, ErrCommandRatePolicyConflict) {
		t.Fatal("stale expected hash changed policy", err)
	}
	if _, err := db.ReplaceCommandRatePolicy(ctx, OriginalDatabaseEpoch, id, policyHash(t, limits), updated); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReplaceCommandRatePolicy(ctx, OriginalDatabaseEpoch, id, policyHash(t, limits), limits); !errors.Is(err, ErrCommandRatePolicyConflict) {
		t.Fatal("operation ID accepted another policy", err)
	}
	if _, err := db.ReplaceCommandRatePolicy(ctx, approvalTestUUID(t), approvalTestUUID(t), policyHash(t, updated), limits); !errors.Is(err, ErrRecoveryUnavailable) {
		t.Fatal("wrong database epoch admitted replacement", err)
	}
	epoch := approvalTestUUID(t)
	if _, err := db.QuarantineRecovery(ctx, approvalTestUUID(t), OriginalDatabaseEpoch, epoch); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReplaceCommandRatePolicy(ctx, epoch, approvalTestUUID(t), policyHash(t, updated), limits); !errors.Is(err, ErrRecoveryUnavailable) {
		t.Fatal("quarantine allowed policy replacement", err)
	}
}

func TestCommandPolicyReplacementHasAtomicAuditAndChecksActualUpdatedPolicy(t *testing.T) {
	for _, failure := range []string{"audit", "policy-update"} {
		t.Run(failure, func(t *testing.T) {
			limits := rateLimitsForTest()
			ctx, db, _, _ := commandRateFixture(t, limits)
			updated := limits
			updated.Device++
			query := `create function fail_policy_change() returns trigger language plpgsql as $$ begin if new.action='command_rate.policy.replace' then raise exception 'fixture';end if;return new;end $$;create trigger fail_policy_change before insert on audit_log for each row execute function fail_policy_change()`
			if failure == "policy-update" {
				query = `create function fail_policy_change() returns trigger language plpgsql as $$ begin return null;end $$;create trigger fail_policy_change before update on command_rate_policy for each row execute function fail_policy_change()`
			}
			if _, err := db.DB.ExecContext(ctx, query); err != nil {
				t.Fatal(err)
			}
			if _, err := db.ReplaceCommandRatePolicy(ctx, OriginalDatabaseEpoch, approvalTestUUID(t), policyHash(t, limits), updated); !errors.Is(err, ErrDatabaseUnavailable) {
				t.Fatal("failed write returned success", err)
			}
			status, err := db.CommandRatePolicyStatus(ctx, OriginalDatabaseEpoch)
			if err != nil || status.Policy == nil || *status.Policy != limits {
				t.Fatal("failed write changed current policy", status, err)
			}
			var count int
			if err := db.DB.QueryRowContext(ctx, `select count(*) from command_rate_policy_changes`).Scan(&count); err != nil || count != 0 {
				t.Fatal("failed write left operation evidence", count, err)
			}
		})
	}
}

func TestCommandPolicyConcurrentReplacementAndImmutableEvidence(t *testing.T) {
	for _, same := range []bool{false, true} {
		t.Run(map[bool]string{false: "different", true: "same"}[same], func(t *testing.T) {
			limits := rateLimitsForTest()
			ctx, db, _, _ := commandRateFixture(t, limits)
			updated := limits
			updated.Device++
			id, expected := approvalTestUUID(t), policyHash(t, limits)
			type outcome struct {
				receipt CommandRatePolicyChange
				err     error
			}
			results := make(chan outcome, 2)
			var wait sync.WaitGroup
			for range 2 {
				attempt := id
				if !same {
					attempt = approvalTestUUID(t)
				}
				wait.Go(func() {
					receipt, err := db.ReplaceCommandRatePolicy(ctx, OriginalDatabaseEpoch, attempt, expected, updated)
					results <- outcome{receipt, err}
				})
			}
			wait.Wait()
			close(results)
			allowed, conflicts := 0, 0
			var receipt CommandRatePolicyChange
			for result := range results {
				if result.err == nil {
					if allowed > 0 && result.receipt != receipt {
						t.Fatal("same operation produced different receipts")
					}
					allowed++
					receipt = result.receipt
				} else if errors.Is(result.err, ErrCommandRatePolicyConflict) {
					conflicts++
				} else {
					t.Fatal(result.err)
				}
			}
			if same && allowed != 2 || !same && (allowed != 1 || conflicts != 1) {
				t.Fatal("concurrent CAS failed", allowed, conflicts)
			}
			for _, query := range []string{`update command_rate_policy_changes set changed_at=clock_timestamp()`, `delete from command_rate_policy_changes`} {
				if _, err := db.DB.ExecContext(ctx, query); err == nil {
					t.Fatal("policy evidence was mutable")
				}
			}
			raw, err := os.ReadFile("../../../../deploy/sql/039_command_rate_policy_changes.down.sql")
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
				t.Fatal("rollback erased retained policy history", rollbackErr, err)
			}
		})
	}
}

func TestCommandPolicyStatusDoesNotConfigureEmptyStateAndMigrationRoundTrips(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	status, err := db.CommandRatePolicyStatus(ctx, OriginalDatabaseEpoch)
	if err != nil || status.Configured || status.Policy != nil || status.PolicySHA256 != nil || status.BudgetsRetained || status.ActiveConsumers != 0 {
		t.Fatal("status fabricated initial policy", status, err)
	}
	for _, direction := range []string{"down", "up"} {
		raw, err := os.ReadFile("../../../../deploy/sql/039_command_rate_policy_changes." + direction + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.ExecContext(ctx, string(raw)); err != nil {
			t.Fatal("empty policy migration could not round trip", direction, err)
		}
	}
}
