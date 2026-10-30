package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func commandRateFixture(t *testing.T, limits CommandRateLimits) (context.Context, *Postgres, TicketRedemption, *Postgres) {
	t.Helper()
	ctx, db, ticket := commandDeadlineFixture(t)
	if err := db.ConfigureCommandRateLimits(ctx, limits); err != nil {
		t.Fatal(err)
	}
	other := &Postgres{DB: db.DB}
	if err := other.ConfigureCommandRateLimits(ctx, limits); err != nil {
		t.Fatal(err)
	}
	return ctx, db, ticket, other
}
func rateLimitsForTest() CommandRateLimits { return CommandRateLimits{1, 60000, 100, 100, 100, 100} }
func rateMessage(ctx context.Context, db *Postgres, ticket TicketRedemption, id string) error {
	_, err := db.RecordRealtimeCommand(ctx, ticket, "message.submit", id, "99999999-9999-4999-8999-999999999999", strings.Repeat("a", 64))
	return err
}
func rateUsage(t *testing.T, ctx context.Context, db *Postgres, kind, id string) int {
	t.Helper()
	var used int
	if err := db.DB.QueryRowContext(ctx, `select used from command_rate_counters where kind=$1 and subject_id=$2`, kind, id).Scan(&used); err != nil {
		t.Fatal(err)
	}
	return used
}

func TestSharedCommandRatesCombineRepositoriesAndAllResourceSubjects(t *testing.T) {
	for _, kind := range []string{"user", "device", "installation", "session"} {
		t.Run(kind, func(t *testing.T) {
			limits := rateLimitsForTest()
			switch kind {
			case "user":
				limits.User = 2
			case "device":
				limits.Device = 2
			case "installation":
				limits.Installation = 2
			case "session":
				limits.Session = 2
			}
			ctx, db, first, other := commandRateFixture(t, limits)
			second := first
			if kind == "user" {
				proof, approval := validEnrollmentInput(t), validEnrollmentInput(t)
				second.DeviceID = approvalTestUUID(t)
				second.ProofKeyThumbprint = proof.InstallationKeyThumbprint
				if _, err := db.DB.ExecContext(ctx, `insert into devices(id,user_id,name,approval_public_jwk,approval_key_thumbprint,proof_public_jwk,proof_key_thumbprint) values($1,$2,'rate-test',$3::jsonb,$4,$5::jsonb,$6)`, second.DeviceID, second.UserID, string(approval.InstallationPublicJWK), approval.InstallationKeyThumbprint, string(proof.InstallationPublicJWK), proof.InstallationKeyThumbprint); err != nil {
					t.Fatal(err)
				}
			} else if kind == "installation" || kind == "session" {
				if _, err := db.PutRuntimeGrant(ctx, UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}, first.DeviceID, first.ProofKeyThumbprint, first.RuntimeID, directoryTarget, RuntimeGrantInput{Role: "operator", Scope: first.Scope}); err != nil {
					t.Fatal(err)
				}
				second.UserID = directoryTarget
				second.DeviceID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
				second.ProofKeyThumbprint = "proof-jkt-target"
			}
			if err := rateMessage(ctx, db, first, approvalTestUUID(t)); err != nil {
				t.Fatal(err)
			}
			if err := rateMessage(ctx, other, second, approvalTestUUID(t)); err != nil {
				t.Fatal("independent repository did not share allowance", err)
			}
			if err := rateMessage(ctx, db, first, approvalTestUUID(t)); !errors.Is(err, ErrCommandRateLimited) {
				t.Fatal("shared subject budget was bypassed", kind, err)
			}
			var commands int
			if err := db.DB.QueryRowContext(ctx, `select count(*) from commands`).Scan(&commands); err != nil || commands != 2 {
				t.Fatal("limited attempt created a command", commands, err)
			}
			id := first.UserID
			switch kind {
			case "device":
				id = first.DeviceID
			case "installation":
				id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
			case "session":
				id = "99999999-9999-4999-8999-999999999999"
			}
			if used := rateUsage(t, ctx, db, kind, id); used != 2 {
				t.Fatal("shared counter changed on denied attempt", used)
			}
		})
	}
}

func TestSharedCommandRateConcurrentAttemptsHaveOneAtomicBudget(t *testing.T) {
	limits := rateLimitsForTest()
	limits.Device = 3
	ctx, db, ticket, other := commandRateFixture(t, limits)
	var wait sync.WaitGroup
	results := make(chan error, 12)
	for index := range 12 {
		wait.Go(func() {
			repository := db
			if index%2 == 1 {
				repository = other
			}
			results <- rateMessage(ctx, repository, ticket, approvalTestUUID(t))
		})
	}
	wait.Wait()
	close(results)
	allowed, limited := 0, 0
	for err := range results {
		if err == nil {
			allowed++
		} else if errors.Is(err, ErrCommandRateLimited) {
			limited++
		} else {
			t.Fatal("concurrent rate attempt failed unexpectedly", err)
		}
	}
	if allowed != 3 || limited != 9 || rateUsage(t, ctx, db, "device", ticket.DeviceID) != 3 {
		t.Fatal("shared counter overspent", allowed, limited)
	}
}

func TestCommandRateAttemptsPersistAcrossConflictsAndCommandAuditRollback(t *testing.T) {
	limits := rateLimitsForTest()
	limits.Device = 4
	ctx, db, ticket, other := commandRateFixture(t, limits)
	id := approvalTestUUID(t)
	if err := rateMessage(ctx, db, ticket, id); err != nil {
		t.Fatal(err)
	}
	if _, err := other.RecordRealtimeCommand(ctx, ticket, "message.submit", id, "99999999-9999-4999-8999-999999999999", strings.Repeat("b", 64)); !errors.Is(err, ErrCommandConflict) {
		t.Fatal("changed intent did not conflict", err)
	}
	if err := rateMessage(ctx, other, ticket, id); err != nil {
		t.Fatal("exact retry did not reconcile", err)
	}
	if _, err := db.DB.ExecContext(ctx, `create function fail_rate_command_audit() returns trigger language plpgsql as $$ begin if new.action='command.received' then raise exception 'fixture';end if;return new;end $$;create trigger fail_rate_command_audit before insert on audit_log for each row execute function fail_rate_command_audit()`); err != nil {
		t.Fatal(err)
	}
	if err := rateMessage(ctx, db, ticket, approvalTestUUID(t)); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatal("audit failure did not roll back command", err)
	}
	if used := rateUsage(t, ctx, db, "device", ticket.DeviceID); used != 4 {
		t.Fatal("failed command rolled back its attempt budget", used)
	}
	if err := rateMessage(ctx, other, ticket, id); !errors.Is(err, ErrCommandRateLimited) {
		t.Fatal("retries bypassed shared budget", err)
	}
	var count int
	if err := db.DB.QueryRowContext(ctx, `select count(*) from commands`).Scan(&count); err != nil || count != 1 {
		t.Fatal("failed attempts changed command facts", count, err)
	}
}

func TestCommandRateDeniesUnownedTargetsBeforeCreatingCountersAndDoesNotNestPoolSlots(t *testing.T) {
	limits := rateLimitsForTest()
	ctx, db, ticket, _ := commandRateFixture(t, limits)
	if _, err := db.RecordRealtimeCommand(ctx, ticket, "message.submit", approvalTestUUID(t), approvalTestUUID(t), strings.Repeat("a", 64)); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("unknown session allocated quota", err)
	}
	wrong := ticket
	wrong.ProofKeyThumbprint = "wrong-proof"
	if err := rateMessage(ctx, db, wrong, approvalTestUUID(t)); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("wrong key allocated quota", err)
	}
	var count int
	if err := db.DB.QueryRowContext(ctx, `select count(*) from command_rate_counters`).Scan(&count); err != nil || count != 0 {
		t.Fatal("unauthorized selector polluted counters", count, err)
	}
	db.DB.SetMaxOpenConns(1)
	deadline, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := rateMessage(deadline, db, ticket, approvalTestUUID(t)); err != nil {
		t.Fatal("quota held a pool slot while opening command transaction", err)
	}
}

func TestCommandCreationCountsInstallationWithoutInventingASession(t *testing.T) {
	limits := rateLimitsForTest()
	limits.Installation = 1
	ctx, db, ticket, other := commandRateFixture(t, limits)
	if _, err := db.RecordRealtimeSessionCreate(ctx, ticket, approvalTestUUID(t), ticket.Scope.Workspaces[0], strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := other.RecordRealtimeSessionCreate(ctx, ticket, approvalTestUUID(t), ticket.Scope.Workspaces[0], strings.Repeat("b", 64)); !errors.Is(err, ErrCommandRateLimited) {
		t.Fatal("creation bypassed installation budget", err)
	}
	var count int
	if err := db.DB.QueryRowContext(ctx, `select count(*) from command_rate_counters where kind='session'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("creation invented session quota identity", count, err)
	}
}

func TestCommandRatePolicyMismatchFailureAndRollbackNeverFallBackToLocalCounters(t *testing.T) {
	limits := rateLimitsForTest()
	ctx, db, ticket, _ := commandRateFixture(t, limits)
	other := &Postgres{DB: db.DB}
	changed := limits
	changed.Device++
	if err := other.ConfigureCommandRateLimits(ctx, changed); err == nil {
		t.Fatal("different node policy was silently accepted")
	}
	if err := rateMessage(ctx, other, ticket, approvalTestUUID(t)); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatal("failed policy setup fell back to unlimited", err)
	}
	invalid := &Postgres{DB: db.DB}
	bad := limits
	bad.Device = 0
	if err := invalid.ConfigureCommandRateLimits(ctx, bad); !errors.Is(err, ErrDatabaseConfig) {
		t.Fatal("invalid policy configured", err)
	}
	if err := rateMessage(ctx, invalid, ticket, approvalTestUUID(t)); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatal("invalid policy fell back to unlimited", err)
	}
	if err := rateMessage(ctx, db, ticket, approvalTestUUID(t)); err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../../deploy/sql/038_command_rates.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	connection, err := db.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, rollbackErr := connection.ExecContext(ctx, string(down))
	_, err = connection.ExecContext(ctx, `rollback`)
	_ = connection.Close()
	if err != nil || rollbackErr == nil {
		t.Fatal("rollback erased retained budgets", err, rollbackErr)
	}
	if _, err := db.DB.ExecContext(ctx, `update command_rate_policy set policy_sha256=decode(repeat('00',32),'hex')`); err != nil {
		t.Fatal(err)
	}
	if err := rateMessage(ctx, db, ticket, approvalTestUUID(t)); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatal("running node trusted stale policy", err)
	}
}

func TestSharedCommandRateIncompleteCounterUpdateCannotAdmitOrResetPolicy(t *testing.T) {
	ctx, db, ticket, _ := commandRateFixture(t, rateLimitsForTest())
	if _, err := db.DB.ExecContext(ctx, `create function skip_command_counter() returns trigger language plpgsql as $$ begin if new.kind='user' then return null;end if;return new;end $$;create trigger skip_command_counter before update on command_rate_counters for each row execute function skip_command_counter()`); err != nil {
		t.Fatal(err)
	}
	if err := rateMessage(ctx, db, ticket, approvalTestUUID(t)); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatal("incomplete update admitted command", err)
	}
	var count int
	if err := db.DB.QueryRowContext(ctx, `select count(*) from command_rate_counters`).Scan(&count); err != nil || count != 0 {
		t.Fatal("incomplete update left partial budgets", count, err)
	}
	if _, err := db.DB.ExecContext(ctx, `drop trigger skip_command_counter on command_rate_counters`); err != nil {
		t.Fatal(err)
	}
	if err := rateMessage(ctx, db, ticket, approvalTestUUID(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `delete from command_rate_policy`); err != nil {
		t.Fatal(err)
	}
	newNode := &Postgres{DB: db.DB}
	if err := newNode.ConfigureCommandRateLimits(ctx, rateLimitsForTest()); err == nil {
		t.Fatal("startup replaced missing policy while budgets existed")
	}
}

func TestCommandRateClockRollbackFailsClosedAndExpiredWindowsReset(t *testing.T) {
	limits := rateLimitsForTest()
	limits.Device = 1
	ctx, db, ticket, _ := commandRateFixture(t, limits)
	if err := rateMessage(ctx, db, ticket, approvalTestUUID(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `update command_rate_counters set window_start=clock_timestamp()+interval '1 minute'`); err != nil {
		t.Fatal(err)
	}
	if err := rateMessage(ctx, db, ticket, approvalTestUUID(t)); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatal("future counter granted a fresh window", err)
	}
	if _, err := db.DB.ExecContext(ctx, `update command_rate_counters set window_start=clock_timestamp()-interval '2 minutes'`); err != nil {
		t.Fatal(err)
	}
	if err := rateMessage(ctx, db, ticket, approvalTestUUID(t)); err != nil {
		t.Fatal("expired window did not reset", err)
	}
	if used := rateUsage(t, ctx, db, "device", ticket.DeviceID); used != 1 {
		t.Fatal("reset retained old usage", used)
	}
}

func TestCommandRatePolicyBodyDriftCannotKeepItsOldDigest(t *testing.T) {
	ctx, db, ticket, _ := commandRateFixture(t, rateLimitsForTest())
	if _, err := db.DB.ExecContext(ctx, `update command_rate_policy set policy=jsonb_set(policy,'{device}','1000'::jsonb)`); err != nil {
		t.Fatal(err)
	}
	if err := rateMessage(ctx, db, ticket, approvalTestUUID(t)); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatal("changed policy body kept old node limits", err)
	}
}

func TestSharedCommandRateUsesDatabaseTimeAfterCounterLockWait(t *testing.T) {
	limits := rateLimitsForTest()
	limits.WindowMilliseconds = 1000
	limits.User = 1
	ctx, db, ticket, other := commandRateFixture(t, limits)
	if err := rateMessage(ctx, db, ticket, approvalTestUUID(t)); err != nil {
		t.Fatal(err)
	}
	gate, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback()
	var expires time.Time
	if err := gate.QueryRowContext(ctx, `update command_rate_counters set window_start=clock_timestamp() where kind='user' returning window_start+interval '1 second'`).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- rateMessage(ctx, other, ticket, approvalTestUUID(t)) }()
	waitForGrantLock(t, ctx, db, "command_rate_counters")
	waitForGrantDatabaseExpiry(t, ctx, db, expires)
	if err := gate.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal("counter wait preserved an expired window", err)
	}
	if used := rateUsage(t, ctx, db, "user", ticket.UserID); used != 1 {
		t.Fatal("new database window was not used", used)
	}
}

func TestSharedCommandRateDoesNotBlockExistingHostResultFacts(t *testing.T) {
	h := newMessageFileFixture(t)
	limits := rateLimitsForTest()
	limits.Device = 1
	if err := h.database.ConfigureCommandRateLimits(h.ctx, limits); err != nil {
		t.Fatal(err)
	}
	id := approvalTestUUID(t)
	if err := rateMessage(h.ctx, h.database, h.ticket, id); err != nil {
		t.Fatal(err)
	}
	if err := rateMessage(h.ctx, h.database, h.ticket, approvalTestUUID(t)); !errors.Is(err, ErrCommandRateLimited) {
		t.Fatal("fixture did not reach quota", err)
	}
	receipt := fixtureReceipt(h, id)
	for _, state := range []string{"host_accepted", "dispatching", "settled"} {
		receipt.State = state
		if _, err := h.database.RecordRealtimeCommandReceipt(h.ctx, receipt); err != nil {
			t.Fatal("quota blocked existing Host facts", state, err)
		}
	}
}

func TestSharedCommandRatesCoverEveryCommandActionAndFileAdmission(t *testing.T) {
	for _, action := range []string{"message.submit", "session.cancel", "session.archive", "session.model.select", "question.answer", "session.create"} {
		t.Run(action, func(t *testing.T) {
			limits := rateLimitsForTest()
			limits.Device = 1
			ctx, db, ticket, other := commandRateFixture(t, limits)
			var err error
			if action == "session.create" {
				_, err = db.RecordRealtimeSessionCreate(ctx, ticket, approvalTestUUID(t), ticket.Scope.Workspaces[0], strings.Repeat("a", 64))
			} else {
				_, err = db.RecordRealtimeCommand(ctx, ticket, action, approvalTestUUID(t), "99999999-9999-4999-8999-999999999999", strings.Repeat("a", 64))
			}
			if err != nil {
				t.Fatal("command did not consume shared allowance", action, err)
			}
			if err := rateMessage(ctx, other, ticket, approvalTestUUID(t)); !errors.Is(err, ErrCommandRateLimited) {
				t.Fatal("operation switched out of its actor budget", action, err)
			}
		})
	}
	t.Run("files", func(t *testing.T) {
		h := newMessageFileFixture(t)
		h.stage(t, h.file)
		limits := rateLimitsForTest()
		limits.Device = 1
		if err := h.database.ConfigureCommandRateLimits(h.ctx, limits); err != nil {
			t.Fatal(err)
		}
		if _, err := h.record(t, approvalTestUUID(t), h.file.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := h.record(t, approvalTestUUID(t), h.file.ID); !errors.Is(err, ErrCommandRateLimited) {
			t.Fatal("file admission bypassed shared budget", err)
		}
		if count := h.count(t, "file_message_refs"); count != 1 {
			t.Fatal("limited file attempt changed reservations", count)
		}
	})
}

func TestSharedCommandRateCounterWaitCannotKeepExpiredGrantOrEraseHistoryOnUnusedMigration(t *testing.T) {
	limits := rateLimitsForTest()
	ctx, db, ticket, _ := commandRateFixture(t, limits)
	if err := rateMessage(ctx, db, ticket, approvalTestUUID(t)); err != nil {
		t.Fatal(err)
	}
	gate, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback()
	if _, err := gate.ExecContext(ctx, `select 1 from command_rate_counters where kind='user' for update`); err != nil {
		t.Fatal(err)
	}
	var expires time.Time
	if err := db.DB.QueryRowContext(ctx, `update runtime_grants set expires_at=clock_timestamp()+interval '500 milliseconds' returning expires_at`).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- rateMessage(ctx, db, ticket, approvalTestUUID(t)) }()
	waitForGrantLock(t, ctx, db, "command_rate_counters")
	waitForGrantDatabaseExpiry(t, ctx, db, expires)
	if err := gate.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrAccessDenied) {
		t.Fatal("counter wait preserved expired command authority", err)
	}
	if used := rateUsage(t, ctx, db, "device", ticket.DeviceID); used != 1 {
		t.Fatal("expired rate attempt changed committed budget", used)
	}
	ctx, unused, _ := commandDeadlineFixture(t)
	for _, direction := range []string{"039_command_rate_policy_changes.down", "038_command_rates.down", "038_command_rates.up", "039_command_rate_policy_changes.up"} {
		raw, err := os.ReadFile("../../../../deploy/sql/" + direction + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := unused.DB.ExecContext(ctx, string(raw)); err != nil {
			t.Fatal("unused rate migration failed", direction, err)
		}
	}
	if err := unused.ConfigureCommandRateLimits(ctx, limits); err != nil {
		t.Fatal("reapplied migration could not configure limits", err)
	}
}
