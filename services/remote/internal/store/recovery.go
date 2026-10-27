package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrRecoveryConflict = errors.New("store: recovery operation conflicts with recorded state")
var ErrRecoveryAuthority = errors.New("store: recovery authority snapshot is invalid or stale")

type RecoveryRun struct {
	ID              string           `json:"recovery_id"`
	SourceEpoch     string           `json:"source_epoch"`
	TargetEpoch     string           `json:"target_epoch"`
	Phase           string           `json:"phase"`
	PreparedAt      time.Time        `json:"prepared_at"`
	ReleasedAt      *time.Time       `json:"released_at"`
	AuthoritySHA256 *string          `json:"authority_sha256"`
	Counts          map[string]int64 `json:"counts"`
}

func readRecoveryRun(ctx context.Context, tx *sql.Tx, id string) (RecoveryRun, error) {
	var run RecoveryRun
	var counts []byte
	err := tx.QueryRowContext(ctx, `select id::text,source_epoch::text,target_epoch::text,phase,prepared_at,released_at,authority_sha256,counts from remote_recovery_runs where id=$1`, id).Scan(&run.ID, &run.SourceEpoch, &run.TargetEpoch, &run.Phase, &run.PreparedAt, &run.ReleasedAt, &run.AuthoritySHA256, &counts)
	if errors.Is(err, sql.ErrNoRows) {
		return run, ErrRecoveryConflict
	}
	if err != nil {
		return run, transactionFailure(err)
	}
	if json.Unmarshal(counts, &run.Counts) != nil {
		return run, ErrDatabaseUnavailable
	}
	return run, nil
}

// Offline administrative operation. Keep ingress isolated and all old relay
// deployments stopped. A committed result is idempotent by the explicit ID;
// uncertain commits must be reconciled by that same ID, never a fresh one.
func (postgres *Postgres) QuarantineRecovery(ctx context.Context, id, expected, epoch string) (RecoveryRun, error) {
	if !grantUUIDPattern.MatchString(id) || !grantUUIDPattern.MatchString(expected) || !grantUUIDPattern.MatchString(epoch) || epoch == OriginalDatabaseEpoch || epoch == expected {
		return RecoveryRun{}, ErrDatabaseConfig
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return retrySerializable(ctx, func() (RecoveryRun, error) { return postgres.quarantineRecoveryOnce(ctx, id, expected, epoch) })
}

func (postgres *Postgres) quarantineRecoveryOnce(ctx context.Context, id, expected, epoch string) (RecoveryRun, error) {
	tx, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return RecoveryRun{}, transactionFailure(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `set local lock_timeout='2s'`); err != nil {
		return RecoveryRun{}, transactionFailure(err)
	}
	state, err := recoveryState(ctx, tx, " for update")
	if err != nil {
		return RecoveryRun{}, err
	}
	if previous, err := readRecoveryRun(ctx, tx, id); err == nil {
		if previous.SourceEpoch != expected || previous.TargetEpoch != epoch {
			return RecoveryRun{}, ErrRecoveryConflict
		}
		return previous, nil
	} else if !errors.Is(err, ErrRecoveryConflict) {
		return RecoveryRun{}, err
	}
	if state.Phase != "ready" || state.Epoch != expected {
		return RecoveryRun{}, ErrRecoveryConflict
	}
	var reused bool
	if err := tx.QueryRowContext(ctx, `select exists(select 1 from remote_recovery_runs where target_epoch=$1 or source_epoch=$1)`, epoch).Scan(&reused); err != nil {
		return RecoveryRun{}, transactionFailure(err)
	}
	if reused {
		return RecoveryRun{}, ErrRecoveryConflict
	}
	if _, err := tx.ExecContext(ctx, `insert into remote_recovery_runs(id,source_epoch,target_epoch,phase,counts) values($1,$2,$3,'quarantined','{}')`, id, expected, epoch); err != nil {
		return RecoveryRun{}, transactionFailure(err)
	}
	counts := map[string]int64{}
	apply := func(name, query string, args ...any) error {
		result, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return transactionFailure(err)
		}
		count, err := result.RowsAffected()
		if err != nil {
			return transactionFailure(err)
		}
		counts[name] = count
		return nil
	}
	operations := []struct{ name, query string }{
		{"devices", `update devices set revoked_at=clock_timestamp() where revoked_at is null`},
		{"installations", `update installations set revoked_at=clock_timestamp() where revoked_at is null`},
		{"grants", `update runtime_grants set revoked_at=clock_timestamp(),grant_version=grant_version+1 where revoked_at is null`},
		{"hosts", `update hosts set state='revoked' where state<>'revoked'`},
		{"users", `update users set status='suspended' where status='active'`},
		{"enrollments", `update enrollments set state='cancelled',decided_at=clock_timestamp() where state in ('pending','user_confirmed')`},
		{"challenges", `update installation_challenges set consumed_at=coalesce(consumed_at,clock_timestamp()) where consumed_at is null`},
		{"host_credentials", `update host_connection_credentials set revoked_at=clock_timestamp() where revoked_at is null`},
		{"tickets", `update realtime_tickets set consumed_at=clock_timestamp() where consumed_at is null`},
		{"runtimes", `update runtimes set connection_id=null,connection_key_version=null,last_seen_at=null,epoch=null where connection_id is not null or epoch is not null`},
		{"sessions", `update sessions set state='unavailable',updated_at=clock_timestamp() where state in ('available','running')`},
		{"commands", `update commands set state='outcome_unknown',updated_at=clock_timestamp() where state not in ('settled','rejected','outcome_unknown')`},
		{"approvals", `update approvals set state=case when state='decision_received' or host_state='consumed' then 'outcome_unknown' else 'invalidated' end
            where state in ('pending','decision_received') or state='allowed' and host_state='consumed'`},
		{"handoffs", `update file_handoffs set state='invalidated',staged_name=null,ended_at=clock_timestamp() where state in ('offered','downloading','staged')`},
		{"push_bindings", `update push_bindings set state='disabled' where state in ('pending','active')`},
		{"push_deliveries", `update push_deliveries set state='expired',lease_id=null,lease_until=null,error_code='recovery_quarantine',updated_at=clock_timestamp() where state in ('queued','leased','retry')`},
		{"consumers", `update control_consumers set generation=gen_random_uuid(),lease_until=clock_timestamp(),relay_origin=null`},
	}
	for _, operation := range operations {
		if err := apply(operation.name, operation.query); err != nil {
			return RecoveryRun{}, err
		}
	}
	if err := apply("memberships", `insert into remote_recovery_memberships(recovery_id,org_id,user_id,role) select $1,org_id,user_id,role from org_memberships`, id); err != nil {
		return RecoveryRun{}, err
	}
	if _, err := tx.ExecContext(ctx, `delete from org_memberships`); err != nil {
		return RecoveryRun{}, transactionFailure(err)
	}
	// No proof/outbox/ack/history deletion. Old snapshots are never interpreted
	// in the new namespace; consumers rebase only after explicit release.
	if _, err := tx.ExecContext(ctx, `update remote_recovery_state set epoch=$1,phase='quarantined',recovery_id=$2,token_not_before=date_trunc('second',clock_timestamp())+interval '1 second' where slot=1`, epoch, id); err != nil {
		return RecoveryRun{}, transactionFailure(err)
	}
	raw, _ := json.Marshal(counts)
	if _, err := tx.ExecContext(ctx, `update remote_recovery_runs set counts=$2::jsonb where id=$1`, id, string(raw)); err != nil {
		return RecoveryRun{}, transactionFailure(err)
	}
	if err := recoveryAudit(ctx, tx, id, "database.recovery.quarantine", map[string]any{"epoch": epoch, "counts": counts}); err != nil {
		return RecoveryRun{}, err
	}
	run, err := readRecoveryRun(ctx, tx, id)
	if err != nil {
		return run, err
	}
	if err := tx.Commit(); err != nil {
		return RecoveryRun{}, transactionFailure(err)
	}
	return run, nil
}

type RecoveryAuthority struct {
	Version       int            `json:"v"`
	Complete      bool           `json:"complete"`
	RecoveryID    string         `json:"recovery_id"`
	DatabaseEpoch string         `json:"database_epoch"`
	Issuer        string         `json:"issuer"`
	CapturedAt    time.Time      `json:"captured_at"`
	ExpiresAt     time.Time      `json:"expires_at"`
	Users         []RecoveryUser `json:"users"`
}
type RecoveryUser struct {
	Subject     string               `json:"subject"`
	Status      string               `json:"status"`
	Memberships []RecoveryMembership `json:"memberships"`
}
type RecoveryMembership struct {
	OrganizationID string `json:"organization_id"`
	Role           string `json:"role"`
}

func (authority RecoveryAuthority) valid(expectedEpoch, issuer string) bool {
	if authority.Version != 1 || !authority.Complete || authority.DatabaseEpoch != expectedEpoch || !grantUUIDPattern.MatchString(authority.RecoveryID) || issuer == "" || authority.Issuer != issuer || authority.Users == nil || len(authority.Users) > 20000 || authority.CapturedAt.IsZero() || authority.ExpiresAt.IsZero() {
		return false
	}
	users := map[string]bool{}
	for _, user := range authority.Users {
		if user.Subject == "" || len(user.Subject) > 2048 || !utf8.ValidString(user.Subject) || strings.IndexFunc(user.Subject, unicode.IsControl) >= 0 || users[user.Subject] || (user.Status != "active" && user.Status != "suspended" && user.Status != "deleted") || user.Memberships == nil || len(user.Memberships) > 256 || user.Status != "active" && len(user.Memberships) != 0 {
			return false
		}
		users[user.Subject] = true
		orgs := map[string]bool{}
		for _, membership := range user.Memberships {
			if !grantUUIDPattern.MatchString(membership.OrganizationID) || orgs[membership.OrganizationID] || (membership.Role != "admin" && membership.Role != "member") {
				return false
			}
			orgs[membership.OrganizationID] = true
		}
	}
	return true
}

// The protected snapshot is an offline operator input from the current trusted
// identity source, not a public endpoint or an exported old database snapshot.
func (postgres *Postgres) ReleaseRecovery(ctx context.Context, expectedEpoch, issuer string, authority RecoveryAuthority) (RecoveryRun, error) {
	if !grantUUIDPattern.MatchString(expectedEpoch) || expectedEpoch == OriginalDatabaseEpoch || !authority.valid(expectedEpoch, issuer) {
		return RecoveryRun{}, ErrRecoveryAuthority
	}
	raw, err := json.Marshal(authority)
	if err != nil {
		return RecoveryRun{}, ErrRecoveryAuthority
	}
	digest := sha256.Sum256(raw)
	fingerprint := hex.EncodeToString(digest[:])
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return retrySerializable(ctx, func() (RecoveryRun, error) {
		return postgres.releaseRecoveryOnce(ctx, expectedEpoch, authority, fingerprint)
	})
}

func (postgres *Postgres) releaseRecoveryOnce(ctx context.Context, epoch string, authority RecoveryAuthority, fingerprint string) (RecoveryRun, error) {
	tx, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return RecoveryRun{}, transactionFailure(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `set local lock_timeout='2s'`); err != nil {
		return RecoveryRun{}, transactionFailure(err)
	}
	state, err := recoveryState(ctx, tx, " for update")
	if err != nil {
		return RecoveryRun{}, err
	}
	run, err := readRecoveryRun(ctx, tx, authority.RecoveryID)
	if err != nil {
		return RecoveryRun{}, err
	}
	if state.Epoch != epoch || run.TargetEpoch != epoch || state.RecoveryID == nil || *state.RecoveryID != run.ID {
		return RecoveryRun{}, ErrRecoveryConflict
	}
	if run.Phase == "ready" {
		if run.AuthoritySHA256 == nil || *run.AuthoritySHA256 != fingerprint {
			return RecoveryRun{}, ErrRecoveryConflict
		}
		return run, nil
	}
	if state.Phase != "quarantined" {
		return RecoveryRun{}, ErrRecoveryConflict
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `select clock_timestamp()`).Scan(&now); err != nil {
		return RecoveryRun{}, transactionFailure(err)
	}
	if authority.CapturedAt.Before(run.PreparedAt) || authority.CapturedAt.After(now) || authority.CapturedAt.Before(now.Add(-15*time.Minute)) || !authority.ExpiresAt.After(now) || authority.ExpiresAt.After(authority.CapturedAt.Add(15*time.Minute)) {
		return RecoveryRun{}, ErrRecoveryAuthority
	}
	// Reassert the complete replacement at release too. No identity writer may
	// run during recovery; unexpected intermediate rows still cannot retain roles.
	if _, err := tx.ExecContext(ctx, `insert into remote_recovery_memberships(recovery_id,org_id,user_id,role) select $1,org_id,user_id,role from org_memberships on conflict do nothing`, run.ID); err != nil {
		return RecoveryRun{}, transactionFailure(err)
	}
	if _, err := tx.ExecContext(ctx, `delete from org_memberships`); err != nil {
		return RecoveryRun{}, transactionFailure(err)
	}
	if _, err := tx.ExecContext(ctx, `update users set status='suspended' where status='active'`); err != nil {
		return RecoveryRun{}, transactionFailure(err)
	}
	for _, user := range authority.Users {
		var id string
		if err := tx.QueryRowContext(ctx, `insert into users(issuer,subject,status) values($1,$2,$3) on conflict(issuer,subject) do update set status=excluded.status returning id::text`, authority.Issuer, user.Subject, user.Status).Scan(&id); err != nil {
			return RecoveryRun{}, transactionFailure(err)
		}
		for _, membership := range user.Memberships {
			if _, err := tx.ExecContext(ctx, `insert into org_memberships(org_id,user_id,role) values($1,$2,$3)`, membership.OrganizationID, id, membership.Role); err != nil {
				return RecoveryRun{}, transactionFailure(err)
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `update remote_recovery_runs set phase='ready',released_at=clock_timestamp(),authority_sha256=$2 where id=$1`, run.ID, fingerprint); err != nil {
		return RecoveryRun{}, transactionFailure(err)
	}
	if _, err := tx.ExecContext(ctx, `update remote_recovery_state set phase='ready',token_not_before=date_trunc('second',clock_timestamp())+interval '1 second' where slot=1 and epoch=$1`, epoch); err != nil {
		return RecoveryRun{}, transactionFailure(err)
	}
	if err := recoveryAudit(ctx, tx, run.ID, "database.recovery.release", map[string]any{"epoch": epoch, "authority_sha256": fingerprint, "users": len(authority.Users)}); err != nil {
		return RecoveryRun{}, err
	}
	run, err = readRecoveryRun(ctx, tx, run.ID)
	if err != nil {
		return run, err
	}
	if err := tx.Commit(); err != nil {
		return RecoveryRun{}, transactionFailure(err)
	}
	return run, nil
}

func recoveryAudit(ctx context.Context, tx *sql.Tx, id, action string, metadata any) error {
	raw, _ := json.Marshal(metadata)
	if _, err := tx.ExecContext(ctx, `insert into audit_log(actor_type,actor_id,action,result,metadata) values('system',$1,$2,'success',$3::jsonb)`, id, action, string(raw)); err != nil {
		return transactionFailure(err)
	}
	return nil
}
