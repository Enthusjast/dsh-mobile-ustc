package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

var errCommandRateChangeNotFound = errors.New("store: command rate change not found")

var ErrCommandRatePolicyConflict = errors.New("store: command rate policy or operation conflicts with current evidence")
var ErrCommandRatePolicyBusy = errors.New("store: command rate policy replacement requires all control consumers drained")

type CommandRatePolicyStatus struct {
	DatabaseEpoch   string             `json:"database_epoch"`
	Configured      bool               `json:"configured"`
	Policy          *CommandRateLimits `json:"policy"`
	PolicySHA256    *string            `json:"policy_sha256"`
	ActiveConsumers int                `json:"active_consumers"`
	BudgetsRetained bool               `json:"budgets_retained"`
}
type CommandRatePolicyChange struct {
	OperationID    string            `json:"operation_id"`
	DatabaseEpoch  string            `json:"database_epoch"`
	PreviousSHA256 string            `json:"previous_sha256"`
	PolicySHA256   string            `json:"policy_sha256"`
	Policy         CommandRateLimits `json:"policy"`
	ChangedAt      time.Time         `json:"changed_at"`
}

func ValidCommandRatePolicyReplacement(epoch, id, expected string, limits CommandRateLimits) bool {
	return grantUUIDPattern.MatchString(epoch) && grantUUIDPattern.MatchString(id) && validSHA256Hex(expected) && limits.Validate() == nil
}

func loadCommandRatePolicy(ctx context.Context, tx *sql.Tx, lock string) (CommandRateLimits, []byte, error) {
	var raw, hash []byte
	if err := tx.QueryRowContext(ctx, `select policy,policy_sha256 from command_rate_policy where slot=1`+lock).Scan(&raw, &hash); err != nil {
		return CommandRateLimits{}, nil, err
	}
	limits, err := ParseCommandRateLimits(raw)
	if err != nil {
		return limits, nil, ErrDatabaseUnavailable
	}
	digest, err := limits.PolicyDigest()
	if err != nil || !bytes.Equal(hash, digest[:]) {
		return limits, nil, ErrDatabaseUnavailable
	}
	return limits, hash, nil
}

func (postgres *Postgres) CommandRatePolicyStatus(parent context.Context, epoch string) (CommandRatePolicyStatus, error) {
	result := CommandRatePolicyStatus{DatabaseEpoch: epoch}
	if !grantUUIDPattern.MatchString(epoch) {
		return result, ErrDatabaseConfig
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return result, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	state, err := recoveryState(ctx, tx, "")
	if err != nil {
		return result, err
	}
	if state.Epoch != epoch || state.Phase != "ready" {
		return result, ErrRecoveryUnavailable
	}
	limits, hash, err := loadCommandRatePolicy(ctx, tx, "")
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return result, ErrDatabaseUnavailable
	}
	if err == nil {
		encoded := hex.EncodeToString(hash)
		result.Configured = true
		result.Policy = &limits
		result.PolicySHA256 = &encoded
	}
	if err := tx.QueryRowContext(ctx, `select (select count(*) from control_consumers where lease_until>clock_timestamp()),exists(select 1 from command_rate_counters)`).Scan(&result.ActiveConsumers, &result.BudgetsRetained); err != nil {
		return result, ErrDatabaseUnavailable
	}
	if tx.Commit() != nil {
		return result, ErrDatabaseUnavailable
	}
	return result, nil
}

func readCommandRateChange(ctx context.Context, tx *sql.Tx, id string) (CommandRatePolicyChange, error) {
	var result CommandRatePolicyChange
	var raw, prior, hash []byte
	if err := tx.QueryRowContext(ctx, `select operation_id::text,database_epoch::text,previous_sha256,policy_sha256,policy,changed_at from command_rate_policy_changes where operation_id=$1`, id).
		Scan(&result.OperationID, &result.DatabaseEpoch, &prior, &hash, &raw, &result.ChangedAt); errors.Is(err, sql.ErrNoRows) {
		return result, errCommandRateChangeNotFound
	} else if err != nil {
		return result, ErrDatabaseUnavailable
	}
	limits, err := ParseCommandRateLimits(raw)
	if err != nil {
		return result, ErrDatabaseUnavailable
	}
	digest, err := limits.PolicyDigest()
	if err != nil || !bytes.Equal(digest[:], hash) || len(prior) != 32 {
		return result, ErrDatabaseUnavailable
	}
	result.PreviousSHA256 = hex.EncodeToString(prior)
	result.PolicySHA256 = hex.EncodeToString(hash)
	result.Policy = limits
	return result, nil
}

// Explicit offline administrator operation. A compare-and-set, retained
// operation receipt and current recovery epoch make unknown outcomes retryable.
func (postgres *Postgres) ReplaceCommandRatePolicy(parent context.Context, epoch, id, expected string, limits CommandRateLimits) (CommandRatePolicyChange, error) {
	if !ValidCommandRatePolicyReplacement(epoch, id, expected, limits) {
		return CommandRatePolicyChange{}, ErrDatabaseConfig
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return CommandRatePolicyChange{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `set local lock_timeout='2s'`); err != nil {
		return CommandRatePolicyChange{}, ErrDatabaseUnavailable
	}
	if _, err := lockRecoveryReady(ctx, tx, epoch); err != nil {
		return CommandRatePolicyChange{}, err
	}
	digest, _ := limits.PolicyDigest()
	encoded := hex.EncodeToString(digest[:])
	prior := func() (CommandRatePolicyChange, error) {
		result, err := readCommandRateChange(ctx, tx, id)
		if err != nil {
			return result, err
		}
		if result.DatabaseEpoch != epoch || result.PreviousSHA256 != expected || result.PolicySHA256 != encoded || result.Policy != limits {
			return CommandRatePolicyChange{}, ErrCommandRatePolicyConflict
		}
		return result, nil
	}
	if result, err := prior(); err == nil {
		return result, nil
	} else if !errors.Is(err, errCommandRateChangeNotFound) {
		return CommandRatePolicyChange{}, err
	}
	// Serialize new replacements with consumer insert/renew/release. Production
	// startup registers its consumer before validating its command policy.
	if _, err := tx.ExecContext(ctx, `lock table control_consumers in share row exclusive mode`); err != nil {
		return CommandRatePolicyChange{}, ErrDatabaseUnavailable
	}
	if result, err := prior(); err == nil {
		return result, nil
	} else if !errors.Is(err, errCommandRateChangeNotFound) {
		return CommandRatePolicyChange{}, err
	}
	_, hash, err := loadCommandRatePolicy(ctx, tx, " for update")
	if errors.Is(err, sql.ErrNoRows) {
		return CommandRatePolicyChange{}, ErrCommandRatePolicyConflict
	}
	if err != nil {
		return CommandRatePolicyChange{}, ErrDatabaseUnavailable
	}
	if hex.EncodeToString(hash) != expected || expected == encoded {
		return CommandRatePolicyChange{}, ErrCommandRatePolicyConflict
	}
	quiet := func() error {
		var active bool
		if err := tx.QueryRowContext(ctx, `select exists(select 1 from control_consumers where lease_until>clock_timestamp())`).Scan(&active); err != nil {
			return ErrDatabaseUnavailable
		}
		if active {
			return ErrCommandRatePolicyBusy
		}
		return nil
	}
	if err := quiet(); err != nil {
		return CommandRatePolicyChange{}, err
	}
	raw, _ := json.Marshal(limits)
	var changedHash, changedPolicy []byte
	if err := tx.QueryRowContext(ctx, `update command_rate_policy set policy=$1::jsonb,policy_sha256=$2 where slot=1 returning policy_sha256,policy`, string(raw), digest[:]).Scan(&changedHash, &changedPolicy); err != nil || !bytes.Equal(changedHash, digest[:]) || !commandPolicyMatches(changedPolicy, limits) {
		return CommandRatePolicyChange{}, ErrDatabaseUnavailable
	}
	if _, err := tx.ExecContext(ctx, `insert into command_rate_policy_changes(operation_id,database_epoch,previous_sha256,policy_sha256,policy) values($1,$2,$3,$4,$5::jsonb)`, id, epoch, hash, digest[:], string(raw)); err != nil {
		return CommandRatePolicyChange{}, ErrDatabaseUnavailable
	}
	metadata, _ := json.Marshal(map[string]string{"operation_id": id, "database_epoch": epoch, "previous_sha256": expected, "policy_sha256": encoded})
	if _, err := tx.ExecContext(ctx, `insert into audit_log(actor_type,actor_id,action,result,metadata) values('system',$1,'command_rate.policy.replace','success',$2::jsonb)`, id, string(metadata)); err != nil {
		return CommandRatePolicyChange{}, ErrDatabaseUnavailable
	}
	result, err := readCommandRateChange(ctx, tx, id)
	if err != nil {
		return result, err
	}
	if err := quiet(); err != nil {
		return CommandRatePolicyChange{}, err
	}
	if tx.Commit() != nil {
		return CommandRatePolicyChange{}, ErrDatabaseUnavailable
	}
	return result, nil
}
