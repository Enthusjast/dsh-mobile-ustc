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

var errConnectionPolicyChangeNotFound = errors.New("store: connection policy change not found")

var ErrConnectionPolicyConflict = errors.New("store: connection policy or operation conflicts with current evidence")
var ErrConnectionPolicyBusy = errors.New("store: connection policy replacement requires all control consumers drained")

type ConnectionPolicyStatus struct {
	DatabaseEpoch     string            `json:"database_epoch"`
	Configured        bool              `json:"configured"`
	Policy            *ConnectionLimits `json:"policy"`
	PolicySHA256      *string           `json:"policy_sha256"`
	ActiveConsumers   int               `json:"active_consumers"`
	OccupancyRetained bool              `json:"occupancy_retained"`
}
type ConnectionPolicyChange struct {
	OperationID    string           `json:"operation_id"`
	DatabaseEpoch  string           `json:"database_epoch"`
	PreviousSHA256 string           `json:"previous_sha256"`
	PolicySHA256   string           `json:"policy_sha256"`
	Policy         ConnectionLimits `json:"policy"`
	ChangedAt      time.Time        `json:"changed_at"`
}

func ValidConnectionPolicyReplacement(epoch, id, expected string, limits ConnectionLimits) bool {
	return grantUUIDPattern.MatchString(epoch) && grantUUIDPattern.MatchString(id) && validSHA256Hex(expected) && limits.Validate() == nil
}

func connectionPolicyMatches(raw []byte, limits ConnectionLimits) bool {
	stored, err := ParseConnectionLimits(raw)
	return err == nil && stored == limits
}

func loadConnectionPolicy(ctx context.Context, tx *sql.Tx, lock string) (ConnectionLimits, []byte, error) {
	var raw, hash []byte
	if err := tx.QueryRowContext(ctx, `select policy,policy_sha256 from realtime_connection_policy where slot=1`+lock).Scan(&raw, &hash); err != nil {
		return ConnectionLimits{}, nil, err
	}
	limits, err := ParseConnectionLimits(raw)
	if err != nil {
		return limits, nil, ErrDatabaseUnavailable
	}
	digest, err := limits.PolicyDigest()
	if err != nil || !bytes.Equal(hash, digest[:]) {
		return limits, nil, ErrDatabaseUnavailable
	}
	return limits, hash, nil
}

func (postgres *Postgres) ConnectionPolicyStatus(parent context.Context, epoch string) (ConnectionPolicyStatus, error) {
	result := ConnectionPolicyStatus{DatabaseEpoch: epoch}
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
	limits, hash, err := loadConnectionPolicy(ctx, tx, "")
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return result, ErrDatabaseUnavailable
	}
	if err == nil {
		encoded := hex.EncodeToString(hash)
		result.Configured = true
		result.Policy = &limits
		result.PolicySHA256 = &encoded
	}
	if err := tx.QueryRowContext(ctx, `select (select count(*) from control_consumers where lease_until>clock_timestamp()),(exists(select 1 from realtime_device_connections) or exists(select 1 from relay_runtime_routes))`).Scan(&result.ActiveConsumers, &result.OccupancyRetained); err != nil {
		return result, ErrDatabaseUnavailable
	}
	if tx.Commit() != nil {
		return result, ErrDatabaseUnavailable
	}
	return result, nil
}

func readConnectionPolicyChange(ctx context.Context, tx *sql.Tx, id string) (ConnectionPolicyChange, error) {
	var result ConnectionPolicyChange
	var raw, prior, hash []byte
	if err := tx.QueryRowContext(ctx, `select operation_id::text,database_epoch::text,previous_sha256,policy_sha256,policy,changed_at from realtime_connection_policy_changes where operation_id=$1`, id).
		Scan(&result.OperationID, &result.DatabaseEpoch, &prior, &hash, &raw, &result.ChangedAt); errors.Is(err, sql.ErrNoRows) {
		return result, errConnectionPolicyChangeNotFound
	} else if err != nil {
		return result, ErrDatabaseUnavailable
	}
	limits, err := ParseConnectionLimits(raw)
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
func (postgres *Postgres) ReplaceConnectionPolicy(parent context.Context, epoch, id, expected string, limits ConnectionLimits) (ConnectionPolicyChange, error) {
	if !ValidConnectionPolicyReplacement(epoch, id, expected, limits) {
		return ConnectionPolicyChange{}, ErrDatabaseConfig
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return ConnectionPolicyChange{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `set local lock_timeout='2s'`); err != nil {
		return ConnectionPolicyChange{}, ErrDatabaseUnavailable
	}
	if _, err := lockRecoveryReady(ctx, tx, epoch); err != nil {
		return ConnectionPolicyChange{}, err
	}
	digest, _ := limits.PolicyDigest()
	encoded := hex.EncodeToString(digest[:])
	prior := func() (ConnectionPolicyChange, error) {
		result, err := readConnectionPolicyChange(ctx, tx, id)
		if err != nil {
			return result, err
		}
		if result.DatabaseEpoch != epoch || result.PreviousSHA256 != expected || result.PolicySHA256 != encoded || result.Policy != limits {
			return ConnectionPolicyChange{}, ErrConnectionPolicyConflict
		}
		return result, nil
	}
	if result, err := prior(); err == nil {
		return result, nil
	} else if !errors.Is(err, errConnectionPolicyChangeNotFound) {
		return ConnectionPolicyChange{}, err
	}
	// Serialize new replacements with consumer insert/renew/release. Production
	// startup registers its consumer before validating its connection policy.
	if err := lockLimitPolicyConsumers(ctx, tx); err != nil {
		return ConnectionPolicyChange{}, ErrDatabaseUnavailable
	}
	if result, err := prior(); err == nil {
		return result, nil
	} else if !errors.Is(err, errConnectionPolicyChangeNotFound) {
		return ConnectionPolicyChange{}, err
	}
	_, hash, err := loadConnectionPolicy(ctx, tx, " for update")
	if errors.Is(err, sql.ErrNoRows) {
		return ConnectionPolicyChange{}, ErrConnectionPolicyConflict
	}
	if err != nil {
		return ConnectionPolicyChange{}, ErrDatabaseUnavailable
	}
	if hex.EncodeToString(hash) != expected || expected == encoded {
		return ConnectionPolicyChange{}, ErrConnectionPolicyConflict
	}
	quiet := func() error { return requireQuietPolicyConsumers(ctx, tx, ErrConnectionPolicyBusy) }
	if err := quiet(); err != nil {
		return ConnectionPolicyChange{}, err
	}
	raw, _ := json.Marshal(limits)
	var changedHash, changedPolicy []byte
	if err := tx.QueryRowContext(ctx, `update realtime_connection_policy set policy=$1::jsonb,policy_sha256=$2 where slot=1 returning policy_sha256,policy`, string(raw), digest[:]).Scan(&changedHash, &changedPolicy); err != nil || !bytes.Equal(changedHash, digest[:]) || !connectionPolicyMatches(changedPolicy, limits) {
		return ConnectionPolicyChange{}, ErrDatabaseUnavailable
	}
	if _, err := tx.ExecContext(ctx, `insert into realtime_connection_policy_changes(operation_id,database_epoch,previous_sha256,policy_sha256,policy) values($1,$2,$3,$4,$5::jsonb)`, id, epoch, hash, digest[:], string(raw)); err != nil {
		return ConnectionPolicyChange{}, ErrDatabaseUnavailable
	}
	metadata, _ := json.Marshal(map[string]string{"operation_id": id, "database_epoch": epoch, "previous_sha256": expected, "policy_sha256": encoded})
	if _, err := tx.ExecContext(ctx, `insert into audit_log(actor_type,actor_id,action,result,metadata) values('system',$1,'connection_policy.replace','success',$2::jsonb)`, id, string(metadata)); err != nil {
		return ConnectionPolicyChange{}, ErrDatabaseUnavailable
	}
	result, err := readConnectionPolicyChange(ctx, tx, id)
	if err != nil {
		return result, err
	}
	if err := quiet(); err != nil {
		return ConnectionPolicyChange{}, err
	}
	if tx.Commit() != nil {
		return ConnectionPolicyChange{}, ErrDatabaseUnavailable
	}
	return result, nil
}
