package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"dsh-mobile-ustc/services/remote/internal/canonical"
)

var ErrCommandRateLimited = errors.New("store: shared command admission budget exhausted")

type CommandRateLimits struct {
	Version            int `json:"v"`
	WindowMilliseconds int `json:"window_ms"`
	User               int `json:"user"`
	Device             int `json:"device"`
	Installation       int `json:"installation"`
	Session            int `json:"session"`
}

func DefaultCommandRateLimits() CommandRateLimits { return CommandRateLimits{1, 1000, 60, 20, 120, 20} }

func ParseCommandRateLimits(raw []byte) (CommandRateLimits, error) {
	var limits CommandRateLimits
	if len(raw) > 8<<10 {
		return limits, ErrDatabaseConfig
	}
	if _, err := canonical.Object(raw); err != nil {
		return limits, ErrDatabaseConfig
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 6 {
		return limits, ErrDatabaseConfig
	}
	for _, key := range []string{"v", "window_ms", "user", "device", "installation", "session"} {
		if fields[key] == nil {
			return limits, ErrDatabaseConfig
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&limits) != nil || limits.Validate() != nil {
		return limits, ErrDatabaseConfig
	}
	return limits, nil
}

func (limits CommandRateLimits) Validate() error {
	if limits.Version != 1 || limits.WindowMilliseconds < 100 || limits.WindowMilliseconds > 60000 {
		return ErrDatabaseConfig
	}
	for _, limit := range []int{limits.User, limits.Device, limits.Installation, limits.Session} {
		if limit < 1 || limit > 100000 {
			return ErrDatabaseConfig
		}
	}
	return nil
}

func (limits CommandRateLimits) PolicyDigest() ([32]byte, error) {
	if err := limits.Validate(); err != nil {
		return [32]byte{}, err
	}
	raw, _ := json.Marshal(limits)
	encoded, err := canonical.Object(raw)
	if err != nil {
		return [32]byte{}, ErrDatabaseConfig
	}
	return sha256.Sum256(encoded), nil
}

type commandRateState struct {
	once   sync.Once
	limits *CommandRateLimits
	hash   [32]byte
	err    error
}

func commandPolicyMatches(raw []byte, limits CommandRateLimits) bool {
	stored, err := ParseCommandRateLimits(raw)
	return err == nil && stored == limits
}

// Startup-only. Production always configures limits before listening; explicit
// library fixtures can leave them unconfigured without fabricating a policy.
func (postgres *Postgres) ConfigureCommandRateLimits(ctx context.Context, limits CommandRateLimits) error {
	configured := false
	postgres.commandRates.once.Do(func() {
		configured = true
		if limits.Validate() != nil {
			postgres.commandRates.err = ErrDatabaseConfig
			return
		}
		postgres.commandRates.err = ErrDatabaseUnavailable
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		raw, _ := json.Marshal(limits)
		digest, digestErr := limits.PolicyDigest()
		if digestErr != nil {
			return
		}
		tx, err := postgres.DB.BeginTx(ctx, nil)
		if err != nil {
			return
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, `insert into command_rate_policy(slot,policy_sha256,policy)
		 select 1,$1,$2::jsonb where not exists(select 1 from command_rate_counters) on conflict do nothing`, digest[:], string(raw)); err != nil {
			return
		}
		var storedHash, storedRaw []byte
		if err := tx.QueryRowContext(ctx, `select policy_sha256,policy from command_rate_policy where slot=1 for share`).Scan(&storedHash, &storedRaw); err != nil {
			return
		}
		if !commandPolicyMatches(storedRaw, limits) || !bytes.Equal(storedHash, digest[:]) {
			return
		}
		if tx.Commit() != nil {
			return
		}
		postgres.commandRates.limits = &limits
		postgres.commandRates.hash = digest
		postgres.commandRates.err = nil
	})
	if !configured {
		return ErrDatabaseConfig
	}
	return postgres.commandRates.err
}

type commandRateCounter struct {
	Kind    string    `json:"kind"`
	Subject string    `json:"subject_id"`
	Start   time.Time `json:"window_start"`
	Used    int       `json:"used"`
}

// Count a currently authorized attempt independently of command success. Its
// transaction releases its pool slot before the command transaction opens.
// Quota commit cannot authorize execution: command admission rechecks authority.
func (postgres *Postgres) admitCommandRate(parent context.Context, ticket TicketRedemption, action, sessionID, workspaceID string, files bool) error {
	state := &postgres.commandRates
	if state.err != nil {
		return ErrDatabaseUnavailable
	}
	if state.limits == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	var hash, rawPolicy []byte
	if err := tx.QueryRowContext(ctx, `select policy_sha256,policy from command_rate_policy where slot=1 for share`).Scan(&hash, &rawPolicy); err != nil || !bytes.Equal(hash, state.hash[:]) || !commandPolicyMatches(rawPolicy, *state.limits) {
		return ErrDatabaseUnavailable
	}
	authority, err := authorizeCommandResources(ctx, tx, ticket, action, sessionID, workspaceID, files)
	if err != nil {
		return err
	}
	if err := checkCommandGrantTime(ctx, tx, ticket); err != nil {
		return err
	}
	var session any
	if sessionID != "" {
		session = sessionID
	}
	if _, err := tx.ExecContext(ctx, `insert into command_rate_counters(kind,subject_id,user_id,device_id,installation_id,session_id)
	 select kind,id,user_id,device_id,installation_id,session_id from (
	 select 0 n,'user'::text kind,$1::uuid id,$1::uuid user_id,null::uuid device_id,null::uuid installation_id,null::uuid session_id
	 union all select 1,'device',$2::uuid,null,$2::uuid,null,null
	 union all select 2,'installation',$3::uuid,null,null,$3::uuid,null
	 union all select 3,'session',$4::uuid,null,null,null,$4::uuid where $4::uuid is not null
	 ) subjects order by n on conflict(kind,subject_id) do nothing`, ticket.UserID, ticket.DeviceID, authority.installation, session); err != nil {
		return ErrDatabaseUnavailable
	}
	rows, err := tx.QueryContext(ctx, `select kind,subject_id::text,window_start,used from command_rate_counters
	 where (kind='user' and subject_id=$1) or (kind='device' and subject_id=$2) or (kind='installation' and subject_id=$3) or (kind='session' and subject_id=$4)
	 order by case kind when 'user' then 0 when 'device' then 1 when 'installation' then 2 else 3 end for update`, ticket.UserID, ticket.DeviceID, authority.installation, session)
	if err != nil {
		return ErrDatabaseUnavailable
	}
	counters := []commandRateCounter{}
	for rows.Next() {
		var counter commandRateCounter
		if err := rows.Scan(&counter.Kind, &counter.Subject, &counter.Start, &counter.Used); err != nil {
			_ = rows.Close()
			return ErrDatabaseUnavailable
		}
		counters = append(counters, counter)
	}
	rowErr := rows.Err()
	_ = rows.Close()
	want := 3
	if session != nil {
		want = 4
	}
	if rowErr != nil || len(counters) != want {
		return ErrDatabaseUnavailable
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `select clock_timestamp()`).Scan(&now); err != nil {
		return ErrDatabaseUnavailable
	}
	limits := state.limits
	for index := range counters {
		counter := &counters[index]
		if now.Before(counter.Start) {
			return ErrDatabaseUnavailable
		}
		if !now.Before(counter.Start.Add(time.Duration(limits.WindowMilliseconds) * time.Millisecond)) {
			counter.Start = now
			counter.Used = 0
		}
		limit := map[string]int{"user": limits.User, "device": limits.Device, "installation": limits.Installation, "session": limits.Session}[counter.Kind]
		if counter.Used >= limit {
			return ErrCommandRateLimited
		}
		counter.Used++
	}
	raw, marshalErr := json.Marshal(counters)
	if marshalErr != nil {
		return ErrDatabaseUnavailable
	}
	updated, err := tx.ExecContext(ctx, `update command_rate_counters c set window_start=v.window_start,used=v.used
	 from jsonb_to_recordset($1::jsonb) as v(kind text,subject_id uuid,window_start timestamptz,used integer)
	 where c.kind=v.kind and c.subject_id=v.subject_id`, string(raw))
	if err != nil {
		return ErrDatabaseUnavailable
	}
	count, err := updated.RowsAffected()
	if err != nil || count != int64(len(counters)) {
		return ErrDatabaseUnavailable
	}
	if err := checkCommandGrantTime(ctx, tx, ticket); err != nil {
		return err
	}
	if tx.Commit() != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}
