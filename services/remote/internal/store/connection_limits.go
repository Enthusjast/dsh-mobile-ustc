package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"dsh-mobile-ustc/services/remote/internal/canonical"
)

var ErrConnectionLimit = errors.New("store: shared connection capacity exhausted")

type ConnectionLimits struct {
	Version           int `json:"v"`
	Total             int `json:"total"`
	User              int `json:"user"`
	Device            int `json:"device"`
	Installation      int `json:"installation"`
	PendingHandshakes int `json:"pending_handshakes"`
}

func DefaultConnectionLimits() ConnectionLimits { return ConnectionLimits{1, 12000, 256, 64, 128, 256} }
func (limits ConnectionLimits) Validate() error {
	if limits.Version != 1 || limits.Total < 1 || limits.Total > 20000 || limits.PendingHandshakes < 1 || limits.PendingHandshakes > 4096 {
		return ErrDatabaseConfig
	}
	for _, value := range []int{limits.User, limits.Device, limits.Installation} {
		if value < 1 || value > limits.Total {
			return ErrDatabaseConfig
		}
	}
	return nil
}
func ParseConnectionLimits(raw []byte) (ConnectionLimits, error) {
	var limits ConnectionLimits
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
	for _, name := range []string{"v", "total", "user", "device", "installation", "pending_handshakes"} {
		if fields[name] == nil {
			return limits, ErrDatabaseConfig
		}
	}
	if json.Unmarshal(raw, &limits) != nil || limits.Validate() != nil {
		return limits, ErrDatabaseConfig
	}
	return limits, nil
}
func (limits ConnectionLimits) PolicyDigest() ([32]byte, error) {
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

type connectionLimitState struct {
	once   sync.Once
	limits *ConnectionLimits
	hash   [32]byte
	err    error
}

func (postgres *Postgres) ConfigureConnectionLimits(parent context.Context, limits ConnectionLimits) error {
	configured := false
	postgres.connectionLimits.once.Do(func() {
		configured = true
		postgres.connectionLimits.err = ErrDatabaseUnavailable
		if limits.Validate() != nil {
			postgres.connectionLimits.err = ErrDatabaseConfig
			return
		}
		ctx, cancel := context.WithTimeout(parent, 3*time.Second)
		defer cancel()
		tx, err := postgres.DB.BeginTx(ctx, nil)
		if err != nil {
			return
		}
		defer tx.Rollback()
		raw, _ := json.Marshal(limits)
		hash, _ := limits.PolicyDigest()
		if _, err := tx.ExecContext(ctx, `insert into realtime_connection_policy(slot,policy_sha256,policy) select 1,$1,$2::jsonb where not exists(select 1 from realtime_device_connections)
		 and not exists(select 1 from relay_runtime_routes r join control_consumers n on n.node_id=r.node_id and n.generation=r.generation and n.lease_until>clock_timestamp()) on conflict do nothing`, hash[:], string(raw)); err != nil {
			return
		}
		var storedHash, storedRaw []byte
		if err := tx.QueryRowContext(ctx, `select policy_sha256,policy from realtime_connection_policy where slot=1 for share`).Scan(&storedHash, &storedRaw); err != nil {
			return
		}
		stored, err := ParseConnectionLimits(storedRaw)
		if err != nil || stored != limits || !bytes.Equal(storedHash, hash[:]) {
			return
		}
		if tx.Commit() != nil {
			return
		}
		postgres.connectionLimits.limits = &limits
		postgres.connectionLimits.hash = hash
		postgres.connectionLimits.err = nil
	})
	if !configured {
		return ErrDatabaseConfig
	}
	return postgres.connectionLimits.err
}

// The write creates an MVCC fence: SERIALIZABLE Host attachment cannot use a
// snapshot taken before another admission while waiting for this shared lock.
func (postgres *Postgres) lockConnectionCapacity(ctx context.Context, tx *sql.Tx) error {
	state := &postgres.connectionLimits
	if state.err != nil {
		return ErrDatabaseUnavailable
	}
	if state.limits == nil {
		return nil
	}
	var hash, raw []byte
	if err := tx.QueryRowContext(ctx, `update realtime_connection_policy set admission_tick=gen_random_uuid() where slot=1 returning policy_sha256,policy`).Scan(&hash, &raw); err != nil {
		return transactionFailure(err)
	}
	limits, err := ParseConnectionLimits(raw)
	if err != nil || limits != *state.limits || !bytes.Equal(hash, state.hash[:]) {
		return ErrDatabaseUnavailable
	}
	return nil
}

func (postgres *Postgres) checkConnectionCapacity(ctx context.Context, tx *sql.Tx, user, device, installation, replaceRuntime string) error {
	state := &postgres.connectionLimits
	if state.limits == nil {
		return nil
	}
	// SERIALIZABLE snapshots can precede a lease renewal. Evaluate occupancy at
	// the earlier snapshot time so an unseen renewal cannot free a live slot.
	var now time.Time
	if err := tx.QueryRowContext(ctx, `select least(clock_timestamp(),transaction_timestamp())`).Scan(&now); err != nil {
		return transactionFailure(err)
	}
	var total, userCount, deviceCount, installationCount int
	err := tx.QueryRowContext(ctx, `with active as (
	 select i.owner_user_id user_id,null::uuid device_id,i.id installation_id from relay_runtime_routes route
	 join control_consumers n on n.node_id=route.node_id and n.generation=route.generation and n.lease_until>$1
	 join runtimes r on r.id=route.runtime_id and r.epoch=route.runtime_epoch and r.connection_id=route.connection_id
	 join installations i on i.id=r.installation_id and i.revoked_at is null
	 where r.revoked_at is null and r.last_seen_at>$1-interval '5 minutes 30 seconds' and ($5::uuid is null or r.id<>$5)
	 union all
	 select c.user_id,c.device_id,c.installation_id from realtime_device_connections c
	 join control_consumers n on n.node_id=c.node_id and n.generation=c.generation and n.lease_until>$1
	 where c.expires_at>$1
	) select count(*),count(*) filter(where user_id=$2),count(*) filter(where device_id=$3),count(*) filter(where installation_id=$4) from active`, now, user, nullableConnectionID(device), installation, nullableConnectionID(replaceRuntime)).Scan(&total, &userCount, &deviceCount, &installationCount)
	if err != nil {
		return transactionFailure(err)
	}
	limits := state.limits
	if total >= limits.Total || userCount >= limits.User || device != "" && deviceCount >= limits.Device || installationCount >= limits.Installation {
		return ErrConnectionLimit
	}
	return nil
}
func nullableConnectionID(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func (directory *RelayDirectory) ClaimDeviceConnection(ctx context.Context, ticket TicketRedemption, id string, expires time.Time) error {
	if directory.connectionLimits.limits == nil && directory.connectionLimits.err == nil {
		return nil
	}
	if !grantUUIDPattern.MatchString(id) {
		return ErrGrantInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := retrySerializable(ctx, func() (bool, error) {
		tx, err := directory.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			return false, transactionFailure(err)
		}
		defer tx.Rollback()
		if err := directory.lockOwner(ctx, tx); err != nil {
			return false, err
		}
		if err := directory.lockConnectionCapacity(ctx, tx); err != nil {
			return false, err
		}
		var raw []byte
		var installation string
		if err := tx.QueryRowContext(ctx, `select g.scope,i.id::text from users u join devices d on d.user_id=u.id
		 join org_memberships m on m.user_id=u.id join hosts h on h.org_id=m.org_id and h.state='active'
		 join installations i on i.host_id=h.id and i.revoked_at is null join runtimes r on r.installation_id=i.id
		 join runtime_grants g on g.runtime_id=r.id and g.user_id=u.id
		 where u.id=$1 and u.status='active' and d.id=$2 and d.key_version=$3 and d.proof_key_thumbprint=$4 and d.revoked_at is null
		 and r.id=$5 and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+` and g.grant_version=$6 and g.revoked_at is null
		 for share of u,d,m,h,i,r,g`, ticket.UserID, ticket.DeviceID, ticket.DeviceKeyVersion, ticket.ProofKeyThumbprint, ticket.RuntimeID, ticket.GrantVersion).Scan(&raw, &installation); errors.Is(err, sql.ErrNoRows) {
			return false, ErrAccessDenied
		} else if err != nil {
			return false, transactionFailure(err)
		}
		var scope GrantScope
		if json.Unmarshal(raw, &scope) != nil || !grantScopeSubset(ticket.Scope, scope) {
			return false, ErrAccessDenied
		}
		if err := checkCommandGrantTime(ctx, tx, ticket); err != nil {
			return false, err
		}
		if _, err := tx.ExecContext(ctx, `delete from realtime_device_connections where connection_id in(select c.connection_id from realtime_device_connections c left join control_consumers n on n.node_id=c.node_id and n.generation=c.generation where c.expires_at<=least(clock_timestamp(),transaction_timestamp()) or n.node_id is null or n.lease_until<=least(clock_timestamp(),transaction_timestamp()) order by c.expires_at,c.connection_id limit 256)`); err != nil {
			return false, transactionFailure(err)
		}
		if err := directory.checkConnectionCapacity(ctx, tx, ticket.UserID, ticket.DeviceID, installation, ""); err != nil {
			return false, err
		}
		// Occupancy is not authority. Keep a thirty-second clock-skew margin past
		// the fixed five-minute socket life; normal close releases it immediately.
		result, err := tx.ExecContext(ctx, `insert into realtime_device_connections(connection_id,node_id,generation,user_id,device_id,installation_id,runtime_id,expires_at)
		 select $1,$2,$3,$4,$5,$6,$7,clock_timestamp()+interval '5 minutes 30 seconds' where $8>clock_timestamp()`, id, directory.identity.NodeID, directory.identity.Generation, ticket.UserID, ticket.DeviceID, installation, ticket.RuntimeID, expires)
		if err != nil {
			return false, transactionFailure(err)
		}
		rows, err := result.RowsAffected()
		if err != nil || rows != 1 {
			return false, ErrAccessDenied
		}
		if err := checkCommandGrantTime(ctx, tx, ticket); err != nil {
			return false, err
		}
		if err := tx.Commit(); err != nil {
			return false, transactionFailure(err)
		}
		return true, nil
	}, directory.admissionGate())
	return err
}

func (directory *RelayDirectory) ReleaseDeviceConnection(ctx context.Context, id string) error {
	if directory.connectionLimits.limits == nil {
		return nil
	}
	_, err := directory.DB.ExecContext(ctx, `delete from realtime_device_connections where connection_id=$1 and node_id=$2 and generation=$3`, id, directory.identity.NodeID, directory.identity.Generation)
	if err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}
