package store

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"strings"
	"time"
)

type RelayNode struct {
	NodeID     string `json:"node_id"`
	Generation string `json:"generation"`
	Origin     string `json:"origin"`
}

type RuntimeRoute struct {
	RelayNode
	RuntimeID    string `json:"runtime_id"`
	RuntimeEpoch string `json:"runtime_epoch"`
	ConnectionID string `json:"connection_id"`
}

// RelayDirectory adds incarnation fencing to the production repository. The
// embedded library repository remains usable by single-process fixtures.
type RelayDirectory struct {
	*Postgres
	consumer *ControlConsumer
	identity RelayNode
}

func ValidRelayOrigin(origin string) bool {
	if origin == "" || len(origin) > 2048 || strings.TrimSpace(origin) != origin {
		return false
	}
	parsed, err := url.Parse(origin)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil &&
		parsed.Path == "" && parsed.RawPath == "" && parsed.RawQuery == "" && !parsed.ForceQuery && parsed.Fragment == "" &&
		parsed.Opaque == "" && parsed.String() == origin
}

func (consumer *ControlConsumer) NewRelayDirectory(ctx context.Context, origin string) (*RelayDirectory, error) {
	if origin != "" && !ValidRelayOrigin(origin) {
		return nil, ErrDatabaseConfig
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	transaction, err := consumer.postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	if _, err := consumer.lock(ctx, transaction); err != nil {
		return nil, err
	}
	if _, err := transaction.ExecContext(ctx, `update control_consumers set relay_origin=nullif($3,'') where node_id=$1 and generation=$2`, consumer.node, consumer.generation, origin); err != nil {
		return nil, ErrDatabaseUnavailable
	}
	if err := transaction.Commit(); err != nil {
		return nil, ErrDatabaseUnavailable
	}
	return &RelayDirectory{consumer.postgres, consumer, RelayNode{consumer.node, consumer.generation, origin}}, nil
}

func (directory *RelayDirectory) RelayIdentity() RelayNode { return directory.identity }

func (directory *RelayDirectory) lockOwner(ctx context.Context, tx *sql.Tx) error {
	var generation string
	var until, now time.Time
	err := tx.QueryRowContext(ctx, `select generation::text,lease_until from control_consumers where node_id=$1 for share`, directory.identity.NodeID).Scan(&generation, &until)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrControlConsumerFenced
	}
	if err != nil {
		return transactionFailure(err)
	}
	if err := tx.QueryRowContext(ctx, `select clock_timestamp()`).Scan(&now); err != nil {
		return transactionFailure(err)
	}
	if generation != directory.identity.Generation || !until.After(now) {
		return ErrControlConsumerFenced
	}
	return nil
}

func routeOwnerCondition(directory *RelayDirectory, active bool) (string, []any) {
	if directory == nil {
		return "", nil
	}
	condition := ` and exists(select 1 from relay_runtime_routes route where route.runtime_id=r.id
        and route.runtime_epoch=$3 and route.connection_id=$4 and route.node_id=$5 and route.generation=$6`
	if active {
		condition += ` and exists(select 1 from control_consumers node where node.node_id=route.node_id and node.generation=route.generation and node.lease_until>clock_timestamp())`
	}
	return condition + `)`, []any{directory.identity.NodeID, directory.identity.Generation}
}

// No timestamp cache: each admission resolves current committed ownership.
// Stale directory rows survive a crash harmlessly and are replaced on attach.
func (directory *RelayDirectory) LookupRuntimeRoute(ctx context.Context, runtime string) (RuntimeRoute, error) {
	if !grantUUIDPattern.MatchString(runtime) {
		return RuntimeRoute{}, ErrGrantInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var route RuntimeRoute
	err := directory.DB.QueryRowContext(ctx, `select route.node_id::text,route.generation::text,coalesce(node.relay_origin,''),
        route.runtime_id::text,route.runtime_epoch::text,route.connection_id::text
        from relay_runtime_routes route
        join control_consumers node on node.node_id=route.node_id and node.generation=route.generation and node.lease_until>clock_timestamp()
        join runtimes r on r.id=route.runtime_id and r.epoch=route.runtime_epoch and r.connection_id=route.connection_id
            and r.revoked_at is null and r.last_seen_at>clock_timestamp()-interval '45 seconds'
        join installations i on i.id=r.installation_id and i.revoked_at is null and i.key_version=r.connection_key_version
        join hosts h on h.id=i.host_id and h.state='active'
        where route.runtime_id=$1 and `+runtimeEnrollmentApprovedSQL, runtime).Scan(&route.NodeID, &route.Generation, &route.Origin, &route.RuntimeID, &route.RuntimeEpoch, &route.ConnectionID)
	if errors.Is(err, sql.ErrNoRows) {
		return RuntimeRoute{}, ErrRuntimeConnectionStale
	}
	if err != nil {
		return RuntimeRoute{}, ErrDatabaseUnavailable
	}
	if route.Origin != "" && !ValidRelayOrigin(route.Origin) {
		return RuntimeRoute{}, ErrDatabaseConfig
	}
	return route, nil
}

func (directory *RelayDirectory) ValidateRelayNode(ctx context.Context, node, generation string) error {
	if !grantUUIDPattern.MatchString(node) || !grantUUIDPattern.MatchString(generation) {
		return ErrControlConsumerFenced
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var valid bool
	if err := directory.DB.QueryRowContext(ctx, `select exists(select 1 from control_consumers where node_id=$1 and generation=$2 and relay_origin is not null and lease_until>clock_timestamp())`, node, generation).Scan(&valid); err != nil {
		return ErrDatabaseUnavailable
	}
	if !valid {
		return ErrControlConsumerFenced
	}
	return nil
}

func (directory *RelayDirectory) AttachRuntimeConnection(ctx context.Context, input RuntimeConnectionInput) (RuntimeConnection, error) {
	return retrySerializable(ctx, func() (RuntimeConnection, error) {
		return directory.attachRuntimeConnectionOwned(ctx, input, directory)
	}, directory.admissionGate())
}

func (directory *RelayDirectory) TouchRuntimeConnection(ctx context.Context, installation, runtime, epoch, connection string) error {
	return directory.touchRuntimeConnectionOwned(ctx, installation, runtime, epoch, connection, directory)
}

func (directory *RelayDirectory) DetachRuntimeConnection(ctx context.Context, installation, runtime, epoch, connection string) error {
	return directory.detachRuntimeConnectionOwned(ctx, installation, runtime, epoch, connection, directory)
}
