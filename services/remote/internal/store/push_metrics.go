package store

import (
	"context"
	"errors"
	"sync"
	"time"

	"dsh-mobile-ustc/services/remote/internal/observability"
	"dsh-mobile-ustc/services/remote/internal/push"
)

type pushObservation struct {
	once    sync.Once
	metrics *observability.Metrics
}

// Startup-only; observers run after confirmed commits and never inspect secrets.
func (postgres *Postgres) ConfigurePushMetrics(metrics *observability.Metrics) error {
	configured := false
	postgres.push.once.Do(func() { postgres.push.metrics = metrics; configured = true })
	if !configured {
		return ErrDatabaseConfig
	}
	return nil
}

func (store *PushStore) observePushOperation(ctx context.Context, operation string, started time.Time, err error) {
	result := "ok"
	if err != nil {
		switch {
		case errors.Is(ctx.Err(), context.Canceled):
			result = "cancelled"
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			result = "timeout"
		case errors.Is(err, push.ErrAccess):
			result = "access_denied"
		case errors.Is(err, push.ErrExpired):
			result = "expired"
		case errors.Is(err, push.ErrLease):
			result = "lease"
		case errors.Is(err, push.ErrConflict):
			result = "conflict"
		case errors.Is(err, push.ErrInvalid):
			result = "invalid"
		default:
			result = "unavailable"
		}
	}
	store.database.push.metrics.PushOperation(operation, result, time.Since(started))
}
