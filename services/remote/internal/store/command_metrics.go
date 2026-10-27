package store

import (
	"context"
	"errors"
	"sync"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
	"dsh-mobile-ustc/services/remote/internal/observability"
)

type commandObservation struct {
	once    sync.Once
	metrics *observability.Metrics
}

// Startup only, before handlers/workers can observe this repository. It never
// changes the active command state machine or emits resource identities.
func (postgres *Postgres) ConfigureCommandMetrics(metrics *observability.Metrics) error {
	configured := false
	postgres.commands.once.Do(func() { postgres.commands.metrics = metrics; configured = true })
	if !configured {
		return ErrDatabaseConfig
	}
	return nil
}

func (postgres *Postgres) observeCommandStore(ctx context.Context, operation string, started time.Time, err error) {
	result := "ok"
	if err != nil {
		switch {
		case ctx.Err() != nil:
			result = "cancelled"
		case errors.Is(err, ErrAccessDenied), errors.Is(err, files.ErrAccess), errors.Is(err, ErrRuntimeConnectionStale):
			result = "denied"
		case errors.Is(err, ErrCommandConflict), errors.Is(err, files.ErrConflict):
			result = "conflict"
		case errors.Is(err, files.ErrStale):
			result = "not_ready"
		case errors.Is(err, ErrGrantInvalid), errors.Is(err, ErrCommandTransition), errors.Is(err, ErrSessionCatalogInvalid), errors.Is(err, files.ErrInvalid):
			result = "invalid"
		default:
			result = "error"
		}
	}
	postgres.commands.metrics.CommandStore(operation, result, time.Since(started))
}
