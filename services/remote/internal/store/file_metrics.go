package store

import (
	"context"
	"sync"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
	"dsh-mobile-ustc/services/remote/internal/observability"
)

type fileObservation struct {
	once    sync.Once
	metrics *observability.Metrics
}

// ConfigureFileMetrics is startup-only, before handlers or workers run.
func (postgres *Postgres) ConfigureFileMetrics(metrics *observability.Metrics) error {
	configured := false
	postgres.files.once.Do(func() { postgres.files.metrics = metrics; configured = true })
	if !configured {
		return ErrDatabaseConfig
	}
	return nil
}

func (repository *FileStore) observeHandoffOperation(ctx context.Context, operation string, started time.Time, err error) {
	if err != nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	repository.database.files.metrics.FileHandoffOperation(operation, files.FileOperationResult(err), time.Since(started))
}
