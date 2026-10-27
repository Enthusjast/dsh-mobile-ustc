package control

import (
	"context"
	"errors"
	"time"

	"dsh-mobile-ustc/services/remote/internal/observability"
	"dsh-mobile-ustc/services/remote/internal/store"
)

type ConsumerRepository interface {
	Repository
	Renew(context.Context) error
	PruneEphemeral(context.Context) error
}

type fencedRepository struct {
	ConsumerRepository
	failure chan<- error
}

func (repository fencedRepository) report(err error) {
	if errors.Is(err, store.ErrControlConsumerFenced) || errors.Is(err, store.ErrGrantInvalid) {
		select {
		case repository.failure <- err:
		default:
		}
	}
}
func (repository fencedRepository) PendingControlEvents(ctx context.Context, limit int) ([]store.ControlEvent, error) {
	events, err := repository.ConsumerRepository.PendingControlEvents(ctx, limit)
	repository.report(err)
	return events, err
}
func (repository fencedRepository) MarkControlEventPublished(ctx context.Context, id string) error {
	err := repository.ConsumerRepository.MarkControlEventPublished(ctx, id)
	repository.report(err)
	return err
}

// RunConsumer retains independent per-operation authority checks while renewing
// exclusive dispatcher ownership. A lost/unknown lease ends service admission;
// only the process coordinator releases ownership after draining its sockets.
func RunConsumer(ctx context.Context, repository ConsumerRepository, relay Relay, metrics *observability.Metrics) error {
	worker, cancel := context.WithCancel(ctx)
	defer cancel()
	fatal := make(chan error, 1)
	done := make(chan struct{})
	go func() { defer close(done); Run(worker, fencedRepository{repository, fatal}, relay, metrics) }()
	defer func() { cancel(); <-done }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	iterations := 0
	for {
		attempt, stop := context.WithTimeout(worker, 2*time.Second)
		started := time.Now()
		err := repository.Renew(attempt)
		stop()
		iterations++
		if ctx.Err() != nil {
			metrics.ControlRun("consumer", "cancelled", time.Since(started))
			return nil
		}
		result := "ok"
		if err != nil {
			result = "error"
		}
		metrics.ControlRun("consumer", result, time.Since(started))
		if err != nil {
			return err
		}
		if iterations%60 == 1 {
			cleanup, stop := context.WithTimeout(worker, 2*time.Second)
			begin := time.Now()
			cleanupErr := repository.PruneEphemeral(cleanup)
			stop()
			result := "ok"
			if cleanupErr != nil {
				result = "error"
			}
			metrics.ControlRun("consumer_cleanup", result, time.Since(begin))
		}
		select {
		case <-ctx.Done():
			return nil
		case err := <-fatal:
			return err
		case <-ticker.C:
		}
	}
}
