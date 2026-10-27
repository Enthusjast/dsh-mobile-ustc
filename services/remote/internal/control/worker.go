package control

import (
	"context"
	"log"
	"sync"
	"time"

	"dsh-mobile-ustc/services/remote/internal/observability"
	"dsh-mobile-ustc/services/remote/internal/store"
)

type Repository interface {
	PendingControlEvents(context.Context, int) ([]store.ControlEvent, error)
	MarkControlEventPublished(context.Context, string) error
}

type Relay interface {
	ApplyControlEvent(context.Context, store.ControlEvent) error
	RevalidateConnections(context.Context) error
}

func DispatchPending(ctx context.Context, repository Repository, apply func(context.Context, store.ControlEvent) error, observers ...*observability.Metrics) error {
	var metrics *observability.Metrics
	if len(observers) > 0 {
		metrics = observers[0]
	}
	events, err := repository.PendingControlEvents(ctx, 128)
	if err != nil {
		return err
	}
	for _, event := range events {
		if err := apply(ctx, event); err != nil {
			metrics.ControlEvent(event.Topic, "apply_error", event.CreatedAt)
			return err
		}
		if err := repository.MarkControlEventPublished(ctx, event.ID); err != nil {
			metrics.ControlEvent(event.Topic, "ack_error", event.CreatedAt)
			return err
		}
		metrics.ControlEvent(event.Topic, "published", event.CreatedAt)
	}
	return nil
}

// Run supports the current single-process Relay deployment. Outbox delivery and
// authoritative lease checks are independent, so event backlog cannot postpone
// grant expiry, device/key revocation or database-outage handling.
func Run(ctx context.Context, repository Repository, relay Relay, observers ...*observability.Metrics) {
	var metrics *observability.Metrics
	if len(observers) > 0 {
		metrics = observers[0]
	}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		repeat(ctx, 250*time.Millisecond, "outbox", func(ctx context.Context) error {
			return DispatchPending(ctx, repository, relay.ApplyControlEvent, metrics)
		}, metrics)
	}()
	go func() {
		defer workers.Done()
		repeat(ctx, time.Second, "leases", relay.RevalidateConnections, metrics)
	}()
	workers.Wait()
}

func repeat(ctx context.Context, interval time.Duration, name string, operation func(context.Context) error, metrics *observability.Metrics) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	unavailable := false
	for ctx.Err() == nil {
		attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
		started := time.Now()
		err := operation(attempt)
		cancel()
		if ctx.Err() != nil {
			metrics.ControlRun(name, "cancelled", time.Since(started))
			return
		}
		result := "ok"
		if err != nil {
			result = "error"
		}
		metrics.ControlRun(name, result, time.Since(started))
		if (err != nil) != unavailable {
			unavailable = err != nil
			log.Printf("remote control %s unavailable=%t", name, unavailable)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
