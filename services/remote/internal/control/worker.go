package control

import (
	"context"
	"log"
	"sync"
	"time"

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

func DispatchPending(ctx context.Context, repository Repository, apply func(context.Context, store.ControlEvent) error) error {
	events, err := repository.PendingControlEvents(ctx, 128)
	if err != nil {
		return err
	}
	for _, event := range events {
		if err := apply(ctx, event); err != nil {
			return err
		}
		if err := repository.MarkControlEventPublished(ctx, event.ID); err != nil {
			return err
		}
	}
	return nil
}

// Run supports the current single-process Relay deployment. Outbox delivery and
// authoritative lease checks are independent, so event backlog cannot postpone
// grant expiry, device/key revocation or database-outage handling.
func Run(ctx context.Context, repository Repository, relay Relay) {
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		repeat(ctx, 250*time.Millisecond, "outbox", func(ctx context.Context) error {
			return DispatchPending(ctx, repository, relay.ApplyControlEvent)
		})
	}()
	go func() {
		defer workers.Done()
		repeat(ctx, time.Second, "leases", relay.RevalidateConnections)
	}()
	workers.Wait()
}

func repeat(ctx context.Context, interval time.Duration, name string, operation func(context.Context) error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	unavailable := false
	for ctx.Err() == nil {
		attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := operation(attempt)
		cancel()
		if ctx.Err() != nil {
			return
		}
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
