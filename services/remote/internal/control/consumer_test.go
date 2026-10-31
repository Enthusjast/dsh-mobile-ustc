package control

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

type consumerFixture struct {
	pending func(context.Context) ([]store.ControlEvent, error)
	renew   func(context.Context) error
	expire  func(context.Context) (int, error)
}

func (fixture consumerFixture) PendingControlEvents(ctx context.Context, _ int) ([]store.ControlEvent, error) {
	return fixture.pending(ctx)
}
func (consumerFixture) MarkControlEventPublished(context.Context, string) error { return nil }
func (fixture consumerFixture) Renew(ctx context.Context) error                 { return fixture.renew(ctx) }
func (consumerFixture) PruneEphemeral(context.Context) error                    { return nil }
func (fixture consumerFixture) ExpireApprovals(ctx context.Context, _ int) (int, error) {
	if fixture.expire != nil {
		return fixture.expire(ctx)
	}
	return 0, nil
}

func TestControlConsumerLostAuthorityStopsBlockedDispatcher(t *testing.T) {
	started := make(chan struct{})
	checked := make(chan struct{}, 1)
	fixture := consumerFixture{pending: func(ctx context.Context) ([]store.ControlEvent, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	},
		renew: func(ctx context.Context) error {
			select {
			case <-started:
			case <-ctx.Done():
				return ctx.Err()
			}
			select {
			case <-checked:
			case <-ctx.Done():
				return ctx.Err()
			}
			return store.ErrControlConsumerFenced
		}}
	done := make(chan error, 1)
	go func() { done <- RunConsumer(context.Background(), fixture, leaseProbe{checked: checked}, nil) }()
	select {
	case err := <-done:
		if !errors.Is(err, store.ErrControlConsumerFenced) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("fenced consumer left a blocked dispatcher alive")
	}
}

func TestControlConsumerMalformedEventIsTerminalAndCancellationIsNormal(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		checked := make(chan struct{}, 1)
		fixture := consumerFixture{pending: func(ctx context.Context) ([]store.ControlEvent, error) {
			if malformed {
				return nil, store.ErrGrantInvalid
			}
			<-ctx.Done()
			return nil, ctx.Err()
		}, renew: func(context.Context) error { return nil }}
		done := make(chan error, 1)
		go func() { done <- RunConsumer(ctx, fixture, leaseProbe{checked: checked}, nil) }()
		if !malformed {
			select {
			case <-checked:
			case <-time.After(time.Second):
				t.Fatal("independent authority worker did not start")
			}
			cancel()
		}
		select {
		case err := <-done:
			if malformed && !errors.Is(err, store.ErrGrantInvalid) || !malformed && err != nil {
				t.Fatal("unexpected consumer shutdown", err)
			}
		case <-time.After(time.Second):
			t.Fatal("consumer failed to end")
		}
		cancel()
	}
}

func TestApprovalExpiryDoesNotDelayRenewalOutboxOrLeaseChecks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	expiring, renewed, dispatched := make(chan struct{}, 1), make(chan struct{}, 1), make(chan struct{}, 1)
	var renewals atomic.Int32
	fixture := consumerFixture{
		pending: func(context.Context) ([]store.ControlEvent, error) {
			select {
			case dispatched <- struct{}{}:
			default:
			}
			return nil, nil
		},
		renew: func(context.Context) error {
			if renewals.Add(1) >= 2 {
				select {
				case renewed <- struct{}{}:
				default:
				}
			}
			return nil
		},
		expire: func(ctx context.Context) (int, error) {
			select {
			case expiring <- struct{}{}:
			default:
			}
			<-ctx.Done()
			return 0, ctx.Err()
		},
	}
	probe := leaseProbe{checked: make(chan struct{}, 1)}
	done := make(chan error, 1)
	go func() { done <- RunConsumer(ctx, fixture, probe, nil) }()
	for _, ready := range []chan struct{}{expiring, renewed, dispatched, probe.checked} {
		select {
		case <-ready:
		case <-time.After(1500 * time.Millisecond):
			t.Fatal("blocked expiry delayed an independent worker")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("expiry worker was not joined on shutdown")
	}
}

func TestApprovalExpiryFencingEndsServiceWorkers(t *testing.T) {
	fixture := consumerFixture{
		pending: func(ctx context.Context) ([]store.ControlEvent, error) { <-ctx.Done(); return nil, ctx.Err() },
		renew:   func(context.Context) error { return nil },
		expire:  func(context.Context) (int, error) { return 0, store.ErrControlConsumerFenced },
	}
	done := make(chan error, 1)
	go func() {
		done <- RunConsumer(context.Background(), fixture, leaseProbe{checked: make(chan struct{}, 1)}, nil)
	}()
	select {
	case err := <-done:
		if !errors.Is(err, store.ErrControlConsumerFenced) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("fenced expiry left service workers running")
	}
}
