package control

import (
	"context"
	"errors"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

type consumerFixture struct {
	pending func(context.Context) ([]store.ControlEvent, error)
	renew   func(context.Context) error
}

func (fixture consumerFixture) PendingControlEvents(ctx context.Context, _ int) ([]store.ControlEvent, error) {
	return fixture.pending(ctx)
}
func (consumerFixture) MarkControlEventPublished(context.Context, string) error { return nil }
func (fixture consumerFixture) Renew(ctx context.Context) error                 { return fixture.renew(ctx) }
func (consumerFixture) PruneEphemeral(context.Context) error                    { return nil }

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
