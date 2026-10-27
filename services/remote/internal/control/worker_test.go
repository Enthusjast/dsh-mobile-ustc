package control

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/observability"
	"dsh-mobile-ustc/services/remote/internal/store"
)

type outboxFixture struct {
	events []store.ControlEvent
	ackErr error
	steps  []string
}

func (fake *outboxFixture) PendingControlEvents(context.Context, int) ([]store.ControlEvent, error) {
	return append([]store.ControlEvent(nil), fake.events...), nil
}

func (fake *outboxFixture) MarkControlEventPublished(_ context.Context, id string) error {
	fake.steps = append(fake.steps, "ack:"+id)
	if fake.ackErr != nil {
		return fake.ackErr
	}
	fake.events = fake.events[1:]
	return nil
}

func TestDispatchRetainsFailedEventsAndReplaysBeforeAcknowledgement(t *testing.T) {
	failure := errors.New("temporary failure")
	for _, stage := range []string{"apply", "ack"} {
		t.Run(stage, func(t *testing.T) {
			fake := &outboxFixture{events: []store.ControlEvent{{ID: "first", Topic: "device.revoked", CreatedAt: time.Now().Add(-time.Second)}, {ID: "second", Topic: "device.revoked", CreatedAt: time.Now().Add(-time.Second)}}}
			metrics := observability.New()
			if stage == "ack" {
				fake.ackErr = failure
			}
			apply := func(_ context.Context, event store.ControlEvent) error {
				fake.steps = append(fake.steps, "apply:"+event.ID)
				if stage == "apply" {
					return failure
				}
				return nil
			}
			if err := DispatchPending(context.Background(), fake, apply, metrics); !errors.Is(err, failure) {
				t.Fatalf("dispatch error=%v", err)
			}
			want := []string{"apply:first"}
			if stage == "ack" {
				want = append(want, "ack:first")
			}
			if !reflect.DeepEqual(fake.steps, want) || len(fake.events) != 2 {
				t.Fatalf("failed event was acknowledged or later event applied: steps=%v pending=%v", fake.steps, fake.events)
			}
			families, err := metrics.Gatherer().Gather()
			if err != nil {
				t.Fatal(err)
			}
			for _, family := range families {
				if family.GetName() == "dsh_remote_control_event_age_seconds" {
					t.Fatal("failed event advanced completed propagation age")
				}
			}
			fake.ackErr, fake.steps = nil, nil
			if err := DispatchPending(context.Background(), fake, func(_ context.Context, event store.ControlEvent) error {
				fake.steps = append(fake.steps, "apply:"+event.ID)
				return nil
			}, metrics); err != nil {
				t.Fatal(err)
			}
			want = []string{"apply:first", "ack:first", "apply:second", "ack:second"}
			if !reflect.DeepEqual(fake.steps, want) || len(fake.events) != 0 {
				t.Fatalf("retry order=%v pending=%v", fake.steps, fake.events)
			}
			families, err = metrics.Gatherer().Gather()
			if err != nil {
				t.Fatal(err)
			}
			observed := false
			for _, family := range families {
				if family.GetName() == "dsh_remote_control_event_age_seconds" {
					observed = len(family.Metric) == 1 && family.Metric[0].GetHistogram().GetSampleCount() == 2
				}
			}
			if !observed {
				t.Fatal("successful retry did not observe both completed publications")
			}
		})
	}
}

type blockedOutbox struct{ started chan struct{} }

func (fake blockedOutbox) PendingControlEvents(ctx context.Context, _ int) ([]store.ControlEvent, error) {
	close(fake.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockedOutbox) MarkControlEventPublished(context.Context, string) error { return nil }

type leaseProbe struct{ checked chan struct{} }

func (leaseProbe) ApplyControlEvent(context.Context, store.ControlEvent) error { return nil }
func (probe leaseProbe) RevalidateConnections(ctx context.Context) error {
	select {
	case probe.checked <- struct{}{}:
	default:
	}
	return ctx.Err()
}

func TestLeaseChecksContinueWhileOutboxIsBlockedAndStopWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := blockedOutbox{started: make(chan struct{})}
	probe := leaseProbe{checked: make(chan struct{}, 1)}
	done := make(chan struct{})
	go func() { defer close(done); Run(ctx, fake, probe) }()
	deadline := time.After(time.Second)
	select {
	case <-fake.started:
	case <-deadline:
		t.Fatal("outbox did not start")
	}
	select {
	case <-probe.checked:
	case <-deadline:
		t.Fatal("outbox delayed authoritative lease checks")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("workers did not stop with context")
	}
}
