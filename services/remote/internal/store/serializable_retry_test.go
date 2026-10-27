package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestSerializableRetryRepeatsOnlyConfirmedAbortStates(t *testing.T) {
	for _, code := range []string{"40001", "40P01", "23505", "08006"} {
		t.Run(code, func(t *testing.T) {
			calls := 0
			value, err := retrySerializable(context.Background(), func() (int, error) {
				calls++
				if calls == 1 {
					return 99, transactionFailure(&pgconn.PgError{Code: code})
				}
				return 7, nil
			})
			if code == "40001" || code == "40P01" {
				if calls != 2 || err != nil || value != 7 {
					t.Fatal("confirmed abort did not restart the full callback", calls, err, value)
				}
			} else if calls != 1 || err != ErrDatabaseUnavailable || value != 0 {
				t.Fatal("non-abort database failure was repeated or leaked a result", calls, err, value)
			}
		})
	}
	for _, failure := range []error{ErrAccessDenied, ErrHostChallengeLimit, transactionFailure(errors.New("unknown commit outcome"))} {
		calls := 0
		value, err := retrySerializable(context.Background(), func() (int, error) { calls++; return 99, failure })
		if calls != 1 || value != 0 || err == nil {
			t.Fatal("denial or ambiguous outcome repeated")
		}
	}
}

func TestSerializableRetryIsBoundedAndHonorsCancellation(t *testing.T) {
	calls := 0
	_, err := retrySerializable(context.Background(), func() (int, error) { calls++; return 0, transactionFailure(&pgconn.PgError{Code: "40001"}) })
	if calls != serializableAttempts || err != ErrDatabaseUnavailable {
		t.Fatal("retry budget not enforced", calls, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	_, err = retrySerializable(ctx, func() (int, error) { calls++; cancel(); return 0, transactionFailure(&pgconn.PgError{Code: "40001"}) })
	if calls != 1 || err != ErrDatabaseUnavailable {
		t.Fatal("cancelled request started another transaction", calls, err)
	}
}

type observedQueueContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

func (ctx *observedQueueContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.observed) })
	return ctx.Context.Done()
}

func TestSerializableAdmissionQueueCancelsBeforeOpeningAndReleasesOnPanic(t *testing.T) {
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waiting := &observedQueueContext{Context: ctx, observed: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		_, err := retrySerializable(waiting, func() (int, error) { t.Error("cancelled queued request opened a transaction"); return 1, nil }, gate)
		done <- err
	}()
	select {
	case <-waiting.observed:
	case <-time.After(time.Second):
		t.Fatal("request never reached the admission wait")
	}
	cancel()
	select {
	case err := <-done:
		if err != ErrDatabaseUnavailable {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued cancellation was ignored")
	}
	if len(gate) != 1 {
		t.Fatal("cancelled waiter stole another holder's slot")
	}
	<-gate
	func() {
		defer func() {
			if recover() == nil {
				t.Error("fixture panic was hidden")
			}
		}()
		_, _ = retrySerializable(context.Background(), func() (int, error) { panic("fixture") }, gate)
	}()
	if len(gate) != 0 {
		t.Fatal("panicking callback leaked the admission slot")
	}
	if value, err := retrySerializable(context.Background(), func() (int, error) { return 7, nil }, gate); err != nil || value != 7 {
		t.Fatal("admission did not recover after panic", err)
	}
}

func TestSerializableAdmissionBudgetIsValidatedAndImmutableAfterUse(t *testing.T) {
	postgres := &Postgres{}
	if err := postgres.ConfigureSerializableAdmissions(0); err != ErrDatabaseConfig {
		t.Fatal("invalid zero budget was accepted")
	}
	if err := postgres.ConfigureSerializableAdmissions(MaximumSerializableAdmissions + 1); err != ErrDatabaseConfig {
		t.Fatal("budget exceeded database pool")
	}
	if err := postgres.ConfigureSerializableAdmissions(2); err != nil || cap(postgres.admissionGate()) != 2 {
		t.Fatal("startup budget was not applied", err)
	}
	if err := postgres.ConfigureSerializableAdmissions(3); err != ErrDatabaseConfig || cap(postgres.admissionGate()) != 2 {
		t.Fatal("live budget was resized")
	}
	defaulted := &Postgres{}
	if cap(defaulted.admissionGate()) != DefaultSerializableAdmissions {
		t.Fatal("default budget changed")
	}
	if err := defaulted.ConfigureSerializableAdmissions(2); err != ErrDatabaseConfig {
		t.Fatal("an observed default gate was replaced")
	}
}
