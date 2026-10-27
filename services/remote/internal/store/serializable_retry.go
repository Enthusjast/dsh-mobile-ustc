package store

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

const serializableAttempts = 16

// Keep SQLSTATE available inside the transaction retry boundary, while retaining
// the established public database error and never formatting driver details.
type transactionFailureError struct{ cause error }

func (failure *transactionFailureError) Error() string { return ErrDatabaseUnavailable.Error() }
func (failure *transactionFailureError) Unwrap() error { return failure.cause }
func (failure *transactionFailureError) Is(target error) bool {
	return target == ErrDatabaseUnavailable
}
func transactionFailure(cause error) error { return &transactionFailureError{cause: cause} }

// The callback must execute a whole database-only transaction and finish its
// rollback before returning. Only PostgreSQL-confirmed aborts may repeat; an
// unknown commit outcome, connection loss or a business denial must not repeat.
func retrySerializable[T any](ctx context.Context, operation func() (T, error), limiters ...chan struct{}) (T, error) {
	var zero T
	var gate chan struct{}
	if len(limiters) > 0 {
		gate = limiters[0]
	}
	for attempt := 0; attempt < serializableAttempts; attempt++ {
		if ctx.Err() != nil {
			return zero, ErrDatabaseUnavailable
		}
		if gate != nil {
			select {
			case gate <- struct{}{}:
			case <-ctx.Done():
				return zero, ErrDatabaseUnavailable
			}
			if ctx.Err() != nil {
				<-gate
				return zero, ErrDatabaseUnavailable
			}
		}
		value, err := func() (T, error) {
			if gate != nil {
				defer func() { <-gate }()
			}
			return operation()
		}()
		if err == nil {
			return value, nil
		}
		var postgresError *pgconn.PgError
		retry := errors.As(err, &postgresError) && (postgresError.Code == "40001" || postgresError.Code == "40P01")
		if !retry {
			if errors.Is(err, ErrDatabaseUnavailable) {
				return zero, ErrDatabaseUnavailable
			}
			return zero, err
		}
		if attempt == serializableAttempts-1 {
			return zero, ErrDatabaseUnavailable
		}
		delay := time.Duration(1<<min(attempt, 4)) * 5 * time.Millisecond
		delay += time.Duration(rand.Int64N(int64(delay) + 1))
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return zero, ErrDatabaseUnavailable
		case <-timer.C:
		}
	}
	return zero, ErrDatabaseUnavailable
}
