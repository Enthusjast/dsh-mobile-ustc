package store

import (
	"context"
	"errors"
	"sync"
	"time"

	"dsh-mobile-ustc/services/remote/internal/approval"
	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/observability"
)

type approvalObservation struct {
	once    sync.Once
	metrics *observability.Metrics
}
type endedApprovalObservation struct {
	before string
	status ApprovalStatus
}

// Startup-only optional observer; no resource IDs or proof bytes enter labels.
func (postgres *Postgres) ConfigureApprovalMetrics(metrics *observability.Metrics) error {
	configured := false
	postgres.approvals.once.Do(func() { postgres.approvals.metrics = metrics; configured = true })
	if !configured {
		return ErrDatabaseConfig
	}
	return nil
}
func (postgres *Postgres) observeApproval(cause string, before, after ApprovalStatus) {
	postgres.approvals.metrics.ApprovalTransition(cause, before.State, after.State, before.HostState, after.HostState, after.Outcome)
}
func (postgres *Postgres) observeEndedApprovals(cause string, ended []endedApprovalObservation) {
	for _, item := range ended {
		postgres.approvals.metrics.ApprovalTransition(cause, item.before, item.status.State, item.status.HostState, item.status.HostState, item.status.Outcome)
	}
}
func (postgres *Postgres) observeApprovalOperation(ctx context.Context, operation string, started time.Time, err error) {
	result := "ok"
	if err != nil {
		switch {
		case ctx.Err() != nil:
			result = "cancelled"
		case errors.Is(err, ErrApprovalExpired):
			result = "expired"
		case errors.Is(err, ErrAccessDenied), errors.Is(err, ErrRuntimeConnectionStale), errors.Is(err, auth.ErrAssurance):
			result = "denied"
		case errors.Is(err, ErrApprovalConflict):
			result = "conflict"
		case errors.Is(err, ErrApprovalInvalid), errors.Is(err, approval.ErrContext), errors.Is(err, approval.ErrDecision), errors.Is(err, approval.ErrAuthorization):
			result = "invalid"
		default:
			result = "error"
		}
	}
	postgres.approvals.metrics.ApprovalOperation(operation, result, time.Since(started))
}
