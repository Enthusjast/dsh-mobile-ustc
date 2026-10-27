package store

import (
	"context"

	"dsh-mobile-ustc/services/remote/internal/observability"
)

// UnknownResults uses one MVCC statement snapshot, independent of local metric
// counters. Retained historical/recovery rows count until their state changes or
// retention removes them. This read never authorizes or reconciles an operation.
func (postgres *Postgres) UnknownResults(ctx context.Context) (observability.UnknownResultCounts, error) {
	var counts observability.UnknownResultCounts
	err := postgres.DB.QueryRowContext(ctx, `select
	 (select count(*) from commands where state='outcome_unknown'),
	 (select count(*) from approvals where state='outcome_unknown')`).Scan(&counts.Commands, &counts.Approvals)
	if err != nil {
		return observability.UnknownResultCounts{}, ErrDatabaseUnavailable
	}
	return counts, nil
}
