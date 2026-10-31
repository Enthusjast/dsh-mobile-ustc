package store

import (
	"context"
	"database/sql"
)

// Both limit families coordinate with the same production startup registry.
func lockLimitPolicyConsumers(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `lock table control_consumers in share row exclusive mode`); err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}
func requireQuietPolicyConsumers(ctx context.Context, tx *sql.Tx, busy error) error {
	var active bool
	if err := tx.QueryRowContext(ctx, `select exists(select 1 from control_consumers where lease_until>clock_timestamp())`).Scan(&active); err != nil {
		return ErrDatabaseUnavailable
	}
	if active {
		return busy
	}
	return nil
}
