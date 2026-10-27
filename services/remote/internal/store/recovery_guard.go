package store

import (
	"context"
	"database/sql"
	"dsh-mobile-ustc/services/remote/internal/auth"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

const OriginalDatabaseEpoch = auth.OriginalDatabaseEpoch

var ErrRecoveryUnavailable = errors.New("store: database recovery is not ready for this deployment epoch")

type RecoveryState struct {
	Epoch          string     `json:"epoch"`
	Phase          string     `json:"phase"`
	RecoveryID     *string    `json:"recovery_id"`
	TokenNotBefore *time.Time `json:"token_not_before"`
}

func recoveryState(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, lock string) (RecoveryState, error) {
	var state RecoveryState
	if err := query.QueryRowContext(ctx, `select epoch::text,phase,recovery_id::text,token_not_before from remote_recovery_state where slot=1`+lock).Scan(&state.Epoch, &state.Phase, &state.RecoveryID, &state.TokenNotBefore); err != nil {
		return state, ErrDatabaseUnavailable
	}
	return state, nil
}

func (postgres *Postgres) RecoveryStatus(ctx context.Context) (RecoveryState, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return recoveryState(ctx, postgres.DB, "")
}

func lockRecoveryReady(ctx context.Context, tx *sql.Tx, expected string) (RecoveryState, error) {
	state, err := recoveryState(ctx, tx, " for share")
	if err != nil {
		return state, err
	}
	if state.Phase != "ready" || expected != "" && state.Epoch != expected {
		return state, ErrRecoveryUnavailable
	}
	return state, nil
}

type RecoveryGuard struct {
	postgres *Postgres
	state    RecoveryState
}

func (postgres *Postgres) NewRecoveryGuard(ctx context.Context, configuredEpoch string) (*RecoveryGuard, error) {
	if configuredEpoch == "" {
		configuredEpoch = OriginalDatabaseEpoch
	}
	if !grantUUIDPattern.MatchString(configuredEpoch) {
		return nil, ErrDatabaseConfig
	}
	state, err := postgres.RecoveryStatus(ctx)
	if err != nil {
		return nil, err
	}
	if state.Epoch != configuredEpoch || state.Phase != "ready" {
		return nil, ErrRecoveryUnavailable
	}
	return &RecoveryGuard{postgres, state}, nil
}

func (guard *RecoveryGuard) Epoch() string { return guard.state.Epoch }
func (guard *RecoveryGuard) TokenNotBefore() time.Time {
	if guard.state.TokenNotBefore == nil {
		return time.Time{}
	}
	return *guard.state.TokenNotBefore
}
func (guard *RecoveryGuard) Check(ctx context.Context) error {
	state, err := guard.postgres.RecoveryStatus(ctx)
	if err != nil {
		return err
	}
	if state.Epoch != guard.state.Epoch || state.Phase != "ready" || !sameRecoveryCutoff(state.TokenNotBefore, guard.state.TokenNotBefore) {
		return ErrRecoveryUnavailable
	}
	return nil
}
func sameRecoveryCutoff(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func (guard *RecoveryGuard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		if err := guard.Check(r.Context()); err != nil {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": map[string]string{"code": "internal"}})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Independently ends upgraded connections/workers through the process
// coordinator. HTTP admission never waits for this background check.
func (guard *RecoveryGuard) Run(ctx context.Context) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if err := guard.Check(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
