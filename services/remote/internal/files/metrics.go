package files

import (
	"context"
	"errors"

	"dsh-mobile-ustc/services/remote/internal/observability"
)

// ConfigureMetrics is startup-only, before Run or any requests. A nil registry
// preserves the existing disabled-metrics path.
func (service *Service) ConfigureMetrics(metrics *observability.Metrics) error {
	configured := false
	service.metricsOnce.Do(func() { service.metrics = metrics; configured = true })
	if !configured {
		return ErrInvalid
	}
	return nil
}

// FileOperationResult maps only known sentinels, never exception text, into
// bounded labels shared by scan workers and handoff repository attempts.
func FileOperationResult(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, ErrAccess):
		return "access_denied"
	case errors.Is(err, ErrStale):
		return "stale"
	case errors.Is(err, ErrRejected):
		return "rejected"
	case errors.Is(err, ErrIntegrity):
		return "integrity"
	case errors.Is(err, ErrScanUnavailable):
		return "scanner_unavailable"
	case errors.Is(err, ErrConflict):
		return "conflict"
	case errors.Is(err, ErrQuota):
		return "quota"
	case errors.Is(err, ErrInvalid):
		return "invalid"
	default:
		return "unavailable"
	}
}
