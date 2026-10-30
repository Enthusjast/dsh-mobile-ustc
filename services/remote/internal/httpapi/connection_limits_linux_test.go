package httpapi_test

import (
	"crypto/sha256"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

func TestProductionSharedConnectionLimitSurvivesIngressAndOwnerMigration(t *testing.T) {
	limits := store.ConnectionLimits{Version: 1, Total: 10, User: 10, Device: 1, Installation: 10, PendingHandshakes: 4}
	f := newRoutingFixtureWithConnections(t, 1, 4, &limits)
	pair := f.pairs[0]
	hostA := f.host(pair, "a")
	phoneA := f.phone(pair, "b")
	second := f.ticket(pair)
	blocked, err := capacityConnect(f.ctx, f.clients["a"], f.origin, "device", "DSH-Ticket "+second.Token, pair.phoneKey, pair)
	if err == nil {
		_ = blocked.CloseNow()
		t.Fatal("second ingress bypassed per-device connection cap")
	}
	digest := sha256.Sum256([]byte(second.Token))
	var consumed bool
	if err := f.db.QueryRowContext(f.ctx, `select consumed_at is not null from realtime_tickets where token_sha256=$1`, digest[:]).Scan(&consumed); err != nil || !consumed {
		t.Fatal("quota fixture failed before registered-key proof", consumed, err)
	}
	f.ping(phoneA)
	f.ping(hostA)
	var count int
	if err := f.db.QueryRowContext(f.ctx, `select count(*) from realtime_device_connections`).Scan(&count); err != nil || count != 1 {
		t.Fatal("rejected connection changed occupancy", count, err)
	}
	pair.epoch = capacityID()
	hostB := f.host(pair, "b")
	f.closed(hostA)
	f.closed(phoneA)
	if err := capacityWait(f.ctx, 3*time.Second, func() (bool, error) {
		err := f.db.QueryRowContext(f.ctx, `select count(*) from realtime_device_connections`).Scan(&count)
		return count == 0, err
	}); err != nil {
		t.Fatal("old socket occupancy not released", err)
	}
	phoneB := f.phone(pair, "a")
	f.snapshot(pair, hostB, phoneB)
	_ = phoneB.CloseNow()
	if err := capacityWait(f.ctx, 3*time.Second, func() (bool, error) {
		err := f.db.QueryRowContext(f.ctx, `select count(*) from realtime_device_connections`).Scan(&count)
		return count == 0, err
	}); err != nil {
		t.Fatal("current socket close did not release quota", err)
	}
	f.ping(hostB)
}
