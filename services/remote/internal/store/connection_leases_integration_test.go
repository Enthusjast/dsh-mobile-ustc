package store

import (
	"testing"
	"time"
)

func TestBatchLeaseJoinsKeepEveryAuthorityBoundaryAndIsolateInvalidRows(t *testing.T) {
	for _, check := range []struct {
		name, mutation string
		device, host   bool
		scope          *GrantScope
	}{
		{name: "valid"},
		{name: "suspended user", mutation: `update users set status='suspended' where subject='owner-subject'`, device: true},
		{name: "revoked device", mutation: `update devices set revoked_at=clock_timestamp() where id='44444444-4444-4444-8444-444444444444'`, device: true},
		{name: "rotated device", mutation: `update devices set key_version=2 where id='44444444-4444-4444-8444-444444444444'`, device: true},
		{name: "removed membership", mutation: `delete from org_memberships where user_id='22222222-2222-4222-8222-222222222222'`, device: true},
		{name: "stale grant", mutation: `update runtime_grants set grant_version=2`, device: true},
		{name: "revoked grant", mutation: `update runtime_grants set revoked_at=clock_timestamp()`, device: true},
		{name: "expired grant", mutation: `update runtime_grants set expires_at=clock_timestamp()-interval '1 second'`, device: true},
		{name: "reduced scope", mutation: `update runtime_grants set scope='{"actions":[],"workspaces":[],"sessions":[]}'::jsonb`, device: true},
		{name: "revoked host", mutation: `update hosts set state='revoked'`, device: true, host: true},
		{name: "revoked installation", mutation: `update installations set revoked_at=clock_timestamp()`, device: true, host: true},
		{name: "rotated installation", mutation: `update installations set key_version=2`, host: true},
		{name: "revoked runtime", mutation: `update runtimes set revoked_at=clock_timestamp()`, device: true, host: true},
		{name: "replaced runtime", mutation: `update runtimes set epoch='aaaaaaaa-1111-4111-8111-111111111111'`, host: true},
		{name: "stale connection key", mutation: `update runtimes set connection_key_version=2`, host: true},
		{name: "missing scoped workspace", mutation: `delete from sessions;delete from workspaces`, device: true},
		{name: "missing scoped session", mutation: `delete from sessions`, device: true},
		{name: "malformed scope", device: true, scope: &GrantScope{}},
	} {
		t.Run(check.name, func(t *testing.T) {
			ctx, postgres := newPostgresIntegrationDatabase(t)
			jkt := seedGrantFixture(t, ctx, postgres.DB)
			const runtimeID = "55555555-5555-4555-8555-555555555555"
			const owner = "22222222-2222-4222-8222-222222222222"
			const device = "44444444-4444-4444-8444-444444444444"
			const installation = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
			const epoch = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
			const hostConnection = "aaaaaaaa-2222-4222-8222-222222222222"
			const phoneConnection = "bbbbbbbb-2222-4222-8222-222222222222"
			const missingConnection = "ffffffff-2222-4222-8222-222222222222"
			if _, err := postgres.DB.ExecContext(ctx, `update runtimes set epoch=$1,connection_id=$2,connection_key_version=1`, epoch, hostConnection); err != nil {
				t.Fatal(err)
			}
			scope := GrantScope{Actions: []string{"host.list"}, Workspaces: []string{"77777777-7777-4777-8777-777777777777"}, Sessions: []string{"99999999-9999-4999-8999-999999999999"}}
			if check.scope != nil {
				scope = *check.scope
			}
			if check.mutation != "" {
				if _, err := postgres.DB.ExecContext(ctx, check.mutation); err != nil {
					t.Fatal(err)
				}
			}
			leases := []RealtimeConnectionLease{
				{Role: "device", ConnectionID: phoneConnection, RuntimeID: runtimeID, UserID: func() *string { s := owner; return &s }(), DeviceID: func() *string { s := device; return &s }(), DeviceKeyVersion: 1, ProofKeyThumbprint: jkt, GrantVersion: 1, Scope: scope},
				{Role: "installation", ConnectionID: hostConnection, RuntimeID: runtimeID, RuntimeEpoch: func() *string { s := epoch; return &s }(), InstallationID: func() *string { s := installation; return &s }(), KeyVersion: 1},
				{Role: "installation", ConnectionID: missingConnection, RuntimeID: "aaaaaaaa-3333-4333-8333-333333333333", KeyVersion: 1},
			}
			started := time.Now()
			invalid, err := postgres.InvalidRealtimeConnectionLeases(ctx, leases)
			if err != nil {
				t.Fatal("batch authority check failed", err, time.Since(started))
			}
			got := map[string]bool{}
			for _, id := range invalid {
				if got[id] {
					t.Fatal("duplicate invalidation")
				}
				got[id] = true
			}
			if got[phoneConnection] != check.device || got[hostConnection] != check.host || !got[missingConnection] || len(got) != 1+boolCount(check.device)+boolCount(check.host) {
				t.Fatalf("authority boundary changed: invalid=%v", got)
			}
		})
	}
}

func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
}
