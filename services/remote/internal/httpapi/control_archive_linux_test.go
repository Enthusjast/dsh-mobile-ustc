package httpapi_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

func TestProductionControlArchivePreservesBothLiveNodes(t *testing.T) {
	f := newRoutingFixture(t, 1, 2)
	pair := f.pairs[0]
	host, phone := f.host(pair, "a"), f.phone(pair, "b")
	first := f.snapshot(pair, host, phone)
	device, batch := capacityID(), capacityID()
	var id string
	if err := f.db.QueryRowContext(f.ctx, `insert into control_outbox(topic,payload,created_at,published_at)
	 values('device.revoked',jsonb_build_object('device_id',$1::text,'marker','PRIVATE_CONTROL_ARCHIVE'),'2000-01-01','2000-01-02') returning id::text`, device).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := capacityWait(f.ctx, 5*time.Second, func() (bool, error) {
		var count int
		err := f.db.QueryRowContext(f.ctx, `select count(*) from control_consumers c join control_outbox e on e.id=$1
		 where c.node_id in ($2,$3) and (pg_visible_in_snapshot(e.producer_xid,c.coverage) or exists(
		 select 1 from control_event_acks a where a.node_id=c.node_id and a.event_id=e.id))`, id, f.nodes["a"].id, f.nodes["b"].id).Scan(&count)
		return count == 2, err
	}); err != nil {
		t.Fatal("both nodes did not cover the synthetic event", err)
	}
	var original []byte
	if err := f.db.QueryRowContext(f.ctx, `select to_jsonb(e) from control_outbox e where id=$1`, id).Scan(&original); err != nil {
		t.Fatal(err)
	}
	dsn, err := capacityDatabaseDSN(f.ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(f.ctx, os.Getenv("REMOTE_TEST_SERVICE_BIN"), "archive", "control", "--batch-id", batch, "--expected-epoch", store.OriginalDatabaseEpoch, "--limit", "4")
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "REMOTE_DATABASE_URL=" + dsn, "REMOTE_DATABASE_EPOCH=" + store.OriginalDatabaseEpoch}
	raw, err := command.CombinedOutput()
	if err != nil {
		t.Fatal("production archive failed", err)
	}
	var result store.ControlArchiveResult
	if json.Unmarshal(raw, &result) != nil || result.BatchID != batch || result.Events != 1 {
		t.Fatal("production archive returned an unexpected result")
	}
	if bytes.Contains(raw, []byte("PRIVATE_CONTROL_ARCHIVE")) || bytes.Contains(raw, []byte(device)) || bytes.Contains(raw, []byte(dsn)) {
		t.Fatal("archive output disclosed source metadata")
	}
	var preserved bool
	if err := f.db.QueryRowContext(f.ctx, `select source=$2::jsonb and reason='covered' from control_outbox_archive where event_id=$1`, id, string(original)).Scan(&preserved); err != nil || !preserved {
		t.Fatal("production archive lost the committed event", err)
	}
	// Verify both existing connections and a fresh subscription remain usable.
	f.ping(host)
	f.ping(phone)
	second := f.snapshot(pair, host, phone)
	if first.SyncID == second.SyncID {
		t.Fatal("new subscription reused an old sync identity")
	}
	for _, node := range f.nodes {
		select {
		case err := <-node.process.done:
			t.Fatal("archive stopped a live control consumer", err)
		default:
		}
	}
}
