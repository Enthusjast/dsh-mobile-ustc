package httpapi_test

import (
	"io"
	"strings"
	"testing"
	"time"
)

func TestProductionApprovalExpiryRunsWithoutNewRequestsOnBothNodes(t *testing.T) {
	f := newRoutingFixture(t, 1, 2)
	pair := f.pairs[0]
	f.host(pair, "a")
	id := capacityID()
	// Seed only pending metadata. This process test exercises scheduling and
	// per-node outbox coverage, independently of native signing/UI fixtures.
	if _, err := f.db.ExecContext(f.ctx, `insert into approvals(id,metadata_version,runtime_id,session_id,runtime_epoch,execution_id,
	 binding_sha256,policy_version,state,expires_at,connection_id,workspace_id,nonce_sha256,assurance_profile,max_auth_age_seconds,request_created_at,created_at)
	 select $1,1,r.id,$2,r.epoch,$3,repeat('a',64),1,'pending',clock_timestamp()+interval '500 milliseconds',
	 r.connection_id,$4,repeat('b',64),'fixture',60,clock_timestamp()-interval '1 second',clock_timestamp()-interval '1 second'
	 from runtimes r where r.id=$5`, id, pair.session, capacityID(), pair.workspace, pair.runtime); err != nil {
		t.Fatal(err)
	}
	if err := capacityWait(f.ctx, 8*time.Second, func() (bool, error) {
		var state string
		var audits, events int
		if err := f.db.QueryRowContext(f.ctx, `select state,
		 (select count(*) from audit_log where action='approval.ended' and metadata->>'approval_id'=$1),
		 (select count(*) from control_outbox where topic='approval.ended' and payload->>'approval_id'=$1)
		 from approvals where id=$1::uuid`, id).Scan(&state, &audits, &events); err != nil {
			return false, err
		}
		return state == "expired" && audits == 1 && events == 1, nil
	}); err != nil {
		t.Fatal("production worker did not expire idle pending approval", err)
	}
	for _, node := range f.nodes {
		if err := capacityWait(f.ctx, 8*time.Second, func() (bool, error) {
			var covered bool
			err := f.db.QueryRowContext(f.ctx, `select exists(select 1 from control_outbox e join control_consumers c on c.node_id=$2
			 where e.topic='approval.ended' and e.payload->>'approval_id'=$1 and
			 (exists(select 1 from control_event_acks ack where ack.node_id=c.node_id and ack.event_id=e.id)
			 or pg_visible_in_snapshot(e.producer_xid,c.coverage)))`, id, node.id).Scan(&covered)
			return covered, err
		}); err != nil {
			t.Fatal("node did not independently cover expiry delivery", err)
		}
		response, err := f.clients["a"].Get(node.metrics + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || !strings.Contains(string(raw), `dsh_remote_control_available{worker="approval_expiry"} 1`) {
			t.Fatal("production expiry worker health missing", err)
		}
	}
}
