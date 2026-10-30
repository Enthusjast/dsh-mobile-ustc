package store

import (
	"testing"

	"dsh-mobile-ustc/services/remote/internal/coldarchive"
)

func TestRuntimeRevocationRetainsDurableAcknowledgementAndInertExport(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	consumer, err := db.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	var id string
	if err := db.DB.QueryRowContext(ctx, `insert into control_outbox(topic,payload,created_at,published_at) values('runtime.revoked',jsonb_build_object('runtime_id',$1::text),'2000-01-01T00:00:00Z','2000-01-02T00:00:00Z') returning id::text`, "33333333-3333-4333-8333-333333333333").Scan(&id); err != nil {
		t.Fatal(err)
	}
	events, err := consumer.PendingControlEvents(ctx, 128)
	if err != nil || len(events) != 1 || events[0].RuntimeID != "33333333-3333-4333-8333-333333333333" {
		t.Fatal("runtime event was not consumable", events, err)
	}
	if err := consumer.MarkControlEventPublished(ctx, id); err != nil {
		t.Fatal(err)
	}
	batch, err := db.ArchiveControlEvents(ctx, archiveFixtureRequest(t))
	if err != nil || batch.Events != 1 {
		t.Fatal("acknowledged runtime event could not be archived", batch, err)
	}
	key := exportFixtureKey(t, 7)
	request := exportFixtureRequest(t, batch.BatchID, key)
	_, artifact, err := db.PrepareControlExport(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := coldarchive.Open(key, artifact, request.DomainID, request.ExportID)
	if err != nil || len(opened.Events) != 1 || opened.Events[0].Topic != "runtime.revoked" || len(opened.Events[0].Acknowledgements) != 1 {
		t.Fatal("inert export lost runtime revocation provenance", err)
	}
}
