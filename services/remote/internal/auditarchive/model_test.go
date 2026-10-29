package auditarchive

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/coldarchive"
)

const testDomain = "11111111-1111-4111-8111-111111111111"
const testExport = "22222222-2222-4222-8222-222222222222"
const testEpoch = "33333333-3333-4333-8333-333333333333"
const testBatch = "44444444-4444-4444-8444-444444444444"

func sampleAuditPayload(t *testing.T) Payload {
	t.Helper()
	archived := time.Date(2025, 4, 1, 12, 0, 0, 0, time.UTC)
	sourceTime := archived.Add(-100 * 24 * time.Hour)
	epoch := testEpoch
	source, err := json.Marshal(map[string]any{"id": 7, "ts": sourceTime, "org_id": nil, "actor_type": "system", "actor_id": "PRIVATE_AUDIT_ACTOR",
		"device_id": nil, "runtime_id": nil, "session_id": nil, "action": "fixture.event", "result": "success", "metadata": map[string]any{"marker": "PRIVATE_AUDIT_BODY"}, "database_epoch": epoch, "producer_xid": "101"})
	if err != nil {
		t.Fatal(err)
	}
	return Payload{Format: "dsh-audit-archive", Version: 1, DomainID: testDomain, ExportID: testExport, OperationEpoch: testEpoch, KeyID: "fixture-key", PreparedAt: archived.Add(time.Second),
		Batch:   Batch{ID: testBatch, DatabaseEpoch: testEpoch, Limit: 4, RetentionYears: 1, Cutoff: archived.Add(-90 * 24 * time.Hour), ArchivedAt: archived, RetainUntil: utcYear(archived, 1), Entries: 1},
		Entries: []Entry{{SourceID: 7, SourceEpoch: &epoch, SourceTime: sourceTime, Source: source}}, Recoveries: []coldarchive.Recovery{}}
}

func TestEncryptedAuditArchiveAuthenticatesAndPreservesSource(t *testing.T) {
	payload := sampleAuditPayload(t)
	raw, err := Encode(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	key, err := coldarchive.NewKey(payload.KeyID, bytes.Repeat([]byte{35}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	salt, nonce, err := coldarchive.Material()
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := coldarchive.SealEncodedWithLimit(key, raw, salt, nonce, MaxPlaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(artifact, []byte("PRIVATE_AUDIT_BODY")) || bytes.Contains(artifact, []byte("PRIVATE_AUDIT_ACTOR")) {
		t.Fatal("encrypted artifact exposed audit data")
	}
	opened, err := Open(key, artifact, testDomain, testExport)
	if err != nil || len(opened.Entries) != 1 || !bytes.Equal(opened.Entries[0].Source, payload.Entries[0].Source) {
		t.Fatal("audit source did not round trip", err)
	}
	if _, err := coldarchive.Open(key, artifact, testDomain, testExport); err == nil {
		t.Fatal("audit artifact was accepted as control history")
	}
	if _, err := Open(key, artifact, "55555555-5555-4555-8555-555555555555", testExport); err == nil {
		t.Fatal("wrong domain accepted")
	}
	other, err := coldarchive.NewKey(payload.KeyID, bytes.Repeat([]byte{36}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := Open(other, artifact, testDomain, testExport); err == nil {
		t.Fatal("wrong key accepted")
	}
	artifact[len(artifact)-1] ^= 1
	if _, err := Open(key, artifact, testDomain, testExport); err == nil {
		t.Fatal("tampered artifact accepted")
	}
	if _, err := json.Marshal(payload); err == nil || strings.Contains(fmt.Sprintf("%+v", payload), "PRIVATE_AUDIT_BODY") {
		t.Fatal("payload formatting exposed source")
	}
}

func TestAuditArchiveChecksSourceIdentityAndLineage(t *testing.T) {
	base := sampleAuditPayload(t)
	for _, mutation := range []func(*Payload){
		func(p *Payload) { p.Entries[0].SourceID++ },
		func(p *Payload) { p.Entries[0].SourceTime = p.Batch.ArchivedAt },
		func(p *Payload) { p.Entries[0].Source = []byte(`{"id":7,"id":8}`) },
		func(p *Payload) { p.Batch.Entries++ },
		func(p *Payload) { p.Batch.RetainUntil = p.Batch.ArchivedAt },
		func(p *Payload) { p.OperationEpoch = "55555555-5555-4555-8555-555555555555" },
	} {
		changed := sampleAuditPayload(t)
		mutation(&changed)
		if _, err := Encode(changed); err == nil {
			t.Fatal("invalid audit identity or lineage accepted")
		}
	}
	var source map[string]any
	if err := json.Unmarshal(base.Entries[0].Source, &source); err != nil {
		t.Fatal(err)
	}
	source["database_epoch"], source["producer_xid"] = nil, nil
	base.Entries[0].SourceEpoch = nil
	base.Entries[0].Source, _ = json.Marshal(source)
	if _, err := Encode(base); err != nil {
		t.Fatal("unknown legacy epoch was not preserved", err)
	}
	source["id"] = int64(-7)
	base.Entries[0].SourceID = -7
	base.Entries[0].Source, _ = json.Marshal(source)
	if _, err := Encode(base); err != nil {
		t.Fatal("valid legacy database identity was not preserved", err)
	}
	base.OperationEpoch = "55555555-5555-4555-8555-555555555555"
	base.Recoveries = []coldarchive.Recovery{{ID: "66666666-6666-4666-8666-666666666666", SourceEpoch: testEpoch, TargetEpoch: base.OperationEpoch,
		PreparedAt: base.Batch.ArchivedAt, ReleasedAt: base.PreparedAt, AuthoritySHA256: strings.Repeat("a", 64), Counts: json.RawMessage(`{"users":0}`)}}
	if _, err := Encode(base); err != nil {
		t.Fatal("released batch lineage was rejected", err)
	}
}
