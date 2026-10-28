package coldarchive

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

const testDomain = "11111111-1111-4111-8111-111111111111"
const testExport = "22222222-2222-4222-8222-222222222222"
const testEpoch = "33333333-3333-4333-8333-333333333333"
const testBatch = "44444444-4444-4444-8444-444444444444"
const testEvent = "55555555-5555-4555-8555-555555555555"
const testNode = "66666666-6666-4666-8666-666666666666"

func examplePayload(t *testing.T) Payload {
	t.Helper()
	archived := time.Date(2026, 10, 28, 8, 0, 0, 0, time.UTC)
	created := archived.Add(-200 * 24 * time.Hour)
	source, _ := json.Marshal(map[string]any{"id": testEvent, "database_epoch": testEpoch, "topic": "device.revoked", "created_at": created, "published_at": created, "producer_xid": "123", "payload": map[string]any{"device_id": testNode, "marker": "PRIVATE_ARCHIVE_BODY"}})
	ack, _ := json.Marshal(map[string]any{"node_id": testNode, "event_id": testEvent, "applied_at": created})
	return Payload{Format: "dsh-control-archive", Version: 1, DomainID: testDomain, ExportID: testExport, OperationEpoch: testEpoch, KeyID: "fixture-key", PreparedAt: archived,
		Batch:  Batch{ID: testBatch, DatabaseEpoch: testEpoch, Limit: 64, RetentionYears: 1, Cutoff: archived.Add(-90 * 24 * time.Hour), ArchivedAt: archived, RetainUntil: utcYear(archived, 1), Events: 1},
		Events: []Event{{ID: testEvent, BatchID: testBatch, BatchEpoch: testEpoch, DatabaseEpoch: testEpoch, Topic: "device.revoked", SourceCreatedAt: created, Source: source, Reason: "covered", ArchivedAt: archived, RetainUntil: utcYear(archived, 1), Acknowledgements: []Acknowledgement{{NodeID: testNode, EventID: testEvent, AppliedAt: created, Source: ack}}}}, Recoveries: []Recovery{}}
}

func testKey(t *testing.T, value byte) *Key {
	t.Helper()
	key, err := NewKey("fixture-key", bytes.Repeat([]byte{value}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Close)
	return key
}

func TestAuthenticatedArchiveRoundTripAndTamperRejection(t *testing.T) {
	key := testKey(t, 7)
	payload := examplePayload(t)
	salt, nonce, err := Material()
	if err != nil {
		t.Fatal(err)
	}
	blob, hash, err := Seal(key, payload, salt, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("PRIVATE_ARCHIVE_BODY")) || bytes.Contains(blob, []byte(testEvent)) {
		t.Fatal("encrypted artifact exposed event metadata")
	}
	again, sameHash, err := Seal(key, payload, salt, nonce)
	if err != nil || hash != sameHash || !bytes.Equal(blob, again) {
		t.Fatal("idempotent material did not reproduce ciphertext", err)
	}
	opened, err := Open(key, blob, testDomain, testExport)
	if err != nil || opened.Batch.ID != testBatch || len(opened.Events) != 1 || len(opened.Events[0].Acknowledgements) != 1 {
		t.Fatal("archive did not round-trip", err)
	}
	for _, value := range []any{payload, payload.Events[0], payload.Events[0].Acknowledgements[0], key} {
		if bytes.Contains([]byte(fmt.Sprintf("%v %#v", value, value)), []byte("PRIVATE_ARCHIVE_BODY")) {
			t.Fatal("formatting exposed source metadata")
		}
	}
	if _, err := json.Marshal(payload); err == nil {
		t.Fatal("generic JSON serialization exposed source metadata")
	}
	wrong := testKey(t, 8)
	if _, err := Open(wrong, blob, testDomain, testExport); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err := Open(key, blob, testEpoch, testExport); err == nil {
		t.Fatal("wrong domain accepted")
	}
	if _, err := Open(key, blob, testDomain, testEvent); err == nil {
		t.Fatal("renamed export accepted")
	}
	for _, index := range []int{0, 8, 40, 59, len(blob) - 1} {
		tampered := append([]byte(nil), blob...)
		tampered[index] ^= 1
		if _, err := Open(key, tampered, testDomain, testExport); err == nil {
			t.Fatal("tampering accepted", index)
		}
	}
	if _, err := Open(key, append(blob, 0), testDomain, testExport); err == nil {
		t.Fatal("trailing data accepted")
	}
	if _, err := Open(key, blob[:len(blob)-1], testDomain, testExport); err == nil {
		t.Fatal("truncated data accepted")
	}
}

func TestArchiveValidatesMetadataCountsAndRecoveryAncestry(t *testing.T) {
	base := examplePayload(t)
	for _, bad := range []func(*Payload){
		func(p *Payload) { p.Batch.Events++ }, func(p *Payload) { p.Events[0].BatchID = testNode },
		func(p *Payload) { p.Events[0].Acknowledgements[0].NodeID = testBatch },
		func(p *Payload) {
			p.Events[0].Source = json.RawMessage(`{"id":"` + testEvent + `","id":"` + testEvent + `"}`)
		},
		func(p *Payload) { p.Batch.RetentionYears = 0 }, func(p *Payload) { p.Batch.Cutoff = p.Batch.ArchivedAt },
		func(p *Payload) {
			p.Events[0].DatabaseEpoch = testNode
			p.Events[0].Reason = "recovered_epoch"
			p.Batch.PreviousEpochEvents = 1
		},
	} {
		copy := examplePayload(t)
		bad(&copy)
		if copy.Validate() == nil {
			t.Fatal("invalid source metadata or missing recovery chain was accepted")
		}
	}
	oldEpoch := "77777777-7777-4777-8777-777777777777"
	newEpoch := "88888888-8888-4888-8888-888888888888"
	base.Events[0].DatabaseEpoch = oldEpoch
	base.Events[0].Reason = "recovered_epoch"
	base.Batch.PreviousEpochEvents = 1
	base.OperationEpoch = newEpoch
	var source map[string]any
	_ = json.Unmarshal(base.Events[0].Source, &source)
	source["database_epoch"] = oldEpoch
	base.Events[0].Source, _ = json.Marshal(source)
	stamp := base.PreparedAt.Add(-time.Hour)
	base.Recoveries = []Recovery{{ID: "99999999-9999-4999-8999-999999999999", SourceEpoch: oldEpoch, TargetEpoch: testEpoch, PreparedAt: stamp, ReleasedAt: stamp, AuthoritySHA256: fmt.Sprintf("%064d", 1), Counts: json.RawMessage(`{}`)},
		{ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", SourceEpoch: testEpoch, TargetEpoch: newEpoch, PreparedAt: stamp, ReleasedAt: stamp, AuthoritySHA256: fmt.Sprintf("%064d", 2), Counts: json.RawMessage(`{}`)}}
	if err := base.Validate(); err != nil {
		t.Fatal("valid cross-epoch chain rejected", err)
	}
	base.Recoveries = base.Recoveries[:1]
	if err := base.Validate(); err == nil {
		t.Fatal("unproven restored-epoch chain accepted")
	}
	if got := utcYear(time.Date(2024, 2, 29, 12, 0, 0, 0, time.UTC), 1); !got.Equal(time.Date(2025, 2, 28, 12, 0, 0, 0, time.UTC)) {
		t.Fatal("UTC calendar retention disagrees with PostgreSQL")
	}
}

func TestClosedKeyFailsWithoutLeaking(t *testing.T) {
	key := testKey(t, 3)
	key.Close()
	if _, err := key.Fingerprint(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed key remained usable", err)
	}
}
