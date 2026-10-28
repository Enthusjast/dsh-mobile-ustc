package evidencearchive

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/approval"
	"dsh-mobile-ustc/services/remote/internal/coldarchive"
)

const fixtureDomain = "11111111-1111-4111-8111-111111111111"
const fixtureExport = "22222222-2222-4222-8222-222222222222"
const fixtureEpoch = "33333333-3333-4333-8333-333333333333"

func samplePayload(t *testing.T) Payload {
	t.Helper()
	raw, err := os.ReadFile("../../../../contracts/security/approval-signatures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Now        string          `json:"now"`
		Context    json.RawMessage `json:"context"`
		Registered struct {
			UserID     string          `json:"user_id"`
			DeviceID   string          `json:"device_id"`
			KeyVersion int64           `json:"key_version"`
			JKT        string          `json:"approval_key_jkt"`
			PublicJWK  json.RawMessage `json:"public_jwk"`
		} `json:"registered"`
		Vectors []struct {
			Compact string `json:"compact"`
		} `json:"vectors"`
	}
	if json.Unmarshal(raw, &fixture) != nil || len(fixture.Vectors) == 0 {
		t.Fatal("invalid signature fixture")
	}
	now, err := time.Parse(time.RFC3339Nano, fixture.Now)
	if err != nil {
		t.Fatal(err)
	}
	key := approval.RegisteredKey{UserID: fixture.Registered.UserID, DeviceID: fixture.Registered.DeviceID, KeyVersion: fixture.Registered.KeyVersion, ApprovalKeyJKT: fixture.Registered.JKT, PublicJWK: fixture.Registered.PublicJWK, Active: true}
	verified, err := approval.VerifyDecision(fixture.Vectors[0].Compact, key, fixture.Context, now)
	if err != nil {
		t.Fatal(err)
	}
	c := verified.Claims
	return Payload{Format: "dsh-approval-evidence", Version: 1, DomainID: fixtureDomain, ExportID: fixtureExport, OperationEpoch: fixtureEpoch, KeyID: "fixture-key", PreparedAt: now.Add(time.Second),
		Proof: Proof{ApprovalID: c.ApprovalID, SourceEpoch: fixtureEpoch, RuntimeID: c.RuntimeID, RuntimeEpoch: c.RuntimeEpoch, SessionID: c.SessionID, ExecutionID: c.ExecutionID,
			UserID: c.UserID, DeviceID: c.DeviceID, KeyVersion: c.KeyVersion, ApprovalKeyJKT: key.ApprovalKeyJKT, Decision: c.Decision, BindingSHA256: c.BindingSHA256,
			PayloadSHA256: verified.PayloadSHA256, JWSSHA256: coldarchive.Digest([]byte(fixture.Vectors[0].Compact)), FingerprintSource: "captured", DecidedAt: now, RetainUntil: utcYear(now),
			DecisionJWS: fixture.Vectors[0].Compact, PublicJWK: fixture.Registered.PublicJWK}, Recoveries: []coldarchive.Recovery{}}
}

func TestEncryptedEvidenceRoundTripRejectsWrongIdentityAndTampering(t *testing.T) {
	payload := samplePayload(t)
	plain, err := Encode(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	key, err := coldarchive.NewKey(payload.KeyID, bytes.Repeat([]byte{17}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	salt, nonce, err := coldarchive.Material()
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := coldarchive.SealEncoded(key, plain, salt, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(artifact, []byte(payload.Proof.DecisionJWS)) || bytes.Contains(artifact, []byte(payload.Proof.UserID)) {
		t.Fatal("encrypted proof leaked its contents")
	}
	opened, err := Open(key, artifact, fixtureDomain, fixtureExport)
	if err != nil || opened.Proof.ApprovalID != payload.Proof.ApprovalID || opened.Proof.JWSSHA256 != payload.Proof.JWSSHA256 {
		t.Fatal("authenticated evidence did not round trip", err)
	}
	if _, err := coldarchive.Open(key, artifact, fixtureDomain, fixtureExport); err == nil {
		t.Fatal("approval evidence was accepted as a control-event archive")
	}
	if _, err := Open(key, artifact, "44444444-4444-4444-8444-444444444444", fixtureExport); err == nil {
		t.Fatal("wrong domain accepted")
	}
	if _, err := Open(key, artifact, fixtureDomain, "55555555-5555-4555-8555-555555555555"); err == nil {
		t.Fatal("wrong export identity accepted")
	}
	other, err := coldarchive.NewKey(payload.KeyID, bytes.Repeat([]byte{18}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := Open(other, artifact, fixtureDomain, fixtureExport); err == nil {
		t.Fatal("wrong key accepted")
	}
	artifact[len(artifact)-1] ^= 1
	if _, err := Open(key, artifact, fixtureDomain, fixtureExport); err == nil {
		t.Fatal("modified ciphertext accepted")
	}
	if _, err := json.Marshal(payload); err == nil || strings.Contains(fmt.Sprintf("%+v", payload), payload.Proof.DecisionJWS) {
		t.Fatal("formatting exposed the proof")
	}
}

func TestEvidenceValidatesSourceBindingAndRecoveryLineage(t *testing.T) {
	valid := samplePayload(t)
	for _, variant := range []string{"signature", "hash", "key", "binding", "retention", "recovery"} {
		changed := valid
		switch variant {
		case "signature":
			changed.Proof.DecisionJWS += "x"
		case "hash":
			changed.Proof.JWSSHA256 = strings.Repeat("a", 64)
		case "key":
			changed.Proof.ApprovalKeyJKT = "wrong"
		case "binding":
			changed.Proof.BindingSHA256 = strings.Repeat("b", 64)
		case "retention":
			changed.Proof.RetainUntil = changed.Proof.DecidedAt
		case "recovery":
			changed.OperationEpoch = "44444444-4444-4444-8444-444444444444"
		}
		if _, err := Encode(changed); err == nil {
			t.Fatal("invalid evidence accepted", variant)
		}
	}
	valid.OperationEpoch = "44444444-4444-4444-8444-444444444444"
	valid.Recoveries = []coldarchive.Recovery{{ID: "55555555-5555-4555-8555-555555555555", SourceEpoch: fixtureEpoch, TargetEpoch: valid.OperationEpoch,
		PreparedAt: valid.Proof.DecidedAt, ReleasedAt: valid.Proof.DecidedAt.Add(time.Second), AuthoritySHA256: strings.Repeat("c", 64), Counts: json.RawMessage(`{"users":0}`)}}
	if _, err := Encode(valid); err != nil {
		t.Fatal("released recovery lineage was rejected", err)
	}
	valid.Recoveries[0].Counts = json.RawMessage(`{"users":0,"users":1}`)
	if _, err := Encode(valid); err == nil {
		t.Fatal("ambiguous recovery metadata accepted")
	}
	valid.Recoveries[0].Counts = json.RawMessage(`{"users":0}`)
	valid.Recoveries[0].ReleasedAt = valid.PreparedAt.Add(time.Second)
	if _, err := Encode(valid); err == nil {
		t.Fatal("future recovery release accepted")
	}
	valid.Recoveries[0].ReleasedAt = valid.PreparedAt
	valid.Recoveries = append(valid.Recoveries, coldarchive.Recovery{ID: "66666666-6666-4666-8666-666666666666", SourceEpoch: valid.OperationEpoch, TargetEpoch: fixtureEpoch,
		PreparedAt: valid.Proof.DecidedAt, ReleasedAt: valid.PreparedAt, AuthoritySHA256: strings.Repeat("d", 64), Counts: json.RawMessage(`{"users":0}`)})
	if _, err := Encode(valid); err == nil {
		t.Fatal("cyclic recovery lineage accepted")
	}
}
