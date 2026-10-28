package approval

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type keyFixture struct {
	UserID     string          `json:"user_id"`
	DeviceID   string          `json:"device_id"`
	KeyVersion int64           `json:"key_version"`
	JKT        string          `json:"approval_key_jkt"`
	PublicJWK  json.RawMessage `json:"public_jwk"`
	Active     bool            `json:"active"`
}

func (key keyFixture) registered() RegisteredKey {
	return RegisteredKey{UserID: key.UserID, DeviceID: key.DeviceID, KeyVersion: key.KeyVersion, ApprovalKeyJKT: key.JKT, PublicJWK: key.PublicJWK, Active: key.Active}
}

type fixture struct {
	Now        string          `json:"now"`
	Context    json.RawMessage `json:"context"`
	Canonical  string          `json:"binding_canonical"`
	SHA256     string          `json:"binding_sha256"`
	Registered keyFixture      `json:"registered"`
	Vectors    []struct {
		Name       string      `json:"name"`
		Compact    string      `json:"compact"`
		Invalid    bool        `json:"invalid"`
		Decision   string      `json:"decision"`
		SHA256     string      `json:"payload_sha256"`
		Registered *keyFixture `json:"registered"`
	} `json:"vectors"`
}

func loadFixture(t *testing.T) (fixture, RegisteredKey, time.Time) {
	return loadFixtureFile(t, "approval-signatures.json")
}

func loadFixtureFile(t *testing.T, name string) (fixture, RegisteredKey, time.Time) {
	t.Helper()
	raw, err := os.ReadFile("../../../../contracts/security/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var data fixture
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	now, ok := utc(data.Now)
	if !ok {
		t.Fatal("invalid test clock")
	}
	key := data.Registered.registered()
	return data, key, now
}

func TestApprovalSignatureSharedVectors(t *testing.T) {
	for _, name := range []string{"approval-signatures.json", "approval-kotlin-signatures.json"} {
		t.Run(name, func(t *testing.T) {
			testApprovalSignatureFixture(t, name)
		})
	}
}

func testApprovalSignatureFixture(t *testing.T, name string) {
	t.Helper()
	data, key, now := loadFixtureFile(t, name)
	binding, err := ContextBinding(data.Context)
	if err != nil || string(binding.Canonical) != data.Canonical || binding.SHA256 != data.SHA256 {
		t.Fatalf("binding mismatch: %v", err)
	}
	for _, vector := range data.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			registered := key
			if vector.Registered != nil {
				registered = vector.Registered.registered()
			}
			verified, err := VerifyDecision(vector.Compact, registered, data.Context, now)
			if vector.Invalid {
				if err == nil {
					t.Fatal("invalid signed decision accepted")
				}
				return
			}
			if err != nil || verified.Claims.Decision != vector.Decision || verified.PayloadSHA256 != vector.SHA256 {
				t.Fatalf("verified decision mismatch: error=%v", err)
			}
		})
	}
}

func TestApprovalSignatureRejectsChangedContextKeysAndTime(t *testing.T) {
	data, key, now := loadFixture(t)
	valid := data.Vectors[0].Compact
	for _, field := range []string{"host_id", "installation_id", "runtime_id", "runtime_epoch", "session_id", "approval_id", "execution_id", "dsh_session_id", "call_id", "tool", "nonce", "policy_version", "arguments", "workspace", "resources", "required_assurance"} {
		var context map[string]any
		if err := json.Unmarshal(data.Context, &context); err != nil {
			t.Fatal(err)
		}
		switch field {
		case "host_id":
			context[field] = context["session_id"]
		case "installation_id", "runtime_id", "runtime_epoch", "session_id", "approval_id", "execution_id":
			context[field] = context["host_id"]
		case "nonce":
			context[field] = "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg"
		case "arguments":
			context[field].(map[string]any)["command"] = "changed command"
		case "workspace":
			context[field].(map[string]any)["root_sha256"] = data.SHA256
		case "resources":
			context[field].([]any)[0].(map[string]any)["version_sha256"] = data.SHA256
		case "required_assurance":
			context[field].(map[string]any)["max_auth_age_seconds"] = 299
		case "policy_version":
			context[field] = 3
		default:
			context[field] = "changed"
		}
		raw, err := json.Marshal(context)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyDecision(valid, key, raw, now); err == nil {
			t.Fatalf("changed %s accepted", field)
		}
	}
	for _, variant := range []string{"revoked", "version", "thumbprint", "private-key", "remote-key"} {
		changed := key
		switch variant {
		case "revoked":
			changed.Active = false
		case "version":
			changed.KeyVersion++
		case "thumbprint":
			changed.ApprovalKeyJKT = "other-key"
		case "private-key", "remote-key":
			var jwk map[string]any
			if err := json.Unmarshal(key.PublicJWK, &jwk); err != nil {
				t.Fatal(err)
			}
			if variant == "private-key" {
				jwk["d"] = "private-material"
			} else {
				jwk["jku"] = "https://example.invalid/key"
			}
			changed.PublicJWK, _ = json.Marshal(jwk)
		}
		if _, err := VerifyDecision(valid, changed, data.Context, now); err == nil {
			t.Fatalf("unavailable key accepted: %s", variant)
		}
	}
	for _, clock := range []time.Time{now.Add(23 * time.Second), now.Add(-8 * time.Second)} {
		if _, err := VerifyDecision(valid, key, data.Context, clock); err == nil {
			t.Fatal("expired/future context accepted")
		}
	}
	first, err := VerifyDecision(valid, key, data.Context, now)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := VerifyDecision(valid, key, data.Context, now)
	if err != nil || first.PayloadSHA256 != retry.PayloadSHA256 {
		t.Fatal("pure verification changed pending state")
	}
}

func TestHistoricalDecisionVerifiesRetainedRecordWithoutCreatingAuthority(t *testing.T) {
	data, key, now := loadFixture(t)
	compact := data.Vectors[0].Compact
	verified, err := VerifyDecision(compact, key, data.Context, now)
	if err != nil {
		t.Fatal(err)
	}
	claims := verified.Claims
	record := HistoricalDecisionEvidence{ApprovalID: claims.ApprovalID, RuntimeID: claims.RuntimeID, RuntimeEpoch: claims.RuntimeEpoch,
		SessionID: claims.SessionID, ExecutionID: claims.ExecutionID, UserID: key.UserID, DeviceID: key.DeviceID, KeyVersion: key.KeyVersion,
		ApprovalKeyJKT: key.ApprovalKeyJKT, PublicJWK: key.PublicJWK, Decision: claims.Decision, BindingSHA256: claims.BindingSHA256, PayloadSHA256: verified.PayloadSHA256}
	if err := VerifyHistoricalDecision(compact, record); err != nil {
		t.Fatal("valid historical evidence failed", err)
	}
	if _, err := VerifyDecision(compact, key, data.Context, now.Add(time.Hour)); err == nil {
		t.Fatal("historical evidence extended live authorization")
	}
	for _, field := range []string{"approval", "runtime", "epoch", "session", "execution", "user", "device", "key-version", "key-thumbprint", "decision", "binding", "payload"} {
		changed := record
		switch field {
		case "approval":
			changed.ApprovalID = claims.SessionID
		case "runtime":
			changed.RuntimeID = claims.SessionID
		case "epoch":
			changed.RuntimeEpoch = claims.SessionID
		case "session":
			changed.SessionID = claims.RuntimeID
		case "execution":
			changed.ExecutionID = claims.SessionID
		case "user":
			changed.UserID = claims.SessionID
		case "device":
			changed.DeviceID = claims.SessionID
		case "key-version":
			changed.KeyVersion++
		case "key-thumbprint":
			changed.ApprovalKeyJKT = "other"
		case "decision":
			changed.Decision = "reject"
		case "binding":
			changed.BindingSHA256 = strings.Repeat("a", 64)
		case "payload":
			changed.PayloadSHA256 = strings.Repeat("b", 64)
		}
		if err := VerifyHistoricalDecision(compact, changed); err == nil {
			t.Fatalf("historical record accepted changed %s", field)
		}
	}
	if err := VerifyHistoricalDecision(compact+"x", record); err == nil {
		t.Fatal("tampered historical signature accepted")
	}
}

func TestApprovalContextRejectsCaseInsensitiveFieldAliases(t *testing.T) {
	data, _, _ := loadFixture(t)
	for _, field := range []string{"domain", "runtime_id", "root_sha256", "kind", "profile", "max_auth_age_seconds"} {
		changed := strings.Replace(string(data.Context), `"`+field+`":`, `"`+strings.ToUpper(field)+`":`, 1)
		if _, err := ContextBinding([]byte(changed)); err == nil {
			t.Fatalf("case-insensitive field alias accepted: %s", field)
		}
	}
}
