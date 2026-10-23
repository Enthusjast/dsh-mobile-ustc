package store

import (
	"database/sql"
	"testing"
)

func TestCommandReceiptTransitionsAllowProgressAndEvidenceBasedUnknownResolution(t *testing.T) {
	for _, receiptState := range []string{"host_accepted", "dispatching", "agent_queued", "observed", "settled", "rejected", "outcome_unknown"} {
		if _, ok := relayReceiptStates[receiptState]; !ok {
			t.Fatalf("valid receipt state %q was rejected", receiptState)
		}
	}
	if _, ok := relayReceiptStates["received"]; ok {
		t.Fatal("Relay-owned received state must not be accepted as a host receipt")
	}
	allowed := [][2]string{
		{"received", "host_accepted"},
		{"host_accepted", "agent_queued"},
		{"agent_queued", "observed"},
		{"observed", "settled"},
		{"outcome_unknown", "agent_queued"},
	}
	for _, transition := range allowed {
		if _, ok := commandTransitions[transition[0]][transition[1]]; !ok {
			t.Fatalf("transition %s -> %s was not enabled", transition[0], transition[1])
		}
	}
	for _, transition := range [][2]string{
		{"received", "agent_queued"},
		{"agent_queued", "host_accepted"},
		{"settled", "outcome_unknown"},
		{"rejected", "agent_queued"},
	} {
		if _, ok := commandTransitions[transition[0]][transition[1]]; ok {
			t.Fatalf("invalid transition %s -> %s was enabled", transition[0], transition[1])
		}
	}
}

func TestRelayCommandDigestAndSessionScopeValidation(t *testing.T) {
	validDigest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if !validSHA256Hex(validDigest) {
		t.Fatal("valid lowercase SHA-256 digest rejected")
	}
	if validSHA256Hex("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF") {
		t.Fatal("noncanonical uppercase digest accepted")
	}
	if validSHA256Hex("short") {
		t.Fatal("short digest accepted")
	}
	workspaceID := "11111111-1111-4111-8111-111111111111"
	sessionID := "22222222-2222-4222-8222-222222222222"
	if !scopeIncludesSession(GrantScope{Workspaces: []string{workspaceID}}, sessionID, sql.NullString{String: workspaceID, Valid: true}) {
		t.Fatal("workspace grant did not include its session")
	}
	if scopeIncludesSession(GrantScope{Workspaces: []string{workspaceID}}, sessionID, sql.NullString{}) {
		t.Fatal("workspace grant included a session with no workspace")
	}
}
