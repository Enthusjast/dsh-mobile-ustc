package store

import (
	"errors"
	"testing"
	"time"
)

func TestNormalizeRuntimeGrantInputAcceptsExplicitRoleScopes(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	input, err := NormalizeRuntimeGrantInput(RuntimeGrantInput{
		Role: "operator",
		Scope: GrantScope{
			Actions:    []string{"message.submit", "session.list", "host.list"},
			Workspaces: []string{},
			Sessions:   []string{"55555555-5555-4555-8555-555555555555"},
		},
	}, now)
	if err != nil {
		t.Fatalf("valid operator grant rejected: %v", err)
	}
	if input.Scope.Actions[0] != "host.list" || input.Scope.Actions[1] != "message.submit" || input.Scope.Actions[2] != "session.list" {
		t.Fatalf("actions were not normalized: %v", input.Scope.Actions)
	}
	if input.Scope.Workspaces == nil {
		t.Fatal("nil workspaces were not normalized to an explicit empty array")
	}
}

func TestNormalizeRuntimeGrantInputRejectsBroadOrMalformedGrants(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		input RuntimeGrantInput
	}{
		{name: "unknown role", input: RuntimeGrantInput{Role: "admin", Scope: GrantScope{Actions: []string{}, Workspaces: []string{}, Sessions: []string{}}}},
		{name: "viewer write", input: RuntimeGrantInput{Role: "viewer", Scope: GrantScope{Actions: []string{"message.submit"}, Workspaces: []string{}, Sessions: []string{}}}},
		{name: "unknown action", input: RuntimeGrantInput{Role: "operator", Scope: GrantScope{Actions: []string{"shell.exec"}, Workspaces: []string{}, Sessions: []string{}}}},
		{name: "duplicate action", input: RuntimeGrantInput{Role: "viewer", Scope: GrantScope{Actions: []string{"host.list", "host.list"}, Workspaces: []string{}, Sessions: []string{}}}},
		{name: "invalid session UUID", input: RuntimeGrantInput{Role: "viewer", Scope: GrantScope{Actions: []string{}, Workspaces: []string{}, Sessions: []string{"not-a-uuid"}}}},
		{name: "owner without grant management", input: RuntimeGrantInput{Role: "owner", Scope: GrantScope{Actions: []string{"host.list"}, Workspaces: []string{}, Sessions: []string{}}}},
		{name: "expired", input: RuntimeGrantInput{Role: "viewer", Scope: GrantScope{Actions: []string{}, Workspaces: []string{}, Sessions: []string{}}, ExpiresAt: timePointer(now)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NormalizeRuntimeGrantInput(test.input, now); !errors.Is(err, ErrGrantInvalid) {
				t.Fatalf("invalid grant error = %v, want ErrGrantInvalid", err)
			}
		})
	}
}

func TestGrantScopeSubsetCannotExpandActionsOrResources(t *testing.T) {
	parent := GrantScope{
		Actions:    []string{"grant.manage", "host.list", "session.list"},
		Workspaces: []string{"44444444-4444-4444-8444-444444444444"},
		Sessions:   []string{"55555555-5555-4555-8555-555555555555"},
	}
	if !grantScopeSubset(GrantScope{Actions: []string{"host.list"}, Workspaces: parent.Workspaces, Sessions: []string{}}, parent) {
		t.Fatal("narrow grant scope was rejected")
	}
	if grantScopeSubset(GrantScope{Actions: []string{"message.submit"}, Workspaces: []string{}, Sessions: []string{}}, parent) {
		t.Fatal("scope expanded an action")
	}
	if grantScopeSubset(GrantScope{Actions: []string{}, Workspaces: []string{"66666666-6666-4666-8666-666666666666"}, Sessions: []string{}}, parent) {
		t.Fatal("scope expanded workspace access")
	}
}

func TestNormalizeTicketScopeExcludesGrantManagementAndRequiresExplicitReadScope(t *testing.T) {
	workspaceID := "44444444-4444-4444-8444-444444444444"
	scope, err := NormalizeTicketScope("owner", GrantScope{
		Actions: []string{"session.list", "host.list"}, Workspaces: []string{workspaceID}, Sessions: []string{},
	})
	if err != nil {
		t.Fatalf("valid owner read ticket scope rejected: %v", err)
	}
	if scope.Actions[0] != "host.list" || scope.Actions[1] != "session.list" {
		t.Fatalf("ticket actions were not normalized: %v", scope.Actions)
	}
	for _, invalid := range []GrantScope{
		{Actions: []string{}, Workspaces: []string{}, Sessions: []string{}},
		{Actions: []string{"grant.manage"}, Workspaces: []string{}, Sessions: []string{}},
		{Actions: []string{"shell.exec"}, Workspaces: []string{}, Sessions: []string{}},
		{Actions: []string{"session.list"}, Workspaces: []string{"not-a-uuid"}, Sessions: []string{}},
	} {
		if _, err := NormalizeTicketScope("owner", invalid); !errors.Is(err, ErrGrantInvalid) {
			t.Fatalf("invalid ticket scope error = %v, want ErrGrantInvalid", err)
		}
	}
}

func timePointer(value time.Time) *time.Time { return &value }
