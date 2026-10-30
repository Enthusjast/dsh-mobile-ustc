package store

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/auth"
)

func TestDirectoryPublishesOnlyTheCurrentUsersGrantAndOpaqueWorkspaceMapping(t *testing.T) {
	ctx, postgres := newPostgresIntegrationDatabase(t)
	ownerProof := seedGrantFixture(t, ctx, postgres.DB)
	const (
		runtimeID = "55555555-5555-4555-8555-555555555555"
		workspace = "77777777-7777-4777-8777-777777777777"
		sessionID = "99999999-9999-4999-8999-999999999999"
		targetID  = "66666666-6666-4666-8666-666666666666"
		deviceID  = "44444444-4444-4444-8444-444444444444"
	)
	owner := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	target := UserIdentity{Issuer: owner.Issuer, Subject: "target-subject"}
	proof, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proofJWK, err := integrationP256JWK(proof)
	if err != nil {
		t.Fatal(err)
	}
	proofJKT, err := auth.PublicP256JWKThumbprintJSON(proofJWK)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.DB.ExecContext(ctx, `update devices set proof_public_jwk=$1::jsonb, proof_key_thumbprint=$2 where user_id=$3`, string(proofJWK), proofJKT, targetID); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.DB.ExecContext(ctx, `update runtime_grants set scope = jsonb_set(scope, '{actions}', '["command.status","grant.manage","host.list","session.list","session.read"]'::jsonb) where runtime_id = $1`, runtimeID); err != nil {
		t.Fatal(err)
	}
	scope := GrantScope{Actions: []string{"session.list", "session.read"}, Workspaces: []string{workspace}, Sessions: []string{sessionID}}
	if _, err := postgres.PutRuntimeGrant(ctx, owner, deviceID, ownerProof, runtimeID, targetID, RuntimeGrantInput{Role: "viewer", Scope: scope}); err != nil {
		t.Fatal(err)
	}
	runtimes, err := postgres.ListRuntimes(ctx, target)
	if err != nil || len(runtimes) != 1 || runtimes[0].OrganizationID != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" || runtimes[0].Access == nil {
		t.Fatalf("scoped directory: %#v, %v", runtimes, err)
	}
	access := runtimes[0].Access
	if access.Role != "viewer" || access.GrantVersion != 1 || !reflect.DeepEqual(access.Scope, scope) {
		t.Fatalf("directory exposed another user's grant: %#v", access)
	}
	sessions, err := postgres.ListSessions(ctx, target, runtimeID)
	if err != nil || len(sessions) != 1 || sessions[0].WorkspaceID == nil || *sessions[0].WorkspaceID != workspace {
		t.Fatalf("opaque workspace mapping missing: %#v, %v", sessions, err)
	}
	encoded, err := json.Marshal(sessions)
	if err != nil || !strings.Contains(string(encoded), `"workspace_id":"`+workspace+`"`) || strings.Contains(string(encoded), "workspace-test") || strings.Contains(string(encoded), "opaque-dsh-session") {
		t.Fatalf("directory exposed a native identity or lost opaque mapping: %s, %v", encoded, err)
	}
	readScope := GrantScope{Actions: []string{"session.read"}, Workspaces: []string{*sessions[0].WorkspaceID}, Sessions: []string{}}
	if _, err := postgres.IssueRealtimeTicket(ctx, target, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", runtimeID, readScope); err != nil {
		t.Fatalf("directory-derived workspace scope could not obtain a read ticket: %v", err)
	}
	if _, err := postgres.DB.ExecContext(ctx, `update sessions set workspace_id = null where id = $1`, sessionID); err != nil {
		t.Fatal(err)
	}
	sessions, err = postgres.ListSessions(ctx, target, runtimeID)
	if err != nil || len(sessions) != 1 || sessions[0].WorkspaceID != nil {
		t.Fatalf("explicit session mapping without workspace: %#v, %v", sessions, err)
	}
	scope.Workspaces = []string{}
	if _, err := postgres.PutRuntimeGrant(ctx, owner, deviceID, ownerProof, runtimeID, targetID, RuntimeGrantInput{Role: "viewer", Scope: scope}); err != nil {
		t.Fatal(err)
	}
	runtimes, err = postgres.ListRuntimes(ctx, target)
	if err != nil || len(runtimes) != 1 || runtimes[0].Access.GrantVersion != 2 || len(runtimes[0].Access.Scope.Workspaces) != 0 {
		t.Fatalf("directory retained stale grant authority: %#v, %v", runtimes, err)
	}
	if _, err := postgres.RevokeRuntimeGrant(ctx, owner, deviceID, ownerProof, runtimeID, targetID); err != nil {
		t.Fatal(err)
	}
	runtimes, err = postgres.ListRuntimes(ctx, target)
	if err != nil || len(runtimes) != 0 {
		t.Fatalf("revoked grant remained visible: %#v, %v", runtimes, err)
	}
	otherIssuer, err := postgres.ListRuntimes(ctx, UserIdentity{Issuer: "https://other.example.edu", Subject: target.Subject})
	if err != nil || len(otherIssuer) != 0 {
		t.Fatalf("directory crossed issuer boundary: %#v, %v", otherIssuer, err)
	}
}
