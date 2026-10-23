package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresMigrationGrantLifecycleAndTransactionalOutbox(t *testing.T) {
	dsn := os.Getenv("REMOTE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set REMOTE_TEST_DATABASE_URL to a local PostgreSQL admin DSN to run integration coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	adminConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse test PostgreSQL DSN: %v", err)
	}
	adminConfig.Database = "postgres"
	admin, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("connect to PostgreSQL admin database: %v", err)
	}
	var testDB *sql.DB
	var testDatabaseName string
	t.Cleanup(func() {
		if testDB != nil {
			_ = testDB.Close()
		}
		if testDatabaseName != "" {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cleanupCancel()
			_, _ = admin.Exec(cleanupCtx, "drop database if exists "+testDatabaseName)
		}
		_ = admin.Close(context.Background())
	})

	randomName := make([]byte, 12)
	if _, err := rand.Read(randomName); err != nil {
		t.Fatal(err)
	}
	testDatabaseName = "dsh_remote_test_" + hex.EncodeToString(randomName)
	if _, err := admin.Exec(ctx, "create database "+testDatabaseName); err != nil {
		t.Fatalf("create isolated test database: %v", err)
	}

	testConfig := adminConfig.Copy()
	testConfig.Database = testDatabaseName
	migrationConnection, err := pgx.ConnectConfig(ctx, testConfig)
	if err != nil {
		t.Fatalf("connect to isolated test database: %v", err)
	}
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve integration test source path")
	}
	migrationPath := filepath.Join(filepath.Dir(sourceFile), "../../../../deploy/sql/001_remote_control.up.sql")
	migration, err := os.ReadFile(migrationPath)
	if err != nil {
		_ = migrationConnection.Close(context.Background())
		t.Fatalf("read PostgreSQL migration: %v", err)
	}
	if _, err := migrationConnection.Exec(ctx, string(migration), pgx.QueryExecModeSimpleProtocol); err != nil {
		_ = migrationConnection.Close(context.Background())
		t.Fatalf("apply PostgreSQL migration: %v", err)
	}
	if err := migrationConnection.Close(context.Background()); err != nil {
		t.Fatalf("close migration connection: %v", err)
	}

	testDB = stdlib.OpenDB(*testConfig)
	testDB.SetMaxOpenConns(4)
	if err := testDB.PingContext(ctx); err != nil {
		t.Fatalf("ping isolated test database: %v", err)
	}
	postgres := &Postgres{DB: testDB}
	seedGrantFixture(t, ctx, testDB)
	identity := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	const (
		deviceID  = "44444444-4444-4444-8444-444444444444"
		runtimeID = "55555555-5555-4555-8555-555555555555"
		targetID  = "66666666-6666-4666-8666-666666666666"
	)
	scope := GrantScope{
		Actions:    []string{"command.status", "host.list", "session.list"},
		Workspaces: []string{"77777777-7777-4777-8777-777777777777"},
		Sessions:   []string{},
	}
	input := RuntimeGrantInput{Role: "operator", Scope: scope}

	version, err := postgres.PutRuntimeGrant(ctx, identity, deviceID, runtimeID, targetID, input)
	if err != nil || version != 1 {
		t.Fatalf("create scoped grant: version=%d error=%v", version, err)
	}
	if err := assertGrantState(ctx, testDB, runtimeID, targetID, 1, "operator", false); err != nil {
		t.Fatal(err)
	}
	if err := assertChangeCounts(ctx, testDB, 1, 1); err != nil {
		t.Fatal(err)
	}

	version, err = postgres.PutRuntimeGrant(ctx, identity, deviceID, runtimeID, targetID, input)
	if err != nil || version != 1 {
		t.Fatalf("idempotent grant update: version=%d error=%v", version, err)
	}
	if err := assertChangeCounts(ctx, testDB, 1, 1); err != nil {
		t.Fatal(err)
	}

	widened := RuntimeGrantInput{Role: "operator", Scope: GrantScope{
		Actions:    []string{"command.status", "host.list", "message.submit", "session.list"},
		Workspaces: scope.Workspaces, Sessions: []string{},
	}}
	if _, err := postgres.PutRuntimeGrant(ctx, identity, deviceID, runtimeID, targetID, widened); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("out-of-scope action update error=%v, want ErrAccessDenied", err)
	}
	if err := assertGrantState(ctx, testDB, runtimeID, targetID, 1, "operator", false); err != nil {
		t.Fatal(err)
	}
	if err := assertChangeCounts(ctx, testDB, 1, 1); err != nil {
		t.Fatal(err)
	}

	version, err = postgres.PutRuntimeGrant(ctx, identity, deviceID, runtimeID, targetID, RuntimeGrantInput{
		Role: "viewer", Scope: GrantScope{Actions: []string{"host.list"}, Workspaces: []string{}, Sessions: []string{}},
	})
	if err != nil || version != 2 {
		t.Fatalf("narrow grant update: version=%d error=%v", version, err)
	}
	if err := assertChangeCounts(ctx, testDB, 2, 2); err != nil {
		t.Fatal(err)
	}

	unknownDeviceID := "88888888-8888-4888-8888-888888888888"
	if _, err := postgres.PutRuntimeGrant(ctx, identity, unknownDeviceID, runtimeID, targetID, input); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatalf("audit failure error=%v, want ErrDatabaseUnavailable", err)
	}
	if err := assertGrantState(ctx, testDB, runtimeID, targetID, 2, "viewer", false); err != nil {
		t.Fatalf("failed audit did not roll grant update back: %v", err)
	}
	if err := assertChangeCounts(ctx, testDB, 2, 2); err != nil {
		t.Fatalf("failed audit left an outbox record: %v", err)
	}

	version, err = postgres.RevokeRuntimeGrant(ctx, identity, deviceID, runtimeID, targetID)
	if err != nil || version != 3 {
		t.Fatalf("revoke scoped grant: version=%d error=%v", version, err)
	}
	if err := assertGrantState(ctx, testDB, runtimeID, targetID, 3, "viewer", true); err != nil {
		t.Fatal(err)
	}
	if err := assertChangeCounts(ctx, testDB, 3, 3); err != nil {
		t.Fatal(err)
	}
	version, err = postgres.RevokeRuntimeGrant(ctx, identity, deviceID, runtimeID, targetID)
	if err != nil || version != 3 {
		t.Fatalf("idempotent grant revoke: version=%d error=%v", version, err)
	}
	if err := assertChangeCounts(ctx, testDB, 3, 3); err != nil {
		t.Fatal(err)
	}

	if _, err := postgres.RevokeRuntimeGrant(ctx, identity, deviceID, runtimeID, "22222222-2222-4222-8222-222222222222"); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("last owner was allowed to revoke itself: %v", err)
	}
	if err := assertChangeCounts(ctx, testDB, 3, 3); err != nil {
		t.Fatal(err)
	}

	hosts, err := postgres.ListHosts(ctx, identity)
	if err != nil || len(hosts) != 1 || hosts[0].ID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("owner host visibility: hosts=%+v error=%v", hosts, err)
	}
	runtimes, err := postgres.ListRuntimes(ctx, identity)
	if err != nil || len(runtimes) != 1 || runtimes[0].ID != runtimeID {
		t.Fatalf("owner runtime visibility: runtimes=%+v error=%v", runtimes, err)
	}
	sessions, err := postgres.ListSessions(ctx, identity, runtimeID)
	if err != nil || len(sessions) != 1 || sessions[0].ID != "99999999-9999-4999-8999-999999999999" {
		t.Fatalf("owner session visibility: sessions=%+v error=%v", sessions, err)
	}
	ticketScope := GrantScope{Actions: []string{"session.list"}, Workspaces: scope.Workspaces, Sessions: []string{}}
	if _, err := postgres.IssueRealtimeTicket(ctx, identity, deviceID, runtimeID, GrantScope{
		Actions: []string{"message.submit"}, Workspaces: scope.Workspaces, Sessions: []string{},
	}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("ticket scope exceeded active grant: %v", err)
	}
	if _, err := postgres.IssueRealtimeTicket(ctx, identity, deviceID, runtimeID, GrantScope{
		Actions: []string{"grant.manage"}, Workspaces: []string{}, Sessions: []string{},
	}); !errors.Is(err, ErrGrantInvalid) {
		t.Fatalf("ticket exposed grant-management action: %v", err)
	}
	ticket, err := postgres.IssueRealtimeTicket(ctx, identity, deviceID, runtimeID, ticketScope)
	if err != nil || len(ticket.Token) != 43 || ticket.GrantVersion != 1 || !ticket.ExpiresAt.After(time.Now()) || ticket.ExpiresAt.After(time.Now().Add(31*time.Second)) {
		t.Fatalf("issue scoped realtime ticket: ticket=%+v error=%v", ticket, err)
	}
	var storedTicketHash []byte
	if err := testDB.QueryRowContext(ctx, `select token_sha256 from realtime_tickets where runtime_id = $1`, runtimeID).Scan(&storedTicketHash); err != nil {
		t.Fatalf("read stored ticket digest: %v", err)
	}
	if len(storedTicketHash) != 32 || string(storedTicketHash) == ticket.Token {
		t.Fatal("database did not store only the SHA-256 ticket digest")
	}
	redemption, err := postgres.ConsumeRealtimeTicket(ctx, ticket.Token)
	if err != nil || redemption.UserID != "22222222-2222-4222-8222-222222222222" || redemption.DeviceID != deviceID ||
		redemption.RuntimeID != runtimeID || redemption.GrantVersion != ticket.GrantVersion || !redemption.ConsumedAt.After(time.Time{}) {
		t.Fatalf("consume realtime ticket: redemption=%+v error=%v", redemption, err)
	}
	if err := assertChangeCounts(ctx, testDB, 5, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.ConsumeRealtimeTicket(ctx, ticket.Token); !errors.Is(err, ErrTicketInvalid) {
		t.Fatalf("replayed realtime ticket error=%v, want ErrTicketInvalid", err)
	}
	staleTicket, err := postgres.IssueRealtimeTicket(ctx, identity, deviceID, runtimeID, ticketScope)
	if err != nil {
		t.Fatalf("issue ticket for stale-grant check: %v", err)
	}
	if _, err := testDB.ExecContext(ctx, `update runtime_grants set grant_version = grant_version + 1 where runtime_id = $1 and user_id = $2`, runtimeID, "22222222-2222-4222-8222-222222222222"); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.ConsumeRealtimeTicket(ctx, staleTicket.Token); !errors.Is(err, ErrTicketInvalid) {
		t.Fatalf("ticket survived a grant version change: %v", err)
	}
	if err := assertChangeCounts(ctx, testDB, 6, 3); err != nil {
		t.Fatal(err)
	}
	activeDeviceID, err := postgres.ActiveDevice(ctx, identity, "proof-jkt-actor")
	if err != nil || activeDeviceID != deviceID {
		t.Fatalf("active device lookup: id=%s error=%v", activeDeviceID, err)
	}
	if err := postgres.RevokeDevice(ctx, identity.Issuer, identity.Subject, deviceID); err != nil {
		t.Fatalf("revoke device: %v", err)
	}
	if _, err := postgres.ActiveDevice(ctx, identity, "proof-jkt-actor"); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("revoked device remained active: %v", err)
	}
	if err := postgres.RevokeDevice(ctx, identity.Issuer, identity.Subject, deviceID); err != nil {
		t.Fatalf("idempotent device revoke: %v", err)
	}
	if err := assertChangeCounts(ctx, testDB, 7, 4); err != nil {
		t.Fatal(err)
	}
}

func seedGrantFixture(t *testing.T, ctx context.Context, database *sql.DB) {
	t.Helper()
	const (
		orgID          = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		otherOrgID     = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
		actorID        = "22222222-2222-4222-8222-222222222222"
		targetID       = "66666666-6666-4666-8666-666666666666"
		outsiderID     = "33333333-3333-4333-8333-333333333333"
		hostID         = "11111111-1111-4111-8111-111111111111"
		installationID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
		runtimeID      = "55555555-5555-4555-8555-555555555555"
		workspaceID    = "77777777-7777-4777-8777-777777777777"
		sessionID      = "99999999-9999-4999-8999-999999999999"
		deviceID       = "44444444-4444-4444-8444-444444444444"
	)
	statements := []struct {
		query string
		args  []any
	}{
		{`insert into orgs (id, slug, name) values ($1, 'test-org', 'Test org'), ($2, 'other-org', 'Other org')`, []any{orgID, otherOrgID}},
		{`insert into users (id, issuer, subject) values ($1, 'https://id.example.edu', 'owner-subject'), ($2, 'https://id.example.edu', 'target-subject'), ($3, 'https://id.example.edu', 'outsider-subject')`, []any{actorID, targetID, outsiderID}},
		{`insert into org_memberships (org_id, user_id, role) values ($1, $2, 'member'), ($1, $3, 'member'), ($4, $5, 'member')`, []any{orgID, actorID, targetID, otherOrgID, outsiderID}},
		{`insert into devices (id, user_id, name, approval_public_jwk, approval_key_thumbprint, proof_public_jwk, proof_key_thumbprint) values ($1, $2, 'owner phone', '{}'::jsonb, 'approval-jkt-actor', '{}'::jsonb, 'proof-jkt-actor')`, []any{deviceID, actorID}},
		{`insert into hosts (id, org_id, alias, state) values ($1, $2, 'Test host', 'active')`, []any{hostID, orgID}},
		{`insert into installations (id, host_id, owner_user_id, public_jwk, public_key_thumbprint) values ($1, $2, $3, '{}'::jsonb, 'installation-jkt')`, []any{installationID, hostID, actorID}},
		{`insert into runtimes (id, installation_id, profile_ref, protocol_version) values ($1, $2, 'test-profile', 1)`, []any{runtimeID, installationID}},
		{`insert into workspaces (id, runtime_id, workspace_ref) values ($1, $2, 'workspace-test')`, []any{workspaceID, runtimeID}},
		{`insert into sessions (id, runtime_id, workspace_id, dsh_session_id) values ($1, $2, $3, 'opaque-dsh-session')`, []any{sessionID, runtimeID, workspaceID}},
		{`insert into runtime_grants (runtime_id, user_id, role, scope, granted_by) values ($1, $2, 'owner', $3::jsonb, $2)`, []any{
			runtimeID, actorID, `{"actions":["grant.manage","host.list","session.list","command.status"],"workspaces":["` + workspaceID + `"],"sessions":["` + sessionID + `"]}`,
		}},
	}
	for _, statement := range statements {
		if _, err := database.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed PostgreSQL integration fixture: %v", err)
		}
	}
}

func assertGrantState(ctx context.Context, database *sql.DB, runtimeID, userID string, version int64, role string, revoked bool) error {
	var actualVersion int64
	var actualRole string
	var revokedAt sql.NullTime
	if err := database.QueryRowContext(ctx, `select grant_version, role, revoked_at from runtime_grants where runtime_id = $1 and user_id = $2`, runtimeID, userID).
		Scan(&actualVersion, &actualRole, &revokedAt); err != nil {
		return err
	}
	if actualVersion != version || actualRole != role || revokedAt.Valid != revoked {
		return errors.New("runtime grant row did not match expected state")
	}
	return nil
}

func assertChangeCounts(ctx context.Context, database *sql.DB, audits, outbox int) error {
	var actualAudits, actualOutbox int
	if err := database.QueryRowContext(ctx, `select count(*) from audit_log`).Scan(&actualAudits); err != nil {
		return err
	}
	if err := database.QueryRowContext(ctx, `select count(*) from control_outbox`).Scan(&actualOutbox); err != nil {
		return err
	}
	if actualAudits != audits || actualOutbox != outbox {
		return errors.New("audit or outbox row count did not match expected transaction state")
	}
	return nil
}
