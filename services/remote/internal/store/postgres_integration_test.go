package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
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
	for _, name := range []string{"001_remote_control.up.sql", "002_enrollment_runtime.up.sql", "003_host_credentials.up.sql", "004_realtime_handshake.up.sql", "005_session_creation_commands.up.sql"} {
		migrationPath := filepath.Join(filepath.Dir(sourceFile), "../../../../deploy/sql", name)
		migration, err := os.ReadFile(migrationPath)
		if err != nil {
			_ = migrationConnection.Close(context.Background())
			t.Fatalf("read PostgreSQL migration %s: %v", name, err)
		}
		if _, err := migrationConnection.Exec(ctx, string(migration), pgx.QueryExecModeSimpleProtocol); err != nil {
			_ = migrationConnection.Close(context.Background())
			t.Fatalf("apply PostgreSQL migration %s: %v", name, err)
		}
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
	deviceProofThumbprint := seedGrantFixture(t, ctx, testDB)
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
	ticketDigest := sha256.Sum256([]byte(ticket.Token))
	if string(storedTicketHash) != string(ticketDigest[:]) {
		t.Fatal("ticket database digest does not match the returned token")
	}
	var ticketDeviceKeyVersion int64
	var ticketProofThumbprint string
	if err := testDB.QueryRowContext(ctx, `select device_key_version, proof_key_thumbprint from realtime_tickets where token_sha256 = $1`, ticketDigest[:]).
		Scan(&ticketDeviceKeyVersion, &ticketProofThumbprint); err != nil {
		t.Fatal(err)
	}
	if ticketDeviceKeyVersion != 1 || ticketProofThumbprint != deviceProofThumbprint {
		t.Fatalf("ticket was not bound to the current device key: version=%d thumbprint=%s", ticketDeviceKeyVersion, ticketProofThumbprint)
	}
	preparedTicket, err := postgres.PrepareRealtimeTicket(ctx, ticket.Token)
	if err != nil || preparedTicket.DeviceID != deviceID || !preparedTicket.ConsumedAt.IsZero() {
		t.Fatalf("prepare realtime ticket without consuming it: redemption=%+v error=%v", preparedTicket, err)
	}
	var pendingConsumption sql.NullTime
	if err := testDB.QueryRowContext(ctx, `select consumed_at from realtime_tickets where token_sha256 = $1`, ticketDigest[:]).Scan(&pendingConsumption); err != nil {
		t.Fatal(err)
	}
	if pendingConsumption.Valid {
		t.Fatal("ticket preparation consumed the ticket before the device proof")
	}
	redemption, err := postgres.ConsumeRealtimeTicket(ctx, ticket.Token)
	if err != nil || redemption.UserID != "22222222-2222-4222-8222-222222222222" || redemption.DeviceID != deviceID ||
		redemption.RuntimeID != runtimeID || redemption.GrantVersion != ticket.GrantVersion ||
		redemption.ProofKeyThumbprint != deviceProofThumbprint || !redemption.ConsumedAt.After(time.Time{}) {
		t.Fatalf("consume realtime ticket: redemption=%+v error=%v", redemption, err)
	}
	redemptionThumbprint, err := auth.PublicP256JWKThumbprintJSON(redemption.ProofPublicJWK)
	if err != nil || redemptionThumbprint != deviceProofThumbprint {
		t.Fatalf("ticket redemption did not return the bound public key: thumbprint=%s error=%v", redemptionThumbprint, err)
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
	staleKeyTicket, err := postgres.IssueRealtimeTicket(ctx, identity, deviceID, runtimeID, ticketScope)
	if err != nil {
		t.Fatalf("issue ticket for stale-device-key check: %v", err)
	}
	if _, err := testDB.ExecContext(ctx, `update devices set key_version = key_version + 1 where id = $1`, deviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.ConsumeRealtimeTicket(ctx, staleKeyTicket.Token); !errors.Is(err, ErrTicketInvalid) {
		t.Fatalf("ticket survived a device-key version change: %v", err)
	}
	if err := assertChangeCounts(ctx, testDB, 7, 3); err != nil {
		t.Fatal(err)
	}

	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	installationJWK, err := integrationP256JWK(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	installationThumbprint, err := auth.PublicP256JWKThumbprintJSON(installationJWK)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentCodeBytes := make([]byte, 32)
	if _, err := rand.Read(enrollmentCodeBytes); err != nil {
		t.Fatal(err)
	}
	enrollmentCode := base64.RawURLEncoding.EncodeToString(enrollmentCodeBytes)
	for index := range enrollmentCodeBytes {
		enrollmentCodeBytes[index] = 0
	}
	enrollmentInput := EnrollmentInput{
		Issuer: identity.Issuer, Subject: identity.Subject,
		RequestID: "aaaaaaaa-1111-4111-8111-111111111111", OrganizationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		Alias: "Second host", ProfileRef: "profile-lab", DSHVersion: "0.2.1-rc.2",
		ApplicationVersion: "1.0.0", PluginVersion: "0.1.0", ProtocolVersion: 1,
		InstallationPublicJWK: installationJWK, InstallationKeyThumbprint: installationThumbprint,
		Code: enrollmentCode, WorkspaceRefs: []string{"project"},
	}
	enrollment, err := postgres.CreateEnrollment(ctx, enrollmentInput)
	if err != nil || enrollment.State != "pending" || len(enrollment.Workspaces) != 1 || enrollment.Workspaces[0].Reference != "project" {
		t.Fatalf("create enrollment: enrollment=%+v error=%v", enrollment, err)
	}
	var storedCodeHash []byte
	if err := testDB.QueryRowContext(ctx, `select code_hash from enrollments where id = $1`, enrollment.EnrollmentID).Scan(&storedCodeHash); err != nil {
		t.Fatal(err)
	}
	if len(storedCodeHash) != 32 || string(storedCodeHash) == enrollmentCode {
		t.Fatal("enrollment code was stored in plaintext")
	}
	if err := assertChangeCounts(ctx, testDB, 8, 4); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.CreateEnrollment(ctx, enrollmentInput); err != nil {
		t.Fatalf("idempotent enrollment retry: %v", err)
	}
	conflictingEnrollment := enrollmentInput
	conflictingEnrollment.Alias = "Other host"
	if _, err := postgres.CreateEnrollment(ctx, conflictingEnrollment); !errors.Is(err, ErrEnrollmentConflict) {
		t.Fatalf("conflicting enrollment retry error=%v, want ErrEnrollmentConflict", err)
	}
	if _, err := postgres.GetEnrollment(ctx, UserIdentity{Issuer: identity.Issuer, Subject: "target-subject"}, enrollment.EnrollmentID); err != nil {
		t.Fatalf("organization member could not inspect enrollment: %v", err)
	}
	if _, err := postgres.GetEnrollment(ctx, UserIdentity{Issuer: identity.Issuer, Subject: "outsider-subject"}, enrollment.EnrollmentID); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("unaffiliated user inspected enrollment: %v", err)
	}
	phoneIdentity := UserIdentity{Issuer: identity.Issuer, Subject: "target-subject"}
	const phoneDeviceID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	wrongCodeBytes := make([]byte, 32)
	if _, err := rand.Read(wrongCodeBytes); err != nil {
		t.Fatal(err)
	}
	wrongCode := base64.RawURLEncoding.EncodeToString(wrongCodeBytes)
	for index := range wrongCodeBytes {
		wrongCodeBytes[index] = 0
	}
	if _, err := postgres.ConfirmEnrollmentUser(ctx, phoneIdentity, phoneDeviceID, enrollment.EnrollmentID, wrongCode); !errors.Is(err, ErrEnrollmentInvalid) {
		t.Fatalf("wrong enrollment code error=%v, want ErrEnrollmentInvalid", err)
	}
	partial, err := postgres.ConfirmEnrollmentUser(ctx, phoneIdentity, phoneDeviceID, enrollment.EnrollmentID, enrollmentCode)
	if err != nil || partial.State != "user_confirmed" {
		t.Fatalf("phone confirmation: state=%s error=%v", partial.State, err)
	}
	if err := assertChangeCounts(ctx, testDB, 9, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.ConfirmEnrollmentHost(ctx, identity, "wrong-installation-key", enrollment.EnrollmentID, enrollmentCode); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("host confirmation with wrong key error=%v, want ErrAccessDenied", err)
	}
	approved, err := postgres.ConfirmEnrollmentHost(ctx, identity, installationThumbprint, enrollment.EnrollmentID, enrollmentCode)
	if err != nil || approved.State != "approved" {
		t.Fatalf("host confirmation: state=%s error=%v", approved.State, err)
	}
	if err := assertChangeCounts(ctx, testDB, 12, 8); err != nil {
		t.Fatal(err)
	}
	challenge, err := postgres.CreateHostCredentialChallenge(ctx, identity, installationThumbprint)
	if err != nil || challenge.InstallationID != enrollment.InstallationID || challenge.Audience != auth.HostCredentialProofAudience {
		t.Fatalf("create installation challenge: challenge=%+v error=%v", challenge, err)
	}
	var staleChallenge HostCredentialChallenge
	for pending := 1; pending < 4; pending++ {
		createdChallenge, err := postgres.CreateHostCredentialChallenge(ctx, identity, installationThumbprint)
		if err != nil {
			t.Fatalf("create pending installation challenge %d: %v", pending+1, err)
		}
		if pending == 3 {
			staleChallenge = createdChallenge
		}
	}
	if _, err := postgres.CreateHostCredentialChallenge(ctx, identity, installationThumbprint); !errors.Is(err, ErrHostChallengeLimit) {
		t.Fatalf("fifth pending installation challenge error=%v, want ErrHostChallengeLimit", err)
	}
	var challengeHash []byte
	if err := testDB.QueryRowContext(ctx, `select challenge_sha256 from installation_challenges where id = $1`, challenge.ChallengeID).Scan(&challengeHash); err != nil {
		t.Fatal(err)
	}
	if len(challengeHash) != 32 || string(challengeHash) == challenge.Challenge {
		t.Fatal("installation challenge was stored in plaintext")
	}
	expectedChallengeHash := sha256.Sum256([]byte(challenge.Challenge))
	if string(challengeHash) != string(expectedChallengeHash[:]) {
		t.Fatal("installation challenge digest does not match the returned challenge")
	}
	hostProof := integrationHostCredentialProof(t, hostKey, challenge)
	if _, err := postgres.ExchangeHostCredential(ctx, identity, installationThumbprint, challenge.ChallengeID, hostProof+"."); !errors.Is(err, ErrHostCredentialInvalid) {
		t.Fatalf("invalid installation proof error=%v, want ErrHostCredentialInvalid", err)
	}
	connectionCredential, err := postgres.ExchangeHostCredential(ctx, identity, installationThumbprint, challenge.ChallengeID, hostProof)
	if err != nil || connectionCredential.InstallationID != enrollment.InstallationID || connectionCredential.KeyThumbprint != installationThumbprint {
		t.Fatalf("exchange installation challenge: credential=%+v error=%v", connectionCredential, err)
	}
	var credentialHash []byte
	if err := testDB.QueryRowContext(ctx, `select token_sha256 from host_connection_credentials where installation_id = $1`, enrollment.InstallationID).Scan(&credentialHash); err != nil {
		t.Fatal(err)
	}
	if len(credentialHash) != 32 || string(credentialHash) == connectionCredential.Credential {
		t.Fatal("host connection credential was stored in plaintext")
	}
	expectedCredentialHash := sha256.Sum256([]byte(connectionCredential.Credential))
	if string(credentialHash) != string(expectedCredentialHash[:]) {
		t.Fatal("host credential digest does not match the returned credential")
	}
	verifiedCredential, err := postgres.ValidateHostConnectionCredential(ctx, connectionCredential.Credential, installationThumbprint)
	if err != nil || verifiedCredential.InstallationID != enrollment.InstallationID {
		t.Fatalf("validate active host credential: result=%+v error=%v", verifiedCredential, err)
	}
	otherHostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublicJWK, err := integrationP256JWK(otherHostKey)
	if err != nil {
		t.Fatal(err)
	}
	otherThumbprint, err := auth.PublicP256JWKThumbprintJSON(otherPublicJWK)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.ValidateHostConnectionCredential(ctx, connectionCredential.Credential, otherThumbprint); !errors.Is(err, ErrHostCredentialInvalid) {
		t.Fatalf("host credential accepted a different installation key: %v", err)
	}
	if _, err := postgres.ExchangeHostCredential(ctx, identity, installationThumbprint, challenge.ChallengeID, hostProof); !errors.Is(err, ErrHostCredentialInvalid) {
		t.Fatalf("replayed installation challenge error=%v, want ErrHostCredentialInvalid", err)
	}
	connection, err := postgres.AttachRuntimeConnection(ctx, RuntimeConnectionInput{
		InstallationID: enrollment.InstallationID, KeyVersion: 1, RuntimeID: enrollment.RuntimeID,
		RuntimeEpoch: "99999999-9999-4999-8999-999999999999", ConnectionID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
		DSHVersion: "0.2.1-rc.2", ApplicationVersion: "1.0.0", PluginVersion: "0.1.0", ProtocolVersion: 1,
	})
	if err != nil || connection.RuntimeID != enrollment.RuntimeID {
		t.Fatalf("attach installation runtime: connection=%+v error=%v", connection, err)
	}
	replacement, err := postgres.AttachRuntimeConnection(ctx, RuntimeConnectionInput{
		InstallationID: enrollment.InstallationID, KeyVersion: 1, RuntimeID: enrollment.RuntimeID,
		RuntimeEpoch: connection.RuntimeEpoch, ConnectionID: "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
		DSHVersion: "0.2.1-rc.2", ApplicationVersion: "1.0.0", PluginVersion: "0.1.0", ProtocolVersion: 1,
	})
	if err != nil {
		t.Fatalf("replace runtime connection: %v", err)
	}
	relayNativeSessionID := "relay-session"
	relaySessionID, err := MobileSessionID(enrollment.RuntimeID, relayNativeSessionID)
	if err != nil {
		t.Fatal(err)
	}
	workspaceID := enrollment.Workspaces[0].ID
	if err := postgres.SyncRealtimeSessionCatalog(ctx, replacement, 1, true, []SessionCatalogItem{{
		SessionID: relaySessionID, DSHSessionID: relayNativeSessionID, WorkspaceID: &workspaceID,
		State: "running", LastPersistedSeq: 12,
	}}); err != nil {
		t.Fatalf("sync runtime session catalog: %v", err)
	}
	if err := postgres.SyncRealtimeSessionCatalog(ctx, replacement, 1, false, []SessionCatalogItem{{
		SessionID: relaySessionID, DSHSessionID: relayNativeSessionID, WorkspaceID: &workspaceID,
		State: "running", LastPersistedSeq: 13,
	}}); err != nil {
		t.Fatalf("refresh runtime session catalog: %v", err)
	}
	visibleSessions, err := postgres.ListSessions(ctx, identity, enrollment.RuntimeID)
	if err != nil || len(visibleSessions) != 1 || visibleSessions[0].ID != relaySessionID ||
		visibleSessions[0].State != "running" || visibleSessions[0].LastPersistedSeq != 13 {
		t.Fatalf("catalog metadata was not exposed through the active workspace grant: sessions=%+v error=%v", visibleSessions, err)
	}
	if err := postgres.SyncRealtimeSessionCatalog(ctx, connection, 1, true, nil); !errors.Is(err, ErrRuntimeConnectionStale) {
		t.Fatalf("superseded connection changed the session directory: %v", err)
	}
	unknownWorkspace := "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	if err := postgres.SyncRealtimeSessionCatalog(ctx, replacement, 1, true, []SessionCatalogItem{{
		SessionID: relaySessionID, DSHSessionID: relayNativeSessionID, WorkspaceID: &unknownWorkspace,
		State: "available", LastPersistedSeq: 0,
	}}); !errors.Is(err, ErrSessionCatalogInvalid) {
		t.Fatalf("unregistered workspace was accepted: %v", err)
	}
	visibleSessions, err = postgres.ListSessions(ctx, identity, enrollment.RuntimeID)
	if err != nil || len(visibleSessions) != 1 || visibleSessions[0].State != "running" || visibleSessions[0].LastPersistedSeq != 13 {
		t.Fatalf("rejected snapshot changed the directory: sessions=%+v error=%v", visibleSessions, err)
	}
	if err := postgres.SyncRealtimeSessionCatalog(ctx, replacement, 1, false, []SessionCatalogItem{{
		SessionID: relaySessionID, DSHSessionID: relayNativeSessionID, State: "unavailable", LastPersistedSeq: -1,
	}}); err != nil {
		t.Fatalf("remove session through catalog delta: %v", err)
	}
	var removedSeq int64
	var removedWorkspace sql.NullString
	if err := testDB.QueryRowContext(ctx, `select workspace_id::text, last_persisted_seq from sessions where id = $1`, relaySessionID).Scan(&removedWorkspace, &removedSeq); err != nil || removedWorkspace.Valid || removedSeq != 13 {
		t.Fatalf("tombstone did not clear scope and preserve persisted cursor: workspace=%v seq=%d error=%v", removedWorkspace, removedSeq, err)
	}
	if err := postgres.SyncRealtimeSessionCatalog(ctx, replacement, 1, true, nil); err != nil {
		t.Fatalf("replace runtime session catalog with empty snapshot: %v", err)
	}
	var unavailableState string
	if err := testDB.QueryRowContext(ctx, `select state from sessions where id = $1`, relaySessionID).Scan(&unavailableState); err != nil || unavailableState != "unavailable" {
		t.Fatalf("removed session was not marked unavailable: state=%q error=%v", unavailableState, err)
	}
	if err := postgres.SyncRealtimeSessionCatalog(ctx, replacement, 1, true, []SessionCatalogItem{{
		SessionID: relaySessionID, DSHSessionID: relayNativeSessionID, WorkspaceID: &workspaceID,
		State: "running", LastPersistedSeq: 13,
	}}); err != nil {
		t.Fatalf("restore runtime session catalog: %v", err)
	}
	messageScope := GrantScope{Actions: []string{"message.submit", "session.cancel", "session.read"}, Workspaces: []string{enrollment.Workspaces[0].ID}, Sessions: []string{}}
	messageTicket, err := postgres.IssueRealtimeTicket(ctx, identity, deviceID, enrollment.RuntimeID, messageScope)
	if err != nil {
		t.Fatalf("issue message ticket: %v", err)
	}
	messageTicketRedemption, err := postgres.PrepareRealtimeTicket(ctx, messageTicket.Token)
	if err != nil {
		t.Fatalf("prepare message ticket: %v", err)
	}
	messageTicketRedemption, err = postgres.ConsumeRealtimeTicket(ctx, messageTicket.Token)
	if err != nil {
		t.Fatalf("consume message ticket: %v", err)
	}
	if err := postgres.AuthorizeRealtimeSessionRead(ctx, messageTicketRedemption, relaySessionID); err != nil {
		t.Fatalf("active workspace read grant denied: %v", err)
	}
	deviceConnectionID := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	deviceLease := RealtimeConnectionLease{
		Role: "device", ConnectionID: deviceConnectionID, RuntimeID: enrollment.RuntimeID,
		UserID: &messageTicketRedemption.UserID, DeviceID: &messageTicketRedemption.DeviceID,
		DeviceKeyVersion: messageTicketRedemption.DeviceKeyVersion, ProofKeyThumbprint: messageTicketRedemption.ProofKeyThumbprint,
		GrantVersion: messageTicketRedemption.GrantVersion, Scope: messageTicketRedemption.Scope,
	}
	hostLease := RealtimeConnectionLease{
		Role: "installation", ConnectionID: replacement.ConnectionID, RuntimeID: enrollment.RuntimeID,
		RuntimeEpoch: &replacement.RuntimeEpoch, InstallationID: &enrollment.InstallationID, KeyVersion: 1,
	}
	assertConnectionLeases(t, ctx, postgres, []RealtimeConnectionLease{deviceLease, hostLease})
	for _, variant := range []string{"device-key", "proof-key", "grant-version", "scope", "user", "host-key", "epoch", "connection"} {
		deviceVariant, hostVariant := deviceLease, hostLease
		otherID := "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
		want := deviceConnectionID
		switch variant {
		case "device-key":
			deviceVariant.DeviceKeyVersion++
		case "proof-key":
			deviceVariant.ProofKeyThumbprint = "other-key"
		case "grant-version":
			deviceVariant.GrantVersion++
		case "scope":
			deviceVariant.Scope.Workspaces = []string{otherID}
		case "user":
			deviceVariant.UserID = &otherID
		case "host-key":
			hostVariant.KeyVersion++
			want = hostVariant.ConnectionID
		case "epoch":
			hostVariant.RuntimeEpoch = &otherID
			want = hostVariant.ConnectionID
		case "connection":
			hostVariant.ConnectionID = connection.ConnectionID
			want = hostVariant.ConnectionID
		}
		assertConnectionLeases(t, ctx, postgres, []RealtimeConnectionLease{deviceVariant, hostVariant}, want)
	}
	if _, err := testDB.ExecContext(ctx, `update runtime_grants set expires_at = clock_timestamp() - interval '1 second' where runtime_id = $1 and user_id = $2`, enrollment.RuntimeID, messageTicketRedemption.UserID); err != nil {
		t.Fatal(err)
	}
	assertConnectionLeases(t, ctx, postgres, []RealtimeConnectionLease{deviceLease, hostLease}, deviceConnectionID)
	if _, err := testDB.ExecContext(ctx, `update runtime_grants set expires_at = null where runtime_id = $1 and user_id = $2`, enrollment.RuntimeID, messageTicketRedemption.UserID); err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"missing-action", "empty-resources", "wrong-device-key", "wrong-runtime", "wrong-grant-version"} {
		ticket := messageTicketRedemption
		switch variant {
		case "missing-action":
			ticket.Scope.Actions = []string{"message.submit"}
		case "empty-resources":
			ticket.Scope.Workspaces = []string{}
		case "wrong-device-key":
			ticket.DeviceKeyVersion++
		case "wrong-runtime":
			ticket.RuntimeID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
		case "wrong-grant-version":
			ticket.GrantVersion++
		}
		if err := postgres.AuthorizeRealtimeSessionRead(ctx, ticket, relaySessionID); !errors.Is(err, ErrAccessDenied) {
			t.Fatalf("session read accepted %s: %v", variant, err)
		}
	}
	messageDigest := sha256.Sum256([]byte("canonical relay message body"))
	messageDigestHex := hex.EncodeToString(messageDigest[:])
	const relayRequestID = "cccccccc-1111-4111-8111-111111111111"
	receivedCommand, err := postgres.RecordRealtimeCommand(ctx, messageTicketRedemption, "message.submit", relayRequestID, relaySessionID, messageDigestHex)
	if err != nil || receivedCommand.State != "received" || receivedCommand.PayloadSHA256 != messageDigestHex {
		t.Fatalf("persist message receipt: command=%+v error=%v", receivedCommand, err)
	}
	if err := postgres.AuthorizeRealtimeCommandReceipt(ctx, messageTicketRedemption, receivedCommand); err != nil {
		t.Fatalf("workspace recipient denied: %v", err)
	}
	for _, variant := range []string{"scope", "device-key", "grant-version", "request", "digest", "session"} {
		ticket, status := messageTicketRedemption, receivedCommand
		switch variant {
		case "scope":
			ticket.Scope.Workspaces = []string{}
			ticket.Scope.Sessions = []string{}
		case "device-key":
			ticket.DeviceKeyVersion++
		case "grant-version":
			ticket.GrantVersion++
		case "request":
			status.RequestID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
		case "digest":
			status.PayloadSHA256 = strings.Repeat("0", 64)
		case "session":
			status.SessionID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
		}
		if err := postgres.AuthorizeRealtimeCommandReceipt(ctx, ticket, status); !errors.Is(err, ErrAccessDenied) && !errors.Is(err, ErrTicketInvalid) {
			t.Fatalf("receipt accepted %s: %v", variant, err)
		}
	}
	retriedCommand, err := postgres.RecordRealtimeCommand(ctx, messageTicketRedemption, "message.submit", relayRequestID, relaySessionID, messageDigestHex)
	if err != nil || retriedCommand.State != "received" {
		t.Fatalf("idempotent message receipt: command=%+v error=%v", retriedCommand, err)
	}
	conflictingDigest := sha256.Sum256([]byte("different relay message body"))
	if _, err := postgres.RecordRealtimeCommand(ctx, messageTicketRedemption, "message.submit", relayRequestID, relaySessionID, hex.EncodeToString(conflictingDigest[:])); !errors.Is(err, ErrCommandConflict) {
		t.Fatalf("same request ID with another payload error=%v, want ErrCommandConflict", err)
	}
	commandReceipt := RelayCommandReceipt{
		InstallationID: enrollment.InstallationID, KeyVersion: 1, RuntimeID: enrollment.RuntimeID,
		RuntimeEpoch: replacement.RuntimeEpoch, ConnectionID: replacement.ConnectionID, DeviceID: deviceID,
		RequestID: relayRequestID, SessionID: relaySessionID, PayloadSHA256: messageDigestHex, State: "host_accepted",
	}
	acceptedCommand, err := postgres.RecordRealtimeCommandReceipt(ctx, commandReceipt)
	if err != nil || acceptedCommand.State != "host_accepted" {
		t.Fatalf("persist host_accepted receipt: status=%+v error=%v", acceptedCommand, err)
	}
	if _, err := postgres.RecordRealtimeCommandReceipt(ctx, commandReceipt); err != nil {
		t.Fatalf("idempotent host_accepted receipt: %v", err)
	}
	commandReceipt.State = "agent_queued"
	queuedCommand, err := postgres.RecordRealtimeCommandReceipt(ctx, commandReceipt)
	if err != nil || queuedCommand.State != "agent_queued" {
		t.Fatalf("persist agent_queued receipt: status=%+v error=%v", queuedCommand, err)
	}
	if _, err := postgres.CommandStatus(ctx, identity, deviceID, relayRequestID); err != nil {
		t.Fatalf("authorized device could not query command status: %v", err)
	}
	const cancelRequestID = "cccccccc-2222-4222-8222-222222222222"
	cancelDigest := sha256.Sum256([]byte("canonical epoch-bound cancel body"))
	cancelDigestHex := hex.EncodeToString(cancelDigest[:])
	noCancel := messageTicketRedemption
	noCancel.Scope.Actions = []string{"message.submit", "session.read"}
	if _, err := postgres.RecordRealtimeCommand(ctx, noCancel, "session.cancel", cancelRequestID, relaySessionID, cancelDigestHex); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("cancel accepted without explicit action: %v", err)
	}
	if _, err := postgres.RecordRealtimeCommand(ctx, noCancel, "question.answer", cancelRequestID, relaySessionID, cancelDigestHex); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("question answer accepted without explicit action: %v", err)
	}
	if _, err := postgres.RecordRealtimeCommand(ctx, messageTicketRedemption, "session.archive", cancelRequestID, relaySessionID, cancelDigestHex); !errors.Is(err, ErrGrantInvalid) {
		t.Fatalf("unimplemented command type accepted: %v", err)
	}
	if _, err := postgres.RecordRealtimeCommand(ctx, messageTicketRedemption, "session.cancel", cancelRequestID, relaySessionID, cancelDigestHex); err != nil {
		t.Fatalf("record cancellation: %v", err)
	}
	cancelReceipt := commandReceipt
	cancelReceipt.RequestID, cancelReceipt.PayloadSHA256, cancelReceipt.State = cancelRequestID, cancelDigestHex, "host_accepted"
	if _, err := postgres.RecordRealtimeCommandReceipt(ctx, cancelReceipt); err != nil {
		t.Fatalf("accept cancellation: %v", err)
	}
	// The host may reconstruct this transition from an already settled journal
	// entry after the Relay lost earlier receipts.
	cancelReceipt.State = "settled"
	if _, err := postgres.RecordRealtimeCommandReceipt(ctx, cancelReceipt); err != nil {
		t.Fatalf("settle recovered cancellation: %v", err)
	}
	if retry, err := postgres.RecordRealtimeCommand(ctx, messageTicketRedemption, "session.cancel", cancelRequestID, relaySessionID, cancelDigestHex); err != nil || retry.State != "settled" {
		t.Fatalf("cancel retry: status=%+v error=%v", retry, err)
	}
	if _, err := postgres.RecordRealtimeCommand(ctx, messageTicketRedemption, "message.submit", cancelRequestID, relaySessionID, messageDigestHex); !errors.Is(err, ErrCommandConflict) {
		t.Fatalf("request ID changed command type: %v", err)
	}
	testPostgresSessionCreation(t, ctx, postgres, messageTicketRedemption, commandReceipt, enrollment.Workspaces[0].ID, relaySessionID)
	if err := postgres.ValidateRealtimeLease(ctx, messageTicketRedemption); err != nil {
		t.Fatalf("active message ticket lease was rejected: %v", err)
	}
	if _, err := testDB.ExecContext(ctx, `update runtime_grants set grant_version = grant_version + 1 where runtime_id = $1 and user_id = $2`, enrollment.RuntimeID, "22222222-2222-4222-8222-222222222222"); err != nil {
		t.Fatal(err)
	}
	if err := postgres.ValidateRealtimeLease(ctx, messageTicketRedemption); !errors.Is(err, ErrTicketInvalid) {
		t.Fatalf("realtime lease survived a grant-version change: %v", err)
	}
	if err := postgres.AuthorizeRealtimeSessionRead(ctx, messageTicketRedemption, relaySessionID); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("session content survived a grant-version change: %v", err)
	}
	assertConnectionLeases(t, ctx, postgres, []RealtimeConnectionLease{deviceLease, hostLease}, deviceConnectionID)
	staleReceipt := commandReceipt
	staleReceipt.ConnectionID = connection.ConnectionID
	staleReceipt.State = "settled"
	if _, err := postgres.RecordRealtimeCommandReceipt(ctx, staleReceipt); !errors.Is(err, ErrRuntimeConnectionStale) {
		t.Fatalf("superseded host connection receipt=%v, want ErrRuntimeConnectionStale", err)
	}
	if err := postgres.TouchRuntimeConnection(ctx, connection.InstallationID, connection.RuntimeID, connection.RuntimeEpoch, connection.ConnectionID); !errors.Is(err, ErrRuntimeConnectionStale) {
		t.Fatalf("superseded runtime connection touch=%v, want ErrRuntimeConnectionStale", err)
	}
	if err := postgres.DetachRuntimeConnection(ctx, connection.InstallationID, connection.RuntimeID, connection.RuntimeEpoch, connection.ConnectionID); err != nil {
		t.Fatalf("stale runtime connection detach: %v", err)
	}
	if err := testDB.QueryRowContext(ctx, `select state from sessions where id = $1`, relaySessionID).Scan(&unavailableState); err != nil || unavailableState != "running" {
		t.Fatalf("stale detach changed the active session: state=%q error=%v", unavailableState, err)
	}
	if _, err := testDB.ExecContext(ctx, `update installations set key_version = key_version + 1 where id = $1`, enrollment.InstallationID); err != nil {
		t.Fatal(err)
	}
	if err := postgres.TouchRuntimeConnection(ctx, replacement.InstallationID, replacement.RuntimeID, replacement.RuntimeEpoch, replacement.ConnectionID); !errors.Is(err, ErrRuntimeConnectionStale) {
		t.Fatalf("runtime connection survived installation-key rotation: %v", err)
	}
	assertConnectionLeases(t, ctx, postgres, []RealtimeConnectionLease{deviceLease, hostLease}, deviceConnectionID, hostLease.ConnectionID)
	if err := postgres.DetachRuntimeConnection(ctx, replacement.InstallationID, replacement.RuntimeID, replacement.RuntimeEpoch, replacement.ConnectionID); err != nil {
		t.Fatalf("detach replacement runtime connection: %v", err)
	}
	if err := postgres.TouchRuntimeConnection(ctx, replacement.InstallationID, replacement.RuntimeID, replacement.RuntimeEpoch, replacement.ConnectionID); !errors.Is(err, ErrRuntimeConnectionStale) {
		t.Fatalf("detached runtime connection touch=%v, want ErrRuntimeConnectionStale", err)
	}
	staleProof := integrationHostCredentialProof(t, hostKey, staleChallenge)
	if _, err := postgres.ExchangeHostCredential(ctx, identity, installationThumbprint, staleChallenge.ChallengeID, staleProof); !errors.Is(err, ErrHostCredentialInvalid) {
		t.Fatalf("challenge from an earlier key version error=%v, want ErrHostCredentialInvalid", err)
	}
	if _, err := postgres.ValidateHostConnectionCredential(ctx, connectionCredential.Credential, installationThumbprint); !errors.Is(err, ErrHostCredentialInvalid) {
		t.Fatalf("credential from an earlier key version error=%v, want ErrHostCredentialInvalid", err)
	}
	if err := assertChangeCounts(ctx, testDB, 38, 8); err != nil {
		t.Fatal(err)
	}
	phoneHosts, err := postgres.ListHosts(ctx, phoneIdentity)
	if err != nil || len(phoneHosts) != 1 || phoneHosts[0].Alias != "Second host" {
		t.Fatalf("confirmed phone owner host visibility: hosts=%+v error=%v", phoneHosts, err)
	}
	if _, err := postgres.ConfirmEnrollmentHost(ctx, identity, installationThumbprint, enrollment.EnrollmentID, enrollmentCode); err != nil {
		t.Fatalf("idempotent host confirmation: %v", err)
	}
	if err := assertChangeCounts(ctx, testDB, 38, 8); err != nil {
		t.Fatal(err)
	}
	activeDeviceID, err := postgres.ActiveDevice(ctx, identity, deviceProofThumbprint)
	if err != nil || activeDeviceID != deviceID {
		t.Fatalf("active device lookup: id=%s error=%v", activeDeviceID, err)
	}
	if err := postgres.RevokeDevice(ctx, identity.Issuer, identity.Subject, deviceID); err != nil {
		t.Fatalf("revoke device: %v", err)
	}
	if _, err := postgres.ActiveDevice(ctx, identity, deviceProofThumbprint); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("revoked device remained active: %v", err)
	}
	if err := postgres.RevokeDevice(ctx, identity.Issuer, identity.Subject, deviceID); err != nil {
		t.Fatalf("idempotent device revoke: %v", err)
	}
	if err := assertChangeCounts(ctx, testDB, 39, 9); err != nil {
		t.Fatal(err)
	}
	pending, err := postgres.PendingControlEvents(ctx, 128)
	if err != nil || len(pending) == 0 {
		t.Fatalf("read transactional control events: count=%d error=%v", len(pending), err)
	}
	seenDevice, seenUpdate, seenRevoke := false, false, false
	for _, event := range pending {
		switch event.Topic {
		case "device.revoked":
			seenDevice = event.DeviceID == deviceID
		case "runtime_grant.updated":
			seenUpdate = true
		case "runtime_grant.revoked":
			seenRevoke = true
		default:
			t.Fatalf("unhandled topic was consumed: %s", event.Topic)
		}
		for range 2 {
			if err := postgres.MarkControlEventPublished(ctx, event.ID); err != nil {
				t.Fatalf("idempotent event acknowledgement: %v", err)
			}
		}
	}
	if !seenDevice || !seenUpdate || !seenRevoke {
		t.Fatalf("missing routing metadata: device=%t update=%t revoke=%t", seenDevice, seenUpdate, seenRevoke)
	}
	if remaining, err := postgres.PendingControlEvents(ctx, 128); err != nil || len(remaining) != 0 {
		t.Fatalf("acknowledged events replayed: count=%d error=%v", len(remaining), err)
	}
	var published, unrelatedPending int
	if err := testDB.QueryRowContext(ctx, `select count(*) filter (where published_at is not null), count(*) filter (where published_at is null) from control_outbox`).Scan(&published, &unrelatedPending); err != nil {
		t.Fatal(err)
	}
	if published != len(pending) || unrelatedPending != 9-len(pending) {
		t.Fatalf("publication affected unrelated topics: published=%d pending=%d", published, unrelatedPending)
	}
}

func assertConnectionLeases(t *testing.T, ctx context.Context, postgres *Postgres, leases []RealtimeConnectionLease, want ...string) {
	t.Helper()
	invalid, err := postgres.InvalidRealtimeConnectionLeases(ctx, leases)
	if err != nil || len(invalid) != len(want) {
		t.Fatalf("invalid connection leases=%v, want %v; error=%v", invalid, want, err)
	}
	for _, id := range want {
		found := false
		for _, actual := range invalid {
			if actual == id {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing invalid connection %s in %v", id, invalid)
		}
	}
}

func integrationHostCredentialProof(t *testing.T, key *ecdsa.PrivateKey, challenge HostCredentialChallenge) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"typ": "dsh-host-credential-proof+jwt", "alg": "ES256"})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := json.Marshal(map[string]any{
		"iss": challenge.InstallationID, "aud": auth.HostCredentialProofAudience,
		"challenge_id": challenge.ChallengeID, "nonce": challenge.Challenge,
		"iat": time.Now().UTC().Unix(), "jti": "host-proof-jti-integration-0001",
	})
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func seedGrantFixture(t *testing.T, ctx context.Context, database *sql.DB) string {
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
		phoneDeviceID  = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	)
	deviceProofKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deviceProofJWK, err := integrationP256JWK(deviceProofKey)
	if err != nil {
		t.Fatal(err)
	}
	deviceProofThumbprint, err := auth.PublicP256JWKThumbprintJSON(deviceProofJWK)
	if err != nil {
		t.Fatal(err)
	}
	statements := []struct {
		query string
		args  []any
	}{
		{`insert into orgs (id, slug, name) values ($1, 'test-org', 'Test org'), ($2, 'other-org', 'Other org')`, []any{orgID, otherOrgID}},
		{`insert into users (id, issuer, subject) values ($1, 'https://id.example.edu', 'owner-subject'), ($2, 'https://id.example.edu', 'target-subject'), ($3, 'https://id.example.edu', 'outsider-subject')`, []any{actorID, targetID, outsiderID}},
		{`insert into org_memberships (org_id, user_id, role) values ($1, $2, 'member'), ($1, $3, 'member'), ($4, $5, 'member')`, []any{orgID, actorID, targetID, otherOrgID, outsiderID}},
		{`insert into devices (id, user_id, name, approval_public_jwk, approval_key_thumbprint, proof_public_jwk, proof_key_thumbprint) values ($1, $2, 'owner phone', '{}'::jsonb, 'approval-jkt-actor', $5::jsonb, $6), ($3, $4, 'target phone', '{}'::jsonb, 'approval-jkt-target', '{}'::jsonb, 'proof-jkt-target')`, []any{deviceID, actorID, phoneDeviceID, targetID, deviceProofJWK, deviceProofThumbprint}},
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
	return deviceProofThumbprint
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
		return fmt.Errorf("audit/outbox counts=%d/%d, want %d/%d", actualAudits, actualOutbox, audits, outbox)
	}
	return nil
}

func integrationP256JWK(key *ecdsa.PrivateKey) ([]byte, error) {
	return json.Marshal(map[string]string{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(key.PublicKey.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.FillBytes(make([]byte, 32))),
	})
}
