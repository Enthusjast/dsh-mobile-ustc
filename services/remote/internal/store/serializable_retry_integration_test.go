package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/auth"
)

func serializableCredentialFixture(t *testing.T) (context.Context, *Postgres, *ecdsa.PrivateKey, string) {
	t.Helper()
	ctx, postgres := newPostgresIntegrationDatabase(t)
	seedGrantFixture(t, ctx, postgres.DB)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := integrationP256JWK(key)
	if err != nil {
		t.Fatal(err)
	}
	jkt, err := auth.PublicP256JWKThumbprintJSON(public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.DB.ExecContext(ctx, `update installations set public_jwk=$1::jsonb,public_key_thumbprint=$2`, string(public), jkt); err != nil {
		t.Fatal(err)
	}
	return ctx, postgres, key, jkt
}

func serializableAbortTrigger(t *testing.T, ctx context.Context, postgres *Postgres, table string, failures int) {
	t.Helper()
	if table != "installation_challenges" && table != "host_connection_credentials" {
		t.Fatal("invalid private trigger target")
	}
	for _, query := range []string{
		`create sequence admission_retry_attempt`,
		fmt.Sprintf(`create function admission_retry_abort() returns trigger language plpgsql as $$ begin if nextval('admission_retry_attempt')<=%d then raise exception 'fixture serialization abort' using errcode='40001';end if;return new;end $$`, failures),
		`create trigger admission_retry_fixture before insert on ` + table + ` for each row execute function admission_retry_abort()`,
	} {
		if _, err := postgres.DB.ExecContext(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSerializableChallengeAbortRestartsAndPublishesOnlyOneResult(t *testing.T) {
	ctx, postgres, _, jkt := serializableCredentialFixture(t)
	serializableAbortTrigger(t, ctx, postgres, "installation_challenges", 2)
	challenge, err := postgres.CreateHostCredentialChallenge(ctx, UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}, jkt)
	if err != nil {
		t.Fatal(err)
	}
	var attempts, rows, audits int
	if err := postgres.DB.QueryRowContext(ctx, `select (select last_value from admission_retry_attempt),(select count(*) from installation_challenges),(select count(*) from audit_log where action='host.credential.challenge')`).Scan(&attempts, &rows, &audits); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 || rows != 1 || audits != 1 {
		t.Fatal("aborted challenge attempts escaped their rollback", attempts, rows, audits)
	}
	var digest []byte
	if err := postgres.DB.QueryRowContext(ctx, `select challenge_sha256 from installation_challenges where id=$1`, challenge.ChallengeID).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(challenge.Challenge))
	if string(digest) != string(want[:]) {
		t.Fatal("returned challenge belongs to an aborted attempt")
	}
}

func TestSerializableCredentialAbortPreservesSingleConsumptionAndAudit(t *testing.T) {
	ctx, postgres, key, jkt := serializableCredentialFixture(t)
	identity := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	challenge, err := postgres.CreateHostCredentialChallenge(ctx, identity, jkt)
	if err != nil {
		t.Fatal(err)
	}
	serializableAbortTrigger(t, ctx, postgres, "host_connection_credentials", 2)
	proof := integrationHostCredentialProof(t, key, challenge)
	credential, err := postgres.ExchangeHostCredential(ctx, identity, jkt, challenge.ChallengeID, proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.ValidateHostConnectionCredential(ctx, credential.Credential, jkt); err != nil {
		t.Fatal("returned an uncommitted credential", err)
	}
	var attempts, rows, consumed, audits int
	if err := postgres.DB.QueryRowContext(ctx, `select (select last_value from admission_retry_attempt),(select count(*) from host_connection_credentials),(select count(*) from installation_challenges where consumed_at is not null),(select count(*) from audit_log where action='host.credential.issue')`).Scan(&attempts, &rows, &consumed, &audits); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 || rows != 1 || consumed != 1 || audits != 1 {
		t.Fatal("credential retry duplicated admission or spent the challenge early", attempts, rows, consumed, audits)
	}
	if _, err := postgres.ExchangeHostCredential(ctx, identity, jkt, challenge.ChallengeID, proof); !errors.Is(err, ErrHostCredentialInvalid) {
		t.Fatal("consumed challenge became reusable", err)
	}
}

func TestSerializableRetryRechecksIdentityAfterAnAbortedAttempt(t *testing.T) {
	ctx, postgres, _, jkt := serializableCredentialFixture(t)
	serializableAbortTrigger(t, ctx, postgres, "installation_challenges", 1)
	identity := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	attempts := 0
	_, err := retrySerializable(ctx, func() (HostCredentialChallenge, error) {
		attempts++
		result, err := postgres.createHostCredentialChallengeOnce(ctx, identity, jkt)
		if attempts == 1 {
			if err == nil {
				t.Fatal("fixture did not abort")
			}
			if _, changeErr := postgres.DB.ExecContext(ctx, `update users set status='suspended' where subject='owner-subject'`); changeErr != nil {
				t.Fatal(changeErr)
			}
		}
		return result, err
	})
	if attempts != 2 || !errors.Is(err, ErrIdentityNotProvisioned) {
		t.Fatal("retry reused authority from the aborted transaction", attempts, err)
	}
	var count int
	if err := postgres.DB.QueryRowContext(ctx, `select count(*) from installation_challenges`).Scan(&count); err != nil || count != 0 {
		t.Fatal("denied retry left a challenge", count, err)
	}
}

func TestSerializableAdmissionLateAuditAbortRollsBackTheWholeMutation(t *testing.T) {
	for _, action := range []string{"host.runtime.connect", "session.catalog.sync", "realtime.ticket.issue", "realtime.ticket.consume"} {
		t.Run(action, func(t *testing.T) {
			ctx, postgres, _, _ := serializableCredentialFixture(t)
			identity := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
			input := RuntimeConnectionInput{InstallationID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", KeyVersion: 1, RuntimeID: "55555555-5555-4555-8555-555555555555", RuntimeEpoch: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", ConnectionID: "ffffffff-ffff-4fff-8fff-ffffffffffff", DSHVersion: "0.2.1-rc.2", ApplicationVersion: "fixture", PluginVersion: "fixture", ProtocolVersion: 1}
			var connection RuntimeConnection
			var ticket RealtimeTicket
			var err error
			if action == "session.catalog.sync" {
				connection, err = postgres.AttachRuntimeConnection(ctx, input)
				if err != nil {
					t.Fatal(err)
				}
			}
			scope := GrantScope{Actions: []string{"host.list"}, Workspaces: []string{"77777777-7777-4777-8777-777777777777"}, Sessions: []string{}}
			if action == "realtime.ticket.consume" {
				ticket, err = postgres.IssueRealtimeTicket(ctx, identity, "44444444-4444-4444-8444-444444444444", input.RuntimeID, scope)
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, query := range []string{
				`create sequence late_admission_attempt`,
				fmt.Sprintf(`create function late_admission_abort() returns trigger language plpgsql as $$ begin if new.action='%s' and nextval('late_admission_attempt')<=2 then raise exception 'fixture late audit serialization abort' using errcode='40001';end if;return new;end $$`, action),
				`create trigger late_admission_fixture before insert on audit_log for each row execute function late_admission_abort()`,
			} {
				if _, err := postgres.DB.ExecContext(ctx, query); err != nil {
					t.Fatal(err)
				}
			}
			switch action {
			case "host.runtime.connect":
				connection, err = postgres.AttachRuntimeConnection(ctx, input)
				if err != nil || connection.ConnectionID != input.ConnectionID {
					t.Fatal("runtime attach did not recover", err)
				}
			case "session.catalog.sync":
				id, _ := MobileSessionID(input.RuntimeID, "retry-catalog")
				workspace := scope.Workspaces[0]
				if err := postgres.SyncRealtimeSessionCatalog(ctx, connection, 1, true, []SessionCatalogItem{{SessionID: id, DSHSessionID: "retry-catalog", WorkspaceID: &workspace, State: "running", LastPersistedSeq: 7}}); err != nil {
					t.Fatal(err)
				}
				var count int
				if err := postgres.DB.QueryRowContext(ctx, `select count(*) from sessions where id=$1 and state='running' and last_persisted_seq=7`, id).Scan(&count); err != nil || count != 1 {
					t.Fatal("catalog replay did not commit exact metadata", count, err)
				}
			case "realtime.ticket.issue":
				ticket, err = postgres.IssueRealtimeTicket(ctx, identity, "44444444-4444-4444-8444-444444444444", input.RuntimeID, scope)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := postgres.PrepareRealtimeTicket(ctx, ticket.Token); err != nil {
					t.Fatal("returned an aborted ticket", err)
				}
			case "realtime.ticket.consume":
				if _, err := postgres.ConsumeRealtimeTicket(ctx, ticket.Token); err != nil {
					t.Fatal(err)
				}
				if _, err := postgres.ConsumeRealtimeTicket(ctx, ticket.Token); !errors.Is(err, ErrTicketInvalid) {
					t.Fatal("consumed ticket became reusable", err)
				}
			}
			var attempts, audits int
			if err := postgres.DB.QueryRowContext(ctx, `select (select last_value from late_admission_attempt),(select count(*) from audit_log where action=$1)`, action).Scan(&attempts, &audits); err != nil {
				t.Fatal(err)
			}
			if attempts != 3 || audits != 1 {
				t.Fatal("late audit rollback leaked an extra outcome", attempts, audits)
			}
		})
	}
}
