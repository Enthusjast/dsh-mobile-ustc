package store

import (
	"errors"
	"testing"
	"time"
)

func TestHostCredentialDeadlinesCannotSurviveDatabaseWaits(t *testing.T) {
	for _, operation := range []string{"challenge-audit", "exchange-challenge-audit", "exchange-credential-audit", "exchange-consume", "exchange-challenge-lock"} {
		t.Run(operation, func(t *testing.T) {
			ctx, db, key, jkt := serializableCredentialFixture(t)
			actor := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
			var challenge HostCredentialChallenge
			var proof string
			if operation != "challenge-audit" {
				var err error
				challenge, err = db.CreateHostCredentialChallenge(ctx, actor, jkt)
				if err != nil {
					t.Fatal(err)
				}
				proof = integrationHostCredentialProof(t, key, challenge)
			}
			if _, err := db.DB.ExecContext(ctx, `create table host_deadline_fixture(expires_at timestamptz not null)`); err != nil {
				t.Fatal(err)
			}
			// Only fixture rows have short lifetimes; production TTLs and clocks
			// stay unchanged. A fixed database deadline is observable outside the
			// blocked transaction, including for not-yet-committed insertions.
			if operation == "challenge-audit" || operation == "exchange-credential-audit" {
				table := "installation_challenges"
				if operation == "exchange-credential-audit" {
					table = "host_connection_credentials"
				}
				if _, err := db.DB.ExecContext(ctx, `create function shorten_host_deadline() returns trigger language plpgsql as $$ begin
				 new.expires_at=(select expires_at from host_deadline_fixture);return new;end $$;
				 create trigger shorten_host_deadline before insert on `+table+` for each row execute function shorten_host_deadline()`); err != nil {
					t.Fatal(err)
				}
			}
			action := "host.credential.issue"
			if operation == "challenge-audit" {
				action = "host.credential.challenge"
			}
			if operation == "exchange-consume" {
				if _, err := db.DB.ExecContext(ctx, `create function hold_host_expiry() returns trigger language plpgsql as $$ begin
				 if old.consumed_at is null and new.consumed_at is not null then perform pg_advisory_xact_lock(426963);end if;return new;end $$;
				 create trigger hold_host_expiry before update on installation_challenges for each row execute function hold_host_expiry()`); err != nil {
					t.Fatal(err)
				}
			} else if operation != "exchange-challenge-lock" {
				if _, err := db.DB.ExecContext(ctx, `create function hold_host_expiry() returns trigger language plpgsql as $$ begin
				 if new.action='`+action+`' then perform pg_advisory_xact_lock(426963);end if;return new;end $$;
				 create trigger hold_host_expiry before insert on audit_log for each row execute function hold_host_expiry()`); err != nil {
					t.Fatal(err)
				}
			}
			var expires time.Time
			if err := db.DB.QueryRowContext(ctx, `insert into host_deadline_fixture values(clock_timestamp()+interval '1 second') returning expires_at`).Scan(&expires); err != nil {
				t.Fatal(err)
			}
			if operation != "challenge-audit" && operation != "exchange-credential-audit" {
				if _, err := db.DB.ExecContext(ctx, `update installation_challenges set expires_at=$1 where id=$2`, expires, challenge.ChallengeID); err != nil {
					t.Fatal(err)
				}
			}
			gate, err := db.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.Rollback()
			if operation == "exchange-challenge-lock" {
				_, err = gate.ExecContext(ctx, `select 1 from installation_challenges where id=$1 for update`, challenge.ChallengeID)
			} else {
				_, err = gate.ExecContext(ctx, `select pg_advisory_xact_lock(426963)`)
			}
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				if operation == "challenge-audit" {
					value, err := db.CreateHostCredentialChallenge(ctx, actor, jkt)
					if err != nil && value != (HostCredentialChallenge{}) {
						result <- errors.New("denied challenge exposed a secret")
						return
					}
					result <- err
				} else {
					value, err := db.ExchangeHostCredential(ctx, actor, jkt, challenge.ChallengeID, proof)
					if err != nil && value != (HostConnectionCredential{}) {
						result <- errors.New("denied exchange exposed a secret")
						return
					}
					result <- err
				}
			}()
			fragment := "insert into audit_log"
			if operation == "exchange-consume" {
				fragment = "update installation_challenges set consumed_at"
			} else if operation == "exchange-challenge-lock" {
				fragment = "select key_version, challenge_sha256"
			}
			waitForGrantLock(t, ctx, db, fragment)
			waitForGrantDatabaseExpiry(t, ctx, db, expires)
			if err := gate.Commit(); err != nil {
				t.Fatal(err)
			}
			if err := <-result; !errors.Is(err, ErrHostCredentialInvalid) {
				t.Fatal("expired Host admission survived a database wait", err)
			}
			var challenges, consumed, credentials, audits int
			if err := db.DB.QueryRowContext(ctx, `select
			 (select count(*) from installation_challenges),
			 (select count(*) from installation_challenges where consumed_at is not null),
			 (select count(*) from host_connection_credentials),
			 (select count(*) from audit_log where action=$1)`, action).Scan(&challenges, &consumed, &credentials, &audits); err != nil {
				t.Fatal(err)
			}
			wantChallenges := 1
			if operation == "challenge-audit" {
				wantChallenges = 0
			}
			if challenges != wantChallenges || consumed != 0 || credentials != 0 || audits != 0 {
				t.Fatal("denied Host admission left durable effects", challenges, consumed, credentials, audits)
			}
			if operation == "exchange-credential-audit" {
				// Only the aborted credential expired. The unspent, still-live
				// challenge can issue one fresh credential after the wait clears.
				if _, err := db.DB.ExecContext(ctx, `drop trigger shorten_host_deadline on host_connection_credentials`); err != nil {
					t.Fatal(err)
				}
				credential, err := db.ExchangeHostCredential(ctx, actor, jkt, challenge.ChallengeID, proof)
				if err != nil {
					t.Fatal("rolled-back exchange spent a live challenge", err)
				}
				if _, err := db.ValidateHostConnectionCredential(ctx, credential.Credential, jkt); err != nil {
					t.Fatal("fresh retry did not commit a usable credential", err)
				}
				if _, err := db.ExchangeHostCredential(ctx, actor, jkt, challenge.ChallengeID, proof); !errors.Is(err, ErrHostCredentialInvalid) {
					t.Fatal("successful retry did not consume exactly once", err)
				}
			}
		})
	}
}
