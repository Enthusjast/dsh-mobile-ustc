package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func proofStateFixture(t *testing.T, limit int) (context.Context, *sql.DB, *PostgresProofStore, string) {
	t.Helper()
	ctx, postgres := newPostgresIntegrationDatabase(t)
	scope, err := auth.ProofScope("https://issuer.example.edu", "urn:proof-fixture", "https://remote.example.edu")
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresProofStore(ctx, postgres.DB, scope, limit)
	if err != nil {
		t.Fatal(err)
	}
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
	return ctx, postgres.DB, repository, jkt
}

func proofStateSecondPool(t *testing.T, ctx context.Context, database *sql.DB) *sql.DB {
	t.Helper()
	config, err := pgx.ParseConfig(os.Getenv("REMOTE_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `select current_database()`).Scan(&config.Database); err != nil {
		t.Fatal(err)
	}
	config.RuntimeParams["default_transaction_isolation"] = "serializable"
	pool := stdlib.OpenDB(*config)
	pool.SetMaxOpenConns(4)
	t.Cleanup(func() { _ = pool.Close() })
	return pool
}

func proofStateCounts(t *testing.T, ctx context.Context, db *sql.DB, scope [32]byte, bucket int) (int, int) {
	t.Helper()
	var counted, actual int
	if err := db.QueryRowContext(ctx, `select entry_count,(select count(*) from dpop_proof_entries where scope_sha256=$1 and bucket=$2) from dpop_proof_buckets where scope_sha256=$1 and bucket=$2`, scope[:], bucket).Scan(&counted, &actual); err != nil {
		t.Fatal(err)
	}
	if counted != actual {
		t.Fatal("proof counter diverged from committed entries", counted, actual)
	}
	return counted, actual
}

func TestPostgresProofStateCrossPoolSingleUseAndRestartPersistence(t *testing.T) {
	ctx, db, first, jkt := proofStateFixture(t, 1024)
	secondPool := proofStateSecondPool(t, ctx, db)
	second, err := NewPostgresProofStore(ctx, secondPool, first.scope, 1024)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := first.Challenge(ctx, jkt)
	if err != nil {
		t.Fatal(err)
	}
	const jti = "PRIVATE_JTI_shared_single_use"
	var group sync.WaitGroup
	results := make(chan auth.ProofResult, 32)
	failures := make(chan error, 32)
	for index := range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			repository := first
			if index%2 != 0 {
				repository = second
			}
			result, err := repository.ConsumeAndRotate(ctx, jkt, jti, nonce, time.Now().Add(auth.ProofStateLifetime))
			if err != nil {
				failures <- err
			} else {
				results <- result
			}
		}()
	}
	group.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	accepted := 0
	var next string
	for result := range results {
		if result.Accepted {
			accepted++
			next = result.Nonce
		}
		if !auth.ValidProofThumbprint(result.Nonce) {
			t.Fatal("rotation omitted a fresh nonce")
		}
	}
	if accepted != 1 {
		t.Fatal("proof accepted more than once across independent pools", accepted)
	}
	restarted, err := NewPostgresProofStore(ctx, secondPool, first.scope, 1024)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := restarted.ConsumeAndRotate(ctx, jkt, jti, nonce, time.Now().Add(auth.ProofStateLifetime))
	if err != nil || replay.Accepted {
		t.Fatal("restart forgot a consumed proof", err)
	}
	replay, err = first.ConsumeAndRotate(ctx, jkt, jti, next, time.Now().Add(auth.ProofStateLifetime))
	if err != nil || replay.Accepted {
		t.Fatal("same jti accepted with another nonce", err)
	}
	fresh, err := second.ConsumeAndRotate(ctx, jkt, "fresh-proof-after-replay-0001", next, time.Now().Add(auth.ProofStateLifetime))
	if err != nil || !fresh.Accepted {
		t.Fatal("replay rejection consumed the unrelated fresh nonce", err)
	}
	count, _ := proofStateCounts(t, ctx, db, first.scope, proofBucket(jkt))
	if count != 36 {
		t.Fatal("unexpected replay accounting", count)
	}
	rows, err := db.QueryContext(ctx, `select row_to_json(entry)::text from dpop_proof_entries entry where scope_sha256=$1`, first.scope[:])
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var row string
		if err := rows.Scan(&row); err != nil {
			t.Fatal(err)
		}
		for _, private := range []string{jkt, jti, nonce, next} {
			if strings.Contains(row, private) {
				t.Fatal("proof table retained raw material")
			}
		}
	}
}

func TestPostgresProofStateScopeQuotaAndAtomicRotationFailure(t *testing.T) {
	ctx, db, repository, jkt := proofStateFixture(t, 64)
	otherScope, _ := auth.ProofScope("https://issuer.example.edu", "urn:proof-fixture", "https://other.example.edu")
	other, err := NewPostgresProofStore(ctx, db, otherScope, 64)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := repository.Challenge(ctx, jkt)
	if err != nil {
		t.Fatal(err)
	}
	const jti = "PRIVATE_JTI_atomic_rotation"
	if wrong, err := other.ConsumeAndRotate(ctx, jkt, jti, nonce, time.Now().Add(auth.ProofStateLifetime)); err != nil || wrong.Accepted {
		t.Fatal("nonce crossed resource scopes", err)
	}
	for _, query := range []string{`create function fail_next_proof_nonce() returns trigger language plpgsql as $$ begin if new.kind=0 then raise exception 'fixture nonce insert unavailable';end if;return new;end $$`,
		`create trigger proof_nonce_failure before insert on dpop_proof_entries for each row execute function fail_next_proof_nonce()`} {
		if _, err := db.ExecContext(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	if result, err := repository.ConsumeAndRotate(ctx, jkt, jti, nonce, time.Now().Add(auth.ProofStateLifetime)); !errors.Is(err, auth.ErrProofStateUnavailable) || result.Accepted || result.Nonce != "" {
		t.Fatal("failed rotation exposed an accepted state", result.Accepted, err)
	}
	count, _ := proofStateCounts(t, ctx, db, repository.scope, proofBucket(jkt))
	if count != 1 {
		t.Fatal("failed rotation spent nonce or retained a jti", count)
	}
	if _, err := db.ExecContext(ctx, `drop trigger proof_nonce_failure on dpop_proof_entries`); err != nil {
		t.Fatal(err)
	}
	result, err := repository.ConsumeAndRotate(ctx, jkt, jti, nonce, time.Now().Add(auth.ProofStateLifetime))
	if err != nil || !result.Accepted {
		t.Fatal("original proof did not survive full rollback", err)
	}
	if _, err := NewPostgresProofStore(ctx, db, repository.scope, 65); err == nil {
		t.Fatal("inconsistent node capacity accepted")
	}
	for index := 2; index < 64; index++ {
		if _, err := repository.Challenge(ctx, jkt); err != nil {
			t.Fatal(err)
		}
	}
	if next, err := repository.ConsumeAndRotate(ctx, jkt, "PRIVATE_JTI_at_full_capacity", result.Nonce, time.Now().Add(auth.ProofStateLifetime)); err == nil || next.Accepted {
		t.Fatal("full bucket allowed partial consumption")
	}
	count, _ = proofStateCounts(t, ctx, db, repository.scope, proofBucket(jkt))
	if count != 64 {
		t.Fatal("quota escaped", count)
	}
	if _, err := db.ExecContext(ctx, `update dpop_proof_entries set expires_at=clock_timestamp()-interval '1 second' where scope_sha256=$1 and bucket=$2 and kind=1`, repository.scope[:], proofBucket(jkt)); err != nil {
		t.Fatal(err)
	}
	if next, err := other.Challenge(ctx, jkt); err != nil || next == "" {
		t.Fatal("one resource exhausted another resource's capacity", err)
	}
	if next, err := repository.ConsumeAndRotate(ctx, jkt, "PRIVATE_JTI_after_reclaim", result.Nonce, time.Now().Add(auth.ProofStateLifetime)); err != nil || !next.Accepted {
		t.Fatal("expiry did not reclaim capacity atomically", err)
	}
	proofStateCounts(t, ctx, db, repository.scope, proofBucket(jkt))
}

func TestPostgresProofStateExpiryBoundedCleanupAndCancellation(t *testing.T) {
	ctx, db, repository, jkt := proofStateFixture(t, 1024)
	bucket := proofBucket(jkt)
	if _, err := db.ExecContext(ctx, `insert into dpop_proof_entries(scope_sha256,bucket,kind,entry_sha256,expires_at)
        select $1,$2,1,digest(n::text,'sha256'),case when n<=800 then clock_timestamp()-interval '1 second' else clock_timestamp()+interval '5 minutes' end from generate_series(1,810) n`, repository.scope[:], bucket); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `update dpop_proof_buckets set entry_count=810 where scope_sha256=$1 and bucket=$2`, repository.scope[:], bucket); err != nil {
		t.Fatal(err)
	}
	if err := repository.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	count, _ := proofStateCounts(t, ctx, db, repository.scope, bucket)
	if count != 298 {
		t.Fatal("cleanup exceeded its bounded batch", count)
	}
	if err := repository.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	count, _ = proofStateCounts(t, ctx, db, repository.scope, bucket)
	if count != 10 {
		t.Fatal("cleanup lost active replay tombstones", count)
	}
	nonce, err := repository.Challenge(ctx, jkt)
	if err != nil {
		t.Fatal(err)
	}
	digest := proofEntryDigest(0, jkt, nonce)
	if _, err := db.ExecContext(ctx, `update dpop_proof_entries set expires_at=clock_timestamp()-interval '1 second' where scope_sha256=$1 and bucket=$2 and kind=0 and entry_sha256=$3`, repository.scope[:], bucket, digest[:]); err != nil {
		t.Fatal(err)
	}
	if expired, err := repository.ConsumeAndRotate(ctx, jkt, "PRIVATE_JTI_expired_nonce", nonce, time.Now().Add(auth.ProofStateLifetime)); err != nil || expired.Accepted {
		t.Fatal("expired nonce accepted", err)
	}
	before, _ := proofStateCounts(t, ctx, db, repository.scope, bucket)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := repository.Challenge(cancelled, jkt); err == nil {
		t.Fatal("cancelled proof request modified state")
	}
	after, _ := proofStateCounts(t, ctx, db, repository.scope, bucket)
	if after != before {
		t.Fatal("cancellation changed state")
	}
}
