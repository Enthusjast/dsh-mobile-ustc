package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"log"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
)

const DefaultProofEntriesPerBucket = 8192
const proofCleanupBatch = 512

type PostgresProofStore struct {
	database *sql.DB
	scope    [32]byte
	limit    int
}

func NewPostgresProofStore(ctx context.Context, database *sql.DB, scope [32]byte, entriesPerBucket int) (*PostgresProofStore, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if database == nil || scope == [32]byte{} || entriesPerBucket < 64 || entriesPerBucket > 65536 {
		return nil, auth.ErrProofStateUnavailable
	}
	transaction, err := database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, auth.ErrProofStateUnavailable
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, `insert into dpop_proof_resources(scope_sha256,entries_per_bucket) values($1,$2) on conflict do nothing`, scope[:], entriesPerBucket); err != nil {
		return nil, auth.ErrProofStateUnavailable
	}
	var configured int
	if err := transaction.QueryRowContext(ctx, `select entries_per_bucket from dpop_proof_resources where scope_sha256=$1`, scope[:]).Scan(&configured); err != nil || configured != entriesPerBucket {
		return nil, auth.ErrProofStateUnavailable
	}
	if _, err := transaction.ExecContext(ctx, `insert into dpop_proof_buckets(scope_sha256,bucket) select $1,n from generate_series(0,255) as n on conflict do nothing`, scope[:]); err != nil {
		return nil, auth.ErrProofStateUnavailable
	}
	if err := transaction.Commit(); err != nil {
		return nil, auth.ErrProofStateUnavailable
	}
	return &PostgresProofStore{database, scope, entriesPerBucket}, nil
}

func (store *PostgresProofStore) Scope() [32]byte { return store.scope }

func proofBucket(jkt string) int { digest := sha256.Sum256([]byte(jkt)); return int(digest[0]) }

func proofEntryDigest(kind byte, jkt, value string) [32]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("dsh-mobile-ustc/dpop-entry/v1\x00"))
	_, _ = hash.Write([]byte{kind})
	for _, part := range []string{jkt, value} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(part))
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func (store *PostgresProofStore) lockBucket(ctx context.Context, transaction *sql.Tx, bucket int) (int, time.Time, error) {
	var count int
	var now time.Time
	err := transaction.QueryRowContext(ctx, `select entry_count from dpop_proof_buckets where scope_sha256=$1 and bucket=$2 for update`, store.scope[:], bucket).Scan(&count)
	if err != nil {
		return 0, time.Time{}, auth.ErrProofStateUnavailable
	}
	if err := transaction.QueryRowContext(ctx, `select clock_timestamp()`).Scan(&now); err != nil {
		return 0, time.Time{}, auth.ErrProofStateUnavailable
	}
	deleted, err := transaction.ExecContext(ctx, `delete from dpop_proof_entries where scope_sha256=$1 and bucket=$2 and ctid in
        (select ctid from dpop_proof_entries where scope_sha256=$1 and bucket=$2 and expires_at<=$3 order by expires_at limit $4)`, store.scope[:], bucket, now, proofCleanupBatch)
	if err != nil {
		return 0, time.Time{}, auth.ErrProofStateUnavailable
	}
	removed, err := deleted.RowsAffected()
	if err != nil || removed > int64(count) {
		return 0, time.Time{}, auth.ErrProofStateUnavailable
	}
	return count - int(removed), now, nil
}

func (store *PostgresProofStore) publishCount(ctx context.Context, transaction *sql.Tx, bucket, count int, now time.Time) error {
	if count < 0 || count > store.limit {
		return auth.ErrProofStateUnavailable
	}
	result, err := transaction.ExecContext(ctx, `update dpop_proof_buckets set entry_count=$3,last_cleanup_at=$4 where scope_sha256=$1 and bucket=$2`, store.scope[:], bucket, count, now)
	if err != nil {
		return auth.ErrProofStateUnavailable
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return auth.ErrProofStateUnavailable
	}
	return nil
}

func (store *PostgresProofStore) evaluate(ctx context.Context, jkt, jti, nonce string, expires time.Time, challengeOnly bool) (auth.ProofResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if !auth.ValidProofThumbprint(jkt) || ctx.Err() != nil || (!challengeOnly && (len(jti) < 16 || len(jti) > 256 || len(nonce) > 256)) {
		return auth.ProofResult{}, auth.ErrProofStateUnavailable
	}
	next, err := auth.NewProofNonce()
	if err != nil {
		return auth.ProofResult{}, err
	}
	bucket := proofBucket(jkt)
	nonceDigest, jtiDigest, nextDigest := proofEntryDigest(0, jkt, nonce), proofEntryDigest(1, jkt, jti), proofEntryDigest(0, jkt, next)
	transaction, err := store.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return auth.ProofResult{}, auth.ErrProofStateUnavailable
	}
	defer transaction.Rollback()
	count, now, err := store.lockBucket(ctx, transaction, bucket)
	if err != nil {
		return auth.ProofResult{}, err
	}
	accepted := false
	if !challengeOnly {
		if expires.After(now.Add(10 * time.Minute)) {
			return auth.ProofResult{}, auth.ErrProofStateUnavailable
		}
		// Expired exact keys may lie beyond this operation's bounded sweep.
		removed, err := transaction.ExecContext(ctx, `delete from dpop_proof_entries where scope_sha256=$1 and bucket=$2 and expires_at<=$3 and
            ((kind=0 and entry_sha256=$4) or (kind=1 and entry_sha256=$5))`, store.scope[:], bucket, now, nonceDigest[:], jtiDigest[:])
		if err != nil {
			return auth.ProofResult{}, auth.ErrProofStateUnavailable
		}
		deleted, err := removed.RowsAffected()
		if err != nil || deleted > int64(count) {
			return auth.ProofResult{}, auth.ErrProofStateUnavailable
		}
		count -= int(deleted)
		var validNonce, replayed bool
		if err := transaction.QueryRowContext(ctx, `select exists(select 1 from dpop_proof_entries where scope_sha256=$1 and bucket=$2 and kind=0 and entry_sha256=$3 and expires_at>$5),
            exists(select 1 from dpop_proof_entries where scope_sha256=$1 and bucket=$2 and kind=1 and entry_sha256=$4 and expires_at>$5)`, store.scope[:], bucket, nonceDigest[:], jtiDigest[:], now).Scan(&validNonce, &replayed); err != nil {
			return auth.ProofResult{}, auth.ErrProofStateUnavailable
		}
		accepted = validNonce && !replayed && expires.After(now)
	}
	// Both accepted rotation and a fresh challenge reserve one net new entry.
	if count >= store.limit {
		return auth.ProofResult{}, auth.ErrProofStateUnavailable
	}
	if accepted {
		deleted, err := transaction.ExecContext(ctx, `delete from dpop_proof_entries where scope_sha256=$1 and bucket=$2 and kind=0 and entry_sha256=$3`, store.scope[:], bucket, nonceDigest[:])
		if err != nil {
			return auth.ProofResult{}, auth.ErrProofStateUnavailable
		}
		rows, err := deleted.RowsAffected()
		if err != nil || rows != 1 {
			return auth.ProofResult{}, auth.ErrProofStateUnavailable
		}
		if _, err := transaction.ExecContext(ctx, `insert into dpop_proof_entries(scope_sha256,bucket,kind,entry_sha256,expires_at) values($1,$2,1,$3,$4)`, store.scope[:], bucket, jtiDigest[:], now.Add(auth.ProofStateLifetime)); err != nil {
			return auth.ProofResult{}, auth.ErrProofStateUnavailable
		}
	}
	if _, err := transaction.ExecContext(ctx, `insert into dpop_proof_entries(scope_sha256,bucket,kind,entry_sha256,expires_at) values($1,$2,0,$3,$4)`, store.scope[:], bucket, nextDigest[:], now.Add(auth.ProofStateLifetime)); err != nil {
		return auth.ProofResult{}, auth.ErrProofStateUnavailable
	}
	if err := store.publishCount(ctx, transaction, bucket, count+1, now); err != nil {
		return auth.ProofResult{}, err
	}
	if err := transaction.Commit(); err != nil {
		return auth.ProofResult{}, auth.ErrProofStateUnavailable
	}
	return auth.ProofResult{Accepted: accepted, Nonce: next}, nil
}

func (store *PostgresProofStore) Challenge(ctx context.Context, jkt string) (string, error) {
	result, err := store.evaluate(ctx, jkt, "", "", time.Time{}, true)
	return result.Nonce, err
}

func (store *PostgresProofStore) ConsumeAndRotate(ctx context.Context, jkt, jti, nonce string, expires time.Time) (auth.ProofResult, error) {
	return store.evaluate(ctx, jkt, jti, nonce, expires, false)
}

// Cleanup touches a bounded set of this resource's least recently swept buckets.
func (store *PostgresProofStore) Cleanup(ctx context.Context) error {
	rows, err := store.database.QueryContext(ctx, `select bucket from dpop_proof_buckets b where scope_sha256=$1 and entry_count>0
        and exists(select 1 from dpop_proof_entries e where e.scope_sha256=b.scope_sha256 and e.bucket=b.bucket and e.expires_at<=clock_timestamp())
        order by last_cleanup_at,bucket limit 16`, store.scope[:])
	if err != nil {
		return auth.ErrProofStateUnavailable
	}
	var buckets []int
	for rows.Next() {
		var bucket int
		if err := rows.Scan(&bucket); err != nil {
			_ = rows.Close()
			return auth.ErrProofStateUnavailable
		}
		buckets = append(buckets, bucket)
	}
	readErr := rows.Err()
	closeErr := rows.Close()
	if readErr != nil || closeErr != nil {
		return auth.ErrProofStateUnavailable
	}
	for _, bucket := range buckets {
		if err := store.cleanupBucket(ctx, bucket); err != nil {
			return err
		}
	}
	return nil
}

func (store *PostgresProofStore) cleanupBucket(ctx context.Context, bucket int) error {
	transaction, err := store.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return auth.ErrProofStateUnavailable
	}
	defer transaction.Rollback()
	count, now, err := store.lockBucket(ctx, transaction, bucket)
	if err != nil {
		return err
	}
	if err := store.publishCount(ctx, transaction, bucket, count, now); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return auth.ErrProofStateUnavailable
	}
	return nil
}

func (store *PostgresProofStore) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	unavailable := false
	for ctx.Err() == nil {
		attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := store.Cleanup(attempt)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if (err != nil) != unavailable {
			unavailable = err != nil
			log.Printf("remote proof cleanup unavailable=%t", unavailable)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

var _ auth.ProofRepository = (*PostgresProofStore)(nil)
