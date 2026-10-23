package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
)

var ErrHostCredentialInvalid = errors.New("store: host credential is invalid")
var ErrHostChallengeLimit = errors.New("store: too many pending host challenges")
var ErrHostCredentialLimit = errors.New("store: too many active host credentials")

type HostCredentialChallenge struct {
	ChallengeID    string    `json:"challenge_id"`
	Challenge      string    `json:"challenge"`
	InstallationID string    `json:"installation_id"`
	Audience       string    `json:"audience"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type HostConnectionCredential struct {
	Credential     string    `json:"credential"`
	TokenType      string    `json:"token_type"`
	InstallationID string    `json:"installation_id"`
	KeyThumbprint  string    `json:"key_thumbprint"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type HostCredentialIdentity struct {
	InstallationID string
	KeyThumbprint  string
	KeyVersion     int64
	ExpiresAt      time.Time
}

// CreateHostCredentialChallenge returns a random challenge only to the active
// owner of the installation whose DPoP key is registered as its host key.
func (postgres *Postgres) CreateHostCredentialChallenge(ctx context.Context, identity UserIdentity, proofKeyJKT string) (HostCredentialChallenge, error) {
	if !keyThumbprintPattern.MatchString(proofKeyJKT) {
		return HostCredentialChallenge{}, ErrAccessDenied
	}
	transaction, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return HostCredentialChallenge{}, ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	userID, err := postgres.userID(ctx, transaction, identity.Issuer, identity.Subject)
	if err != nil {
		return HostCredentialChallenge{}, err
	}
	var installationID, orgID string
	var keyVersion int64
	err = transaction.QueryRowContext(ctx, `
		select i.id::text, h.org_id::text, i.key_version
		from installations i
		join hosts h on h.id = i.host_id and h.state = 'active'
		where i.owner_user_id = $1 and i.public_key_thumbprint = $2 and i.revoked_at is null
		for update of i, h`, userID, proofKeyJKT).Scan(&installationID, &orgID, &keyVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return HostCredentialChallenge{}, ErrAccessDenied
	}
	if err != nil {
		return HostCredentialChallenge{}, ErrDatabaseUnavailable
	}
	if _, err := transaction.ExecContext(ctx, `
		delete from installation_challenges
		where installation_id = $1 and created_at <= clock_timestamp() - interval '5 minutes'`, installationID); err != nil {
		return HostCredentialChallenge{}, ErrDatabaseUnavailable
	}
	if _, err := transaction.ExecContext(ctx, `
		delete from host_connection_credentials
		where installation_id = $1 and (revoked_at is not null or expires_at <= clock_timestamp() or key_version <> $2)`, installationID, keyVersion); err != nil {
		return HostCredentialChallenge{}, ErrDatabaseUnavailable
	}
	var pending int
	if err := transaction.QueryRowContext(ctx, `
		select count(*) from installation_challenges
		where installation_id = $1 and consumed_at is null and expires_at > clock_timestamp()`, installationID).Scan(&pending); err != nil {
		return HostCredentialChallenge{}, ErrDatabaseUnavailable
	}
	if pending >= 4 {
		return HostCredentialChallenge{}, ErrHostChallengeLimit
	}
	var recent int
	if err := transaction.QueryRowContext(ctx, `
		select count(*) from installation_challenges
		where installation_id = $1 and created_at > clock_timestamp() - interval '5 minutes'`, installationID).Scan(&recent); err != nil {
		return HostCredentialChallenge{}, ErrDatabaseUnavailable
	}
	if recent >= 20 {
		return HostCredentialChallenge{}, ErrHostChallengeLimit
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return HostCredentialChallenge{}, ErrDatabaseUnavailable
	}
	challenge := base64.RawURLEncoding.EncodeToString(secret)
	for index := range secret {
		secret[index] = 0
	}
	digest := sha256.Sum256([]byte(challenge))
	var result HostCredentialChallenge
	result.Challenge = challenge
	result.InstallationID = installationID
	result.Audience = auth.HostCredentialProofAudience
	err = transaction.QueryRowContext(ctx, `
		insert into installation_challenges (installation_id, key_version, challenge_sha256, expires_at)
		values ($1, $2, $3, clock_timestamp() + interval '90 seconds')
		returning id::text, expires_at`, installationID, keyVersion, digest[:]).Scan(&result.ChallengeID, &result.ExpiresAt)
	if err != nil {
		return HostCredentialChallenge{}, ErrDatabaseUnavailable
	}
	metadata, _ := json.Marshal(map[string]any{"installation_id": installationID, "challenge_id": result.ChallengeID})
	if _, err := transaction.ExecContext(ctx, `
		insert into audit_log (org_id, actor_type, actor_id, action, result, metadata)
		values ($1, 'installation', $2, 'host.credential.challenge', 'success', $3::jsonb)`, orgID, installationID, string(metadata)); err != nil {
		return HostCredentialChallenge{}, ErrDatabaseUnavailable
	}
	if err := transaction.Commit(); err != nil {
		return HostCredentialChallenge{}, ErrDatabaseUnavailable
	}
	return result, nil
}

// ExchangeHostCredential consumes one challenge and stores only the digest of
// a five-minute installation credential.
func (postgres *Postgres) ExchangeHostCredential(ctx context.Context, identity UserIdentity, proofKeyJKT, challengeID, proof string) (HostConnectionCredential, error) {
	if !keyThumbprintPattern.MatchString(proofKeyJKT) || !grantUUIDPattern.MatchString(challengeID) || len(proof) == 0 || len(proof) > 8<<10 {
		return HostConnectionCredential{}, ErrHostCredentialInvalid
	}
	transaction, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return HostConnectionCredential{}, ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	userID, err := postgres.userID(ctx, transaction, identity.Issuer, identity.Subject)
	if err != nil {
		if errors.Is(err, ErrIdentityNotProvisioned) {
			return HostConnectionCredential{}, ErrHostCredentialInvalid
		}
		return HostConnectionCredential{}, err
	}
	var challengeInstallationID string
	err = transaction.QueryRowContext(ctx, `
		select installation_id::text from installation_challenges where id = $1`, challengeID).Scan(&challengeInstallationID)
	if errors.Is(err, sql.ErrNoRows) {
		return HostConnectionCredential{}, ErrHostCredentialInvalid
	}
	if err != nil {
		return HostConnectionCredential{}, ErrDatabaseUnavailable
	}
	var installationID, orgID, publicKeyThumbprint string
	var publicJWK []byte
	var keyVersion int64
	err = transaction.QueryRowContext(ctx, `
		select i.id::text, h.org_id::text, i.public_jwk, i.public_key_thumbprint, i.key_version
		from installations i
		join hosts h on h.id = i.host_id and h.state = 'active'
		join users u on u.id = i.owner_user_id and u.status = 'active'
		where i.id = $1 and i.public_key_thumbprint = $2 and u.id = $3 and i.revoked_at is null
		for update of i, h`, challengeInstallationID, proofKeyJKT, userID).Scan(
		&installationID, &orgID, &publicJWK, &publicKeyThumbprint, &keyVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return HostConnectionCredential{}, ErrHostCredentialInvalid
	}
	if err != nil {
		return HostConnectionCredential{}, ErrDatabaseUnavailable
	}
	var challengeDigest []byte
	var challengeKeyVersion int64
	var expiresAt time.Time
	var consumedAt sql.NullTime
	var challengeActive bool
	err = transaction.QueryRowContext(ctx, `
		select key_version, challenge_sha256, expires_at, consumed_at, expires_at > clock_timestamp()
		from installation_challenges
		where id = $1 and installation_id = $2
		for update`, challengeID, installationID).Scan(
		&challengeKeyVersion,
		&challengeDigest, &expiresAt, &consumedAt, &challengeActive)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (consumedAt.Valid || !challengeActive) {
		return HostConnectionCredential{}, ErrHostCredentialInvalid
	}
	if err != nil {
		return HostConnectionCredential{}, ErrDatabaseUnavailable
	}
	if challengeKeyVersion != keyVersion {
		return HostConnectionCredential{}, ErrHostCredentialInvalid
	}
	if err := auth.VerifyHostCredentialProof(proof, publicJWK, installationID, challengeID, publicKeyThumbprint, challengeDigest); err != nil {
		return HostConnectionCredential{}, ErrHostCredentialInvalid
	}
	var activeCredentials int
	if err := transaction.QueryRowContext(ctx, `
		select count(*) from host_connection_credentials
		where installation_id = $1 and key_version = $2 and revoked_at is null and expires_at > clock_timestamp()`, installationID, keyVersion).Scan(&activeCredentials); err != nil {
		return HostConnectionCredential{}, ErrDatabaseUnavailable
	}
	if activeCredentials >= 8 {
		return HostConnectionCredential{}, ErrHostCredentialLimit
	}
	credentialSecret := make([]byte, 32)
	if _, err := rand.Read(credentialSecret); err != nil {
		return HostConnectionCredential{}, ErrDatabaseUnavailable
	}
	credential := base64.RawURLEncoding.EncodeToString(credentialSecret)
	for index := range credentialSecret {
		credentialSecret[index] = 0
	}
	credentialDigest := sha256.Sum256([]byte(credential))
	if err := transaction.QueryRowContext(ctx, `
		update installation_challenges set consumed_at = clock_timestamp()
		where id = $1 and consumed_at is null and expires_at > clock_timestamp()
		returning consumed_at`, challengeID).Scan(new(time.Time)); errors.Is(err, sql.ErrNoRows) {
		return HostConnectionCredential{}, ErrHostCredentialInvalid
	} else if err != nil {
		return HostConnectionCredential{}, ErrDatabaseUnavailable
	}
	result := HostConnectionCredential{
		Credential: credential, TokenType: "DSH-Host", InstallationID: installationID,
		KeyThumbprint: publicKeyThumbprint,
	}
	err = transaction.QueryRowContext(ctx, `
		insert into host_connection_credentials (token_sha256, installation_id, key_version, expires_at)
		values ($1, $2, $3, clock_timestamp() + interval '5 minutes')
		returning expires_at`, credentialDigest[:], installationID, keyVersion).Scan(&result.ExpiresAt)
	if err != nil {
		return HostConnectionCredential{}, ErrDatabaseUnavailable
	}
	metadata, _ := json.Marshal(map[string]any{"installation_id": installationID, "key_version": keyVersion})
	if _, err := transaction.ExecContext(ctx, `
		insert into audit_log (org_id, actor_type, actor_id, action, result, metadata)
		values ($1, 'installation', $2, 'host.credential.issue', 'success', $3::jsonb)`, orgID, installationID, string(metadata)); err != nil {
		return HostConnectionCredential{}, ErrDatabaseUnavailable
	}
	if err := transaction.Commit(); err != nil {
		return HostConnectionCredential{}, ErrDatabaseUnavailable
	}
	return result, nil
}

// ValidateHostConnectionCredential validates the short-lived token and its
// registered key binding. A Relay must still issue and verify a fresh signed
// connection challenge before accepting the socket.
func (postgres *Postgres) ValidateHostConnectionCredential(ctx context.Context, credential, proofKeyJKT string) (HostCredentialIdentity, error) {
	if !keyThumbprintPattern.MatchString(proofKeyJKT) || len(credential) != 43 {
		return HostCredentialIdentity{}, ErrHostCredentialInvalid
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(credential)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != credential {
		return HostCredentialIdentity{}, ErrHostCredentialInvalid
	}
	for index := range decoded {
		decoded[index] = 0
	}
	digest := sha256.Sum256([]byte(credential))
	var result HostCredentialIdentity
	err = postgres.DB.QueryRowContext(ctx, `
		select i.id::text, i.public_key_thumbprint, i.key_version, c.expires_at
		from host_connection_credentials c
		join installations i on i.id = c.installation_id and i.revoked_at is null
		join hosts h on h.id = i.host_id and h.state = 'active'
		where c.token_sha256 = $1 and c.revoked_at is null and c.expires_at > clock_timestamp()
		  and c.key_version = i.key_version and i.public_key_thumbprint = $2`, digest[:], proofKeyJKT).
		Scan(&result.InstallationID, &result.KeyThumbprint, &result.KeyVersion, &result.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return HostCredentialIdentity{}, ErrHostCredentialInvalid
	}
	if err != nil {
		return HostCredentialIdentity{}, ErrDatabaseUnavailable
	}
	return result, nil
}
