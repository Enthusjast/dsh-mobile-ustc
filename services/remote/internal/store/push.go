package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"dsh-mobile-ustc/services/remote/internal/push"
	"github.com/jackc/pgx/v5/pgconn"
)

type PushStore struct {
	database                     *Postgres
	cipher                       *push.Cipher
	issuer, project, packageName string
	approvals                    *ApprovalControl
}
type pushBinding struct {
	ID, Org, User, Device, JKT, Provider, Project, AddressHash, RequestHash, RevokeHash, ChallengeHash, State string
	KeyVersion                                                                                                int64
	Address                                                                                                   []byte
	Created, ChallengeExpiry, Expiry                                                                          time.Time
}

const pushBindingColumns = `b.id::text,b.org_id::text,b.user_id::text,b.device_id::text,b.device_key_version,b.proof_key_jkt,b.provider,b.provider_project,b.address_sha256,b.address_ciphertext,b.request_sha256,b.revoke_sha256,b.challenge_sha256,b.state,b.created_at,b.challenge_expires_at,b.expires_at`

func scanPushBinding(row interface{ Scan(...any) error }) (pushBinding, error) {
	var b pushBinding
	err := row.Scan(&b.ID, &b.Org, &b.User, &b.Device, &b.KeyVersion, &b.JKT, &b.Provider, &b.Project, &b.AddressHash, &b.Address, &b.RequestHash, &b.RevokeHash, &b.ChallengeHash, &b.State, &b.Created, &b.ChallengeExpiry, &b.Expiry)
	return b, err
}
func (b pushBinding) aad() string {
	return strings.Join([]string{"endpoint", b.ID, b.Org, b.User, b.Device, strconv.FormatInt(b.KeyVersion, 10), b.JKT, b.Provider, b.Project, b.AddressHash, b.RequestHash}, "\x00")
}
func (b pushBinding) public() push.Binding {
	return push.Binding{ID: b.ID, State: b.State, ChallengeExpiresAt: b.ChallengeExpiry, ExpiresAt: b.Expiry}
}
func pushRandom() (string, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", push.ErrUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
func pushUUID() (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", push.ErrUnavailable
	}
	data[6] = data[6]&15 | 64
	data[8] = data[8]&63 | 128
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", data[:4], data[4:6], data[6:8], data[8:10], data[10:]), nil
}
func NewPushStore(ctx context.Context, database *Postgres, cipher *push.Cipher, issuer, project, packageName, lookupFingerprint string, approvals *ApprovalControl) (*PushStore, error) {
	if database == nil || database.DB == nil || cipher == nil || issuer == "" || project == "" || packageName == "" || !push.Digest(lookupFingerprint) {
		return nil, push.ErrInvalid
	}
	if _, err := database.DB.ExecContext(ctx, `insert into push_key_metadata(slot,lookup_key_sha256) values(1,$1) on conflict(slot) do nothing`, lookupFingerprint); err != nil {
		return nil, push.ErrUnavailable
	}
	var known string
	if database.DB.QueryRowContext(ctx, `select lookup_key_sha256 from push_key_metadata where slot=1`).Scan(&known) != nil {
		return nil, push.ErrUnavailable
	}
	if known != lookupFingerprint {
		return nil, push.ErrInvalid
	}
	store := &PushStore{database: database, cipher: cipher, issuer: issuer, project: project, packageName: packageName, approvals: approvals}
	// Reject a deployment that removed/replaced an encryption key still needed
	// by a live channel. Do not silently label undecryptable channels active.
	rows, err := database.DB.QueryContext(ctx, `select `+pushBindingColumns+` from push_bindings b join devices d on d.id=b.device_id and d.revoked_at is null and d.key_version=b.device_key_version and d.proof_key_thumbprint=b.proof_key_jkt
	 where b.provider_project=$1 and b.state in ('pending','active') and b.expires_at>clock_timestamp()`, project)
	if err != nil {
		return nil, push.ErrUnavailable
	}
	for rows.Next() {
		binding, err := scanPushBinding(rows)
		if err != nil {
			rows.Close()
			return nil, push.ErrUnavailable
		}
		plain, err := cipher.Open(binding.Address, binding.aad())
		valid := err == nil && push.FID(string(plain))
		clear(plain)
		if !valid {
			rows.Close()
			return nil, push.ErrInvalid
		}
	}
	read, closeErr := rows.Err(), rows.Close()
	if read != nil || closeErr != nil {
		return nil, push.ErrUnavailable
	}
	return store, nil
}
func (store *PushStore) actor(ctx context.Context, tx *sql.Tx, actor push.Actor, org string) (string, int64, error) {
	if !push.UUID(actor.DeviceID) || !push.UUID(org) || actor.Issuer != store.issuer {
		return "", 0, push.ErrAccess
	}
	var user string
	var version int64
	err := tx.QueryRowContext(ctx, `select u.id::text,d.key_version from users u join devices d on d.user_id=u.id and d.id=$3 and d.revoked_at is null
	 join org_memberships m on m.user_id=u.id and m.org_id=$5 where u.issuer=$1 and u.subject=$2 and u.status='active' and d.proof_key_thumbprint=$4 for share of u,d,m`, actor.Issuer, actor.Subject, actor.DeviceID, actor.ProofKeyJKT, org).Scan(&user, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, push.ErrAccess
	}
	if err != nil {
		return "", 0, push.ErrUnavailable
	}
	return user, version, nil
}
func (store *PushStore) owned(ctx context.Context, tx *sql.Tx, actor push.Actor, id, lock string) (pushBinding, error) {
	if !push.UUID(id) {
		return pushBinding{}, push.ErrAccess
	}
	b, err := scanPushBinding(tx.QueryRowContext(ctx, `select `+pushBindingColumns+` from push_bindings b where b.id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return b, push.ErrAccess
	}
	if err != nil {
		return b, push.ErrUnavailable
	}
	user, version, err := store.actor(ctx, tx, actor, b.Org)
	if err != nil {
		return b, err
	}
	b, err = scanPushBinding(tx.QueryRowContext(ctx, `select `+pushBindingColumns+` from push_bindings b where b.id=$1 `+lock, id))
	if err != nil {
		return b, push.ErrUnavailable
	}
	if b.User != user || b.Device != actor.DeviceID || b.JKT != actor.ProofKeyJKT || b.KeyVersion != version || b.Project != store.project {
		return b, push.ErrAccess
	}
	return b, nil
}
func pushAudit(ctx context.Context, tx *sql.Tx, b pushBinding, action, result string, metadata any) error {
	body, err := json.Marshal(metadata)
	if err != nil {
		return push.ErrInvalid
	}
	_, err = tx.ExecContext(ctx, `insert into audit_log(org_id,actor_type,actor_id,device_id,action,result,metadata) values($1,'system','push-service',$2,$3,$4,$5::jsonb)`, b.Org, b.Device, action, result, string(body))
	if err != nil {
		return push.ErrUnavailable
	}
	return nil
}
func (store *PushStore) Register(ctx context.Context, actor push.Actor, input push.Registration) (push.Binding, error) {
	if !input.Valid() {
		return push.Binding{}, push.ErrInvalid
	}
	tx, err := store.database.DB.BeginTx(ctx, nil)
	if err != nil {
		return push.Binding{}, push.ErrUnavailable
	}
	defer tx.Rollback()
	var budgetUser string
	if actor.Issuer != store.issuer {
		return push.Binding{}, push.ErrAccess
	}
	err = tx.QueryRowContext(ctx, `select id::text from users where issuer=$1 and subject=$2 and status='active'`, actor.Issuer, actor.Subject).Scan(&budgetUser)
	if errors.Is(err, sql.ErrNoRows) {
		return push.Binding{}, push.ErrAccess
	}
	if err != nil {
		return push.Binding{}, push.ErrUnavailable
	}
	// Lock the user's budget before device/binding rows, including idempotent
	// retries. Extra registered devices cannot bypass the challenge rate limit.
	if _, err = tx.ExecContext(ctx, `select pg_advisory_xact_lock(hashtextextended('push-registration:'||$1,0))`, budgetUser); err != nil {
		return push.Binding{}, push.ErrUnavailable
	}
	user, version, err := store.actor(ctx, tx, actor, input.OrganizationID)
	if err != nil {
		return push.Binding{}, err
	}
	if user != budgetUser {
		return push.Binding{}, push.ErrAccess
	}
	raw, _ := json.Marshal(input)
	digest := sha256.Sum256(raw)
	requestHash := hex.EncodeToString(digest[:])
	clear(raw)
	old, err := scanPushBinding(tx.QueryRowContext(ctx, `select `+pushBindingColumns+` from push_bindings b where b.id=$1 for update`, input.BindingID))
	if err == nil {
		if old.User != user || old.Device != actor.DeviceID || old.Org != input.OrganizationID || old.KeyVersion != version || old.JKT != actor.ProofKeyJKT || old.RequestHash != requestHash || old.Project != store.project {
			return push.Binding{}, push.ErrConflict
		}
		return old.public(), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return push.Binding{}, push.ErrUnavailable
	}
	var count int
	if tx.QueryRowContext(ctx, `select count(*) from push_bindings where device_id=$1 and created_at>clock_timestamp()-interval '1 hour'`, actor.DeviceID).Scan(&count) != nil {
		return push.Binding{}, push.ErrUnavailable
	}
	if count >= 10 {
		return push.Binding{}, push.ErrConflict
	}
	if tx.QueryRowContext(ctx, `select count(*) from push_bindings where user_id=$1 and created_at>clock_timestamp()-interval '1 hour'`, user).Scan(&count) != nil {
		return push.Binding{}, push.ErrUnavailable
	}
	if count >= 20 {
		return push.Binding{}, push.ErrConflict
	}
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return push.Binding{}, push.ErrUnavailable
	}
	nonce, err := pushRandom()
	if err != nil {
		return push.Binding{}, err
	}
	b := pushBinding{ID: input.BindingID, Org: input.OrganizationID, User: user, Device: actor.DeviceID, KeyVersion: version, JKT: actor.ProofKeyJKT, Provider: "fcm", Project: store.project,
		AddressHash: store.cipher.AddressHash("fcm", store.project, input.Address), RequestHash: requestHash, RevokeHash: input.RevokeSHA256, ChallengeHash: push.SecretHash(nonce), State: "pending", Created: now, ChallengeExpiry: now.Add(3 * time.Minute), Expiry: now.Add(7 * 24 * time.Hour)}
	sealed, err := store.cipher.Seal([]byte(input.Address), b.aad())
	if err != nil {
		return push.Binding{}, push.ErrUnavailable
	}
	delivery, err := pushUUID()
	if err != nil {
		return push.Binding{}, err
	}
	challenge, err := store.cipher.Seal([]byte(nonce), b.aad()+"\x00challenge\x00"+delivery)
	if err != nil {
		return push.Binding{}, push.ErrUnavailable
	}
	_, err = tx.ExecContext(ctx, `insert into push_bindings(id,org_id,user_id,device_id,device_key_version,proof_key_jkt,provider,provider_project,address_sha256,address_ciphertext,request_sha256,revoke_sha256,challenge_sha256,state,created_at,challenge_expires_at,expires_at)
	 values($1,$2,$3,$4,$5,$6,'fcm',$7,$8,$9,$10,$11,$12,'pending',$13,$14,$15)`, b.ID, b.Org, b.User, b.Device, b.KeyVersion, b.JKT, b.Project, b.AddressHash, sealed, b.RequestHash, b.RevokeHash, b.ChallengeHash, b.Created, b.ChallengeExpiry, b.Expiry)
	if err != nil {
		return push.Binding{}, push.ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `insert into push_deliveries(id,binding_id,kind,nonce_ciphertext,expires_at) values($1,$2,'challenge',$3,$4)`, delivery, b.ID, challenge, b.ChallengeExpiry); err != nil {
		return push.Binding{}, push.ErrUnavailable
	}
	if pushAudit(ctx, tx, b, "push.binding", "pending", map[string]string{"binding_id": b.ID, "provider": "fcm"}) != nil || tx.Commit() != nil {
		return push.Binding{}, push.ErrUnavailable
	}
	return b.public(), nil
}
func (store *PushStore) Status(ctx context.Context, actor push.Actor, id string) (push.Binding, error) {
	tx, err := store.database.DB.BeginTx(ctx, nil)
	if err != nil {
		return push.Binding{}, push.ErrUnavailable
	}
	defer tx.Rollback()
	b, err := store.owned(ctx, tx, actor, id, "for share of b")
	if err != nil {
		return push.Binding{}, err
	}
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return push.Binding{}, push.ErrUnavailable
	}
	if now.Before(b.Created) || !now.Before(b.Expiry) || b.State == "pending" && !now.Before(b.ChallengeExpiry) {
		b.State = "expired"
	}
	return b.public(), nil
}
func (store *PushStore) Confirm(ctx context.Context, actor push.Actor, id, nonce string) (push.Binding, error) {
	if !push.Secret(nonce) {
		return push.Binding{}, push.ErrInvalid
	}
	tx, err := store.database.DB.BeginTx(ctx, nil)
	if err != nil {
		return push.Binding{}, push.ErrUnavailable
	}
	defer tx.Rollback()
	b, err := store.owned(ctx, tx, actor, id, "for update of b")
	if err != nil {
		return push.Binding{}, err
	}
	hash := push.SecretHash(nonce)
	if subtle.ConstantTimeCompare([]byte(hash), []byte(b.ChallengeHash)) != 1 {
		return push.Binding{}, push.ErrAccess
	}
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return push.Binding{}, push.ErrUnavailable
	}
	if now.Before(b.Created) || !now.Before(b.Expiry) || b.State != "pending" && b.State != "active" {
		return push.Binding{}, push.ErrExpired
	}
	if b.State == "active" {
		return b.public(), nil
	}
	if !now.Before(b.ChallengeExpiry) {
		return push.Binding{}, push.ErrExpired
	}
	_, err = tx.ExecContext(ctx, `update push_bindings set state='expired',address_ciphertext=null where state='active' and expires_at<=clock_timestamp()`)
	if err != nil {
		return push.Binding{}, push.ErrUnavailable
	}
	_, err = tx.ExecContext(ctx, `update push_bindings set state='active',activated_at=clock_timestamp() where id=$1`, id)
	if err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return push.Binding{}, push.ErrConflict
		}
		return push.Binding{}, push.ErrUnavailable
	}
	if _, err = tx.ExecContext(ctx, `update push_deliveries set state='confirmed',nonce_ciphertext=null,updated_at=clock_timestamp() where binding_id=$1 and kind='challenge'`, id); err != nil {
		return push.Binding{}, push.ErrUnavailable
	}
	if pushAudit(ctx, tx, b, "push.binding", "active", map[string]string{"binding_id": id}) != nil || tx.Commit() != nil {
		return push.Binding{}, push.ErrUnavailable
	}
	b.State = "active"
	return b.public(), nil
}

// A locally retained, deletion-only secret permits logout cleanup after the old OAuth session is gone.
func (store *PushStore) Revoke(ctx context.Context, id, secret string) error {
	if !push.UUID(id) || !push.Secret(secret) {
		return nil
	}
	tx, err := store.database.DB.BeginTx(ctx, nil)
	if err != nil {
		return push.ErrUnavailable
	}
	defer tx.Rollback()
	b, err := scanPushBinding(tx.QueryRowContext(ctx, `select `+pushBindingColumns+` from push_bindings b where b.id=$1 for update`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return push.ErrUnavailable
	}
	hash := push.SecretHash(secret)
	if subtle.ConstantTimeCompare([]byte(hash), []byte(b.RevokeHash)) != 1 {
		return nil
	}
	if b.State == "disabled" || b.State == "expired" {
		return nil
	}
	if _, err = tx.ExecContext(ctx, `update push_bindings set state='disabled',address_ciphertext=null where id=$1`, id); err != nil {
		return push.ErrUnavailable
	}
	if _, err = tx.ExecContext(ctx, `update push_deliveries set state='expired',nonce_ciphertext=null,error_code='binding_disabled',updated_at=clock_timestamp() where binding_id=$1 and state in ('queued','retry','leased')`, id); err != nil {
		return push.ErrUnavailable
	}
	if pushAudit(ctx, tx, b, "push.binding", "disabled", map[string]string{"binding_id": id}) != nil || tx.Commit() != nil {
		return push.ErrUnavailable
	}
	return nil
}

func (store *PushStore) Capabilities() map[string]any {
	sources := []string{"question", "timed_question"}
	if store.approvals != nil {
		sources = append(sources, "approval")
	}
	return map[string]any{"v": 1, "providers": []any{map[string]string{"provider": "fcm", "project_id": store.project, "package_name": store.packageName, "address_kind": "fid"}}, "sources": sources, "verification": "provider_challenge", "lease_seconds": 604800}
}
