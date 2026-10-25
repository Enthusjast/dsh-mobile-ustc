package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
)

const fileHandoffLease = 5 * time.Second

func fileHostAudit(ctx context.Context, transaction *sql.Tx, handoff files.Handoff, action string) error {
	metadata, _ := json.Marshal(map[string]any{"file_id": handoff.File.ID, "handoff_id": handoff.ID, "connection_id": handoff.Host.ConnectionID,
		"runtime_epoch": handoff.Host.RuntimeEpoch, "installation_key_version": handoff.Host.KeyVersion, "size_bytes": handoff.File.SizeBytes, "sha256": handoff.File.SHA256})
	if _, err := transaction.ExecContext(ctx, `insert into audit_log(org_id,actor_type,actor_id,device_id,runtime_id,session_id,action,result,metadata)
	 values($1,'installation',$2,$3,$4,$5,$6,'success',$7::jsonb)`, handoff.File.OrganizationID, handoff.Host.InstallationID, handoff.File.DeviceID, handoff.File.RuntimeID, handoff.File.SessionID, action, string(metadata)); err != nil {
		return files.ErrUnavailable
	}
	return nil
}

func hostFileBinding(ctx context.Context, transaction *sql.Tx, host files.HostBinding) (json.RawMessage, string, error) {
	for _, id := range []string{host.InstallationID, host.RuntimeID, host.RuntimeEpoch, host.ConnectionID} {
		if !grantUUIDPattern.MatchString(id) {
			return nil, "", files.ErrAccess
		}
	}
	if host.KeyVersion <= 0 {
		return nil, "", files.ErrAccess
	}
	var public []byte
	var thumb string
	err := transaction.QueryRowContext(ctx, `select i.public_jwk,i.public_key_thumbprint from runtimes r
	 join installations i on i.id=r.installation_id and i.revoked_at is null join hosts h on h.id=i.host_id and h.state='active'
	 where r.id=$1 and i.id=$2 and i.key_version=$3 and r.connection_key_version=i.key_version and r.epoch=$4 and r.connection_id=$5
	 and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+` for share of r,i,h`, host.RuntimeID, host.InstallationID, host.KeyVersion, host.RuntimeEpoch, host.ConnectionID).Scan(&public, &thumb)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", files.ErrAccess
	}
	if err != nil {
		return nil, "", files.ErrUnavailable
	}
	now, err := databaseTime(ctx, transaction)
	if err != nil {
		return nil, "", err
	}
	if !host.CredentialExpiresAt.After(now) {
		return nil, "", files.ErrAccess
	}
	return public, thumb, nil
}

func cleanHandoffFile(ctx context.Context, transaction *sql.Tx, record files.Record, policy string) (fileAuthority, error) {
	if record.State != "clean" || !validSHA256Hex(policy) || record.CommittedAttempt == "" {
		return fileAuthority{}, files.ErrAccess
	}
	var actual, stored string
	if err := transaction.QueryRowContext(ctx, `select t.scanner_policy_sha256,f.object_key from file_transfers t join files f on f.id=t.file_id where f.id=$1`, record.ID).Scan(&actual, &stored); err != nil {
		return fileAuthority{}, files.ErrUnavailable
	}
	key, err := record.CommittedKey()
	if err != nil || actual != policy || stored != key.StorageKey() {
		return fileAuthority{}, files.ErrAccess
	}
	authority, err := authorizeBoundFile(ctx, transaction, record)
	if err != nil {
		return authority, err
	}
	if authority.sessionState != "available" && authority.sessionState != "running" {
		return authority, files.ErrAccess
	}
	now, err := databaseTime(ctx, transaction)
	if err != nil {
		return authority, err
	}
	if !record.ExpiresAt.After(now) {
		return authority, files.ErrAccess
	}
	return authority, nil
}

const handoffColumns = `h.id::text,h.installation_id::text,h.installation_key_version,h.runtime_id::text,h.runtime_epoch::text,h.connection_id::text,
 h.credential_expires_at,h.scanner_policy_sha256,h.state,h.lease_until,h.expires_at`

func scanHandoff(row fileScanner, record files.Record) (files.Handoff, error) {
	handoff := files.Handoff{File: record}
	err := row.Scan(&handoff.ID, &handoff.Host.InstallationID, &handoff.Host.KeyVersion, &handoff.Host.RuntimeID, &handoff.Host.RuntimeEpoch, &handoff.Host.ConnectionID,
		&handoff.Host.CredentialExpiresAt, &handoff.PolicySHA256, &handoff.State, &handoff.LeaseUntil, &handoff.ExpiresAt)
	return handoff, err
}
func loadHandoff(ctx context.Context, transaction *sql.Tx, id string) (files.Handoff, error) {
	if !grantUUIDPattern.MatchString(id) {
		return files.Handoff{}, files.ErrAccess
	}
	var file string
	if err := transaction.QueryRowContext(ctx, `select file_id::text from file_handoffs where id=$1`, id).Scan(&file); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return files.Handoff{}, files.ErrAccess
		}
		return files.Handoff{}, files.ErrUnavailable
	}
	record, err := loadFile(ctx, transaction, file, "for share of f,t")
	if err != nil {
		return files.Handoff{}, files.ErrUnavailable
	}
	handoff, err := scanHandoff(transaction.QueryRowContext(ctx, `select `+handoffColumns+` from file_handoffs h where h.id=$1 for update`, id), record)
	if err != nil {
		return handoff, files.ErrUnavailable
	}
	return handoff, nil
}
func sameFileHost(left, right files.HostBinding) bool {
	return left.InstallationID == right.InstallationID && left.KeyVersion == right.KeyVersion && left.RuntimeID == right.RuntimeID && left.RuntimeEpoch == right.RuntimeEpoch && left.ConnectionID == right.ConnectionID
}
func validHandoff(ctx context.Context, transaction *sql.Tx, handoff files.Handoff, host files.HostBinding, policy string) (fileAuthority, error) {
	if !sameFileHost(handoff.Host, host) || handoff.PolicySHA256 != policy || handoff.File.RuntimeID != host.RuntimeID {
		return fileAuthority{}, files.ErrAccess
	}
	if err := fileMessageAllowsHandoff(ctx, transaction, handoff.File.ID, false); err != nil {
		return fileAuthority{}, err
	}
	if _, _, err := hostFileBinding(ctx, transaction, handoff.Host); err != nil {
		return fileAuthority{}, err
	}
	authority, err := cleanHandoffFile(ctx, transaction, handoff.File, policy)
	if err != nil {
		return authority, err
	}
	now, err := databaseTime(ctx, transaction)
	if err != nil {
		return authority, err
	}
	if handoff.State != "offered" && handoff.State != "downloading" && handoff.State != "staged" || !handoff.LeaseUntil.After(now) || !handoff.ExpiresAt.After(now) {
		return authority, files.ErrStale
	}
	return authority, nil
}

func (repository *FileStore) IssueHandoff(ctx context.Context, host files.HostBinding, id, policy string) (*files.FileOffer, error) {
	if !grantUUIDPattern.MatchString(id) || !validSHA256Hex(policy) {
		return nil, files.ErrInvalid
	}
	transaction, err := repository.database.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, files.ErrUnavailable
	}
	defer transaction.Rollback()
	record, err := loadFile(ctx, transaction, id, "for update of f,t")
	if errors.Is(err, sql.ErrNoRows) {
		return nil, files.ErrAccess
	}
	if err != nil {
		return nil, files.ErrUnavailable
	}
	if record.RuntimeID != host.RuntimeID {
		return nil, files.ErrAccess
	}
	if err := fileMessageAllowsHandoff(ctx, transaction, id, true); err != nil {
		return nil, err
	}
	if _, _, err := hostFileBinding(ctx, transaction, host); err != nil {
		return nil, err
	}
	authority, err := cleanHandoffFile(ctx, transaction, record, policy)
	if err != nil {
		return nil, err
	}
	now, err := databaseTime(ctx, transaction)
	if err != nil {
		return nil, err
	}
	if _, err := transaction.ExecContext(ctx, `update file_handoffs set state='invalidated',ended_at=clock_timestamp(),staged_name=null where file_id=$1 and state in ('offered','downloading','staged')
	 and (lease_until<=clock_timestamp() or expires_at<=clock_timestamp() or installation_id<>$2 or installation_key_version<>$3 or runtime_epoch<>$4 or connection_id<>$5 or scanner_policy_sha256<>$6)`, id, host.InstallationID, host.KeyVersion, host.RuntimeEpoch, host.ConnectionID, policy); err != nil {
		return nil, files.ErrUnavailable
	}
	var active, recent int
	if err := transaction.QueryRowContext(ctx, `select count(*) from file_handoffs where file_id=$1 and state in ('offered','downloading','staged')`, id).Scan(&active); err != nil {
		return nil, files.ErrUnavailable
	}
	if active > 0 {
		if err := transaction.Commit(); err != nil {
			return nil, files.ErrUnavailable
		}
		return nil, nil
	}
	if err := transaction.QueryRowContext(ctx, `select count(*) from file_handoffs where file_id=$1 and created_at>clock_timestamp()-interval '1 minute'`, id).Scan(&recent); err != nil {
		return nil, files.ErrUnavailable
	}
	if recent >= 10 {
		return nil, files.ErrQuota
	}
	handoffID, err := fileUUID()
	if err != nil {
		return nil, err
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, files.ErrUnavailable
	}
	token := base64.RawURLEncoding.EncodeToString(random[:])
	clear(random[:])
	digest := sha256.Sum256([]byte(token))
	expires := now.Add(5 * time.Minute)
	for _, bound := range []time.Time{host.CredentialExpiresAt, record.ExpiresAt} {
		if bound.Before(expires) {
			expires = bound
		}
	}
	if authority.grantExpires.Valid && authority.grantExpires.Time.Before(expires) {
		expires = authority.grantExpires.Time
	}
	until := now.Add(fileHandoffLease)
	if expires.Before(until) {
		until = expires
	}
	if !until.After(now) {
		return nil, files.ErrAccess
	}
	if _, err := transaction.ExecContext(ctx, `insert into file_handoffs(id,file_id,installation_id,installation_key_version,runtime_id,runtime_epoch,connection_id,scanner_policy_sha256,token_sha256,state,lease_until,expires_at,credential_expires_at)
	 values($1,$2,$3,$4,$5,$6,$7,$8,$9,'offered',$10,$11,$12)`, handoffID, id, host.InstallationID, host.KeyVersion, host.RuntimeID, host.RuntimeEpoch, host.ConnectionID, policy, digest[:], until, expires, host.CredentialExpiresAt); err != nil {
		return nil, files.ErrUnavailable
	}
	if err := transaction.Commit(); err != nil {
		return nil, files.ErrUnavailable
	}
	return &files.FileOffer{SessionID: record.SessionID, HandoffID: handoffID, FileID: id, Name: record.Name, SizeBytes: record.SizeBytes, SHA256: record.SHA256, UserID: record.UploaderID, DeviceID: record.DeviceID, KeyVersion: record.KeyVersion, GrantVersion: record.GrantVersion, DownloadToken: token, LeaseUntil: until, ExpiresAt: expires}, nil
}

func (repository *FileStore) PendingHandoffFiles(ctx context.Context, host files.HostBinding, policy string, limit int) ([]string, error) {
	if limit < 1 || limit > 32 || !validSHA256Hex(policy) {
		return nil, files.ErrInvalid
	}
	transaction, err := repository.database.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, files.ErrUnavailable
	}
	defer transaction.Rollback()
	if _, _, err := hostFileBinding(ctx, transaction, host); err != nil {
		return nil, err
	}
	rows, err := transaction.QueryContext(ctx, `select f.id::text from files f join file_transfers t on t.file_id=f.id join sessions s on s.id=f.session_id
	 join users u on u.id=f.uploader_id and u.status='active'
	 join devices d on d.id=t.uploader_device_id and d.user_id=u.id and d.revoked_at is null and d.key_version=t.device_key_version and d.proof_key_thumbprint=t.proof_key_jkt
	 join runtime_grants g on g.runtime_id=t.runtime_id and g.user_id=u.id and g.grant_version=t.grant_version and g.revoked_at is null
	 where t.runtime_id=$1 and f.state='clean' and f.expires_at>clock_timestamp() and t.scanner_policy_sha256=$2 and s.state in ('available','running')
	 and g.role in ('operator','owner') and (g.expires_at is null or g.expires_at>clock_timestamp())
	 and g.scope->'actions' ? 'file.upload' and ((g.scope->'sessions') ? f.session_id::text or (g.scope->'workspaces') ? s.workspace_id::text)
	 and exists(select 1 from org_memberships m where m.org_id=t.org_id and m.user_id=u.id)
	 and not exists(select 1 from file_message_refs ref join commands c on c.device_id=ref.device_id and c.request_id=ref.request_id where ref.file_id=f.id and c.state<>'received')
	 and (select count(*) from file_handoffs recent where recent.file_id=f.id and recent.created_at>clock_timestamp()-interval '1 minute')<10
	 and not exists(select 1 from file_handoffs h where h.file_id=f.id and h.state in ('offered','downloading','staged') and h.connection_id=$3 and h.runtime_epoch=$4 and h.lease_until>clock_timestamp() and h.expires_at>clock_timestamp())
	 order by f.created_at,f.id limit $5`, host.RuntimeID, policy, host.ConnectionID, host.RuntimeEpoch, limit)
	if err != nil {
		return nil, files.ErrUnavailable
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			return nil, files.ErrUnavailable
		}
		ids = append(ids, id)
	}
	if rows.Err() != nil {
		return nil, files.ErrUnavailable
	}
	return ids, nil
}

func (repository *FileStore) RenewHandoff(ctx context.Context, host files.HostBinding, id, policy string) (files.Handoff, error) {
	transaction, err := repository.database.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return files.Handoff{}, files.ErrUnavailable
	}
	defer transaction.Rollback()
	handoff, err := loadHandoff(ctx, transaction, id)
	if err != nil {
		return handoff, err
	}
	if _, err := validHandoff(ctx, transaction, handoff, host, policy); err != nil {
		return handoff, err
	}
	now, err := databaseTime(ctx, transaction)
	if err != nil {
		return handoff, err
	}
	handoff.LeaseUntil = now.Add(fileHandoffLease)
	if handoff.ExpiresAt.Before(handoff.LeaseUntil) {
		handoff.LeaseUntil = handoff.ExpiresAt
	}
	if _, err := transaction.ExecContext(ctx, `update file_handoffs set lease_until=$2 where id=$1`, id, handoff.LeaseUntil); err != nil {
		return handoff, files.ErrUnavailable
	}
	if err := transaction.Commit(); err != nil {
		return handoff, files.ErrUnavailable
	}
	return handoff, nil
}

func (repository *FileStore) RedeemFileRead(ctx context.Context, id, token, policy string, verify func(files.ReadPermit) error) (files.ReadPermit, error) {
	if len(token) != 43 || verify == nil {
		return files.ReadPermit{}, files.ErrAccess
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != 32 {
		return files.ReadPermit{}, files.ErrAccess
	}
	clear(raw)
	transaction, err := repository.database.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return files.ReadPermit{}, files.ErrUnavailable
	}
	defer transaction.Rollback()
	handoff, err := loadHandoff(ctx, transaction, id)
	if err != nil {
		return files.ReadPermit{}, err
	}
	if _, err := validHandoff(ctx, transaction, handoff, handoff.Host, policy); err != nil {
		return files.ReadPermit{}, err
	}
	var stored []byte
	var started sql.NullTime
	if err := transaction.QueryRowContext(ctx, `select token_sha256,read_started_at from file_handoffs where id=$1`, id).Scan(&stored, &started); err != nil {
		return files.ReadPermit{}, files.ErrUnavailable
	}
	digest := sha256.Sum256([]byte(token))
	if handoff.State != "offered" || started.Valid || subtle.ConstantTimeCompare(digest[:], stored) != 1 {
		return files.ReadPermit{}, files.ErrAccess
	}
	public, thumb, err := hostFileBinding(ctx, transaction, handoff.Host)
	if err != nil {
		return files.ReadPermit{}, err
	}
	permit := files.ReadPermit{Handoff: handoff, PublicJWK: public, KeyThumbprint: thumb}
	if verify(permit) != nil {
		return files.ReadPermit{}, files.ErrAccess
	}
	if _, err := validHandoff(ctx, transaction, handoff, handoff.Host, policy); err != nil {
		return files.ReadPermit{}, err
	}
	if _, err := transaction.ExecContext(ctx, `update file_handoffs set state='downloading',read_started_at=clock_timestamp() where id=$1`, id); err != nil {
		return files.ReadPermit{}, files.ErrUnavailable
	}
	if err := fileHostAudit(ctx, transaction, handoff, "file.host_read"); err != nil {
		return files.ReadPermit{}, err
	}
	if err := transaction.Commit(); err != nil {
		return files.ReadPermit{}, files.ErrUnavailable
	}
	permit.Handoff.State = "downloading"
	return permit, nil
}

func (repository *FileStore) CheckFileRead(ctx context.Context, host files.HostBinding, id, policy string) (files.Handoff, error) {
	transaction, err := repository.database.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return files.Handoff{}, files.ErrUnavailable
	}
	defer transaction.Rollback()
	handoff, err := loadHandoff(ctx, transaction, id)
	if err != nil {
		return handoff, err
	}
	if handoff.State != "downloading" && handoff.State != "staged" {
		return handoff, files.ErrStale
	}
	if _, err := validHandoff(ctx, transaction, handoff, host, policy); err != nil {
		return handoff, err
	}
	if err := transaction.Commit(); err != nil {
		return handoff, files.ErrUnavailable
	}
	return handoff, nil
}

func (repository *FileStore) StageHandoff(ctx context.Context, host files.HostBinding, id, sha string, size int64, name, policy string) error {
	if len(name) > 512 || strings.TrimSpace(name) == "" {
		return files.ErrInvalid
	}
	transaction, err := repository.database.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return files.ErrUnavailable
	}
	defer transaction.Rollback()
	handoff, err := loadHandoff(ctx, transaction, id)
	if err != nil {
		return err
	}
	if _, err := validHandoff(ctx, transaction, handoff, host, policy); err != nil {
		return err
	}
	if handoff.File.SHA256 != sha || handoff.File.SizeBytes != size {
		return files.ErrConflict
	}
	_, err = files.NormalizeRegistration(files.UploadRegistration{RequestID: id, RuntimeID: host.RuntimeID, SessionID: handoff.File.SessionID, Name: name, SizeBytes: size, SHA256: sha})
	if err != nil {
		return files.ErrInvalid
	}
	if handoff.State == "staged" {
		var previous string
		if err := transaction.QueryRowContext(ctx, `select staged_name from file_handoffs where id=$1`, id).Scan(&previous); err != nil {
			return files.ErrUnavailable
		}
		if previous != name {
			return files.ErrConflict
		}
	} else {
		if handoff.State != "downloading" {
			return files.ErrStale
		}
		if _, err := transaction.ExecContext(ctx, `update file_handoffs set state='staged',staged_name=$2 where id=$1`, id, name); err != nil {
			return files.ErrUnavailable
		}
		if err := fileHostAudit(ctx, transaction, handoff, "file.host_staged"); err != nil {
			return err
		}
		if _, err := transaction.ExecContext(ctx, `update control_outbox set published_at=clock_timestamp() where topic='file.clean' and payload->>'file_id'=$1 and published_at is null`, handoff.File.ID); err != nil {
			return files.ErrUnavailable
		}
	}
	if err := transaction.Commit(); err != nil {
		return files.ErrUnavailable
	}
	return nil
}

func (repository *FileStore) EndHandoff(ctx context.Context, host files.HostBinding, id string) error {
	transaction, err := repository.database.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return files.ErrUnavailable
	}
	defer transaction.Rollback()
	handoff, err := loadHandoff(ctx, transaction, id)
	if err != nil {
		return err
	}
	if !sameFileHost(handoff.Host, host) {
		return files.ErrAccess
	}
	if _, err := transaction.ExecContext(ctx, `update file_handoffs set state='invalidated',staged_name=null,ended_at=clock_timestamp() where id=$1 and state in ('offered','downloading','staged')`, id); err != nil {
		return files.ErrUnavailable
	}
	if err := transaction.Commit(); err != nil {
		return files.ErrUnavailable
	}
	return nil
}
