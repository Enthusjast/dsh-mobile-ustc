package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

var ErrQuestionReferencesInvalid = errors.New("store: invalid question references")
var ErrQuestionReferencesConflict = errors.New("store: question reference sequence conflict")
var ErrQuestionReferencesLimited = errors.New("store: question reference budget exceeded")

// References never include native call IDs, questions, options, answers or tool arguments.
type QuestionReferenceItem struct {
	ID        string     `json:"question_id"`
	SessionID string     `json:"session_id"`
	Kind      string     `json:"kind"`
	State     string     `json:"state"`
	ExpiresAt *time.Time `json:"expires_at"`
}

func (item *QuestionReferenceItem) UnmarshalJSON(raw []byte) error {
	type value QuestionReferenceItem
	var decoded value
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&decoded) != nil {
		return ErrQuestionReferencesInvalid
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(raw, &keys) != nil || len(keys) != 5 {
		return ErrQuestionReferencesInvalid
	}
	for _, key := range []string{"question_id", "session_id", "kind", "state", "expires_at"} {
		if len(keys[key]) == 0 || key != "expires_at" && string(keys[key]) == "null" {
			return ErrQuestionReferencesInvalid
		}
	}
	*item = QuestionReferenceItem(decoded)
	return nil
}
func (item QuestionReferenceItem) Valid() bool {
	if !grantUUIDPattern.MatchString(item.ID) || !grantUUIDPattern.MatchString(item.SessionID) {
		return false
	}
	if item.Kind == "question" {
		return item.State == "pending" && item.ExpiresAt != nil
	}
	return item.Kind == "timed_question" && (item.State == "pending" || (item.State == "continued" || item.State == "reply_queued") && item.ExpiresAt == nil)
}

// A full snapshot is owned by one current Host connection. Sequence retries can
// renew exactly that snapshot; an old connection cannot prolong its authority.
func (postgres *Postgres) SyncRealtimeQuestionReferences(ctx context.Context, connection RuntimeConnection, keyVersion, sequence int64, items []QuestionReferenceItem) error {
	if !grantUUIDPattern.MatchString(connection.InstallationID) || !grantUUIDPattern.MatchString(connection.RuntimeID) ||
		!grantUUIDPattern.MatchString(connection.RuntimeEpoch) || !grantUUIDPattern.MatchString(connection.ConnectionID) || keyVersion < 1 || sequence < 1 || sequence > 9007199254740991 || items == nil || len(items) > 128 {
		return ErrQuestionReferencesInvalid
	}
	seen := map[string]bool{}
	for _, item := range items {
		if !item.Valid() || seen[item.ID] {
			return ErrQuestionReferencesInvalid
		}
		seen[item.ID] = true
	}
	encoded, err := json.Marshal(items)
	if err != nil {
		return ErrQuestionReferencesInvalid
	}
	hash := sha256.Sum256(encoded)
	digest := hex.EncodeToString(hash[:])
	tx, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	var org string
	err = tx.QueryRowContext(ctx, `select h.org_id::text from runtimes r
	 join installations i on i.id=r.installation_id and i.revoked_at is null
	 join hosts h on h.id=i.host_id and h.state='active'
	 where r.id=$1 and i.id=$2 and i.key_version=$3 and r.connection_key_version=$3 and r.epoch=$4 and r.connection_id=$5
	 and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+` for share of r,i,h`, connection.RuntimeID, connection.InstallationID, keyVersion, connection.RuntimeEpoch, connection.ConnectionID).Scan(&org)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrRuntimeConnectionStale
	}
	if err != nil {
		return ErrDatabaseUnavailable
	}
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return ErrDatabaseUnavailable
	}
	for _, item := range items {
		if item.ExpiresAt != nil && (item.ExpiresAt.After(now.Add(630*time.Second)) || item.ExpiresAt.Before(now.Add(-30*time.Second))) {
			return ErrQuestionReferencesInvalid
		}
	}
	_, err = tx.ExecContext(ctx, `insert into question_reference_feeds(runtime_id,runtime_epoch,connection_id,key_version,sequence,snapshot_sha256,lease_until)
	 values($1,$2,$3,$4,0,$5,clock_timestamp()) on conflict(runtime_id) do nothing`, connection.RuntimeID, connection.RuntimeEpoch, connection.ConnectionID, keyVersion, hex.EncodeToString(make([]byte, 32)))
	if err != nil {
		return ErrDatabaseUnavailable
	}
	var oldEpoch, oldConnection, oldDigest string
	var oldKey, oldSequence int64
	err = tx.QueryRowContext(ctx, `select runtime_epoch::text,connection_id::text,key_version,sequence,snapshot_sha256 from question_reference_feeds where runtime_id=$1 for update`, connection.RuntimeID).Scan(&oldEpoch, &oldConnection, &oldKey, &oldSequence, &oldDigest)
	if err != nil {
		return ErrDatabaseUnavailable
	}
	newConnection := oldEpoch != connection.RuntimeEpoch || oldConnection != connection.ConnectionID || oldKey != keyVersion
	if newConnection && sequence != 1 || !newConnection && sequence != oldSequence+1 && (sequence != oldSequence || digest != oldDigest) {
		return ErrQuestionReferencesConflict
	}
	changed := newConnection || digest != oldDigest
	if changed {
		if oldEpoch != connection.RuntimeEpoch {
			if _, err = tx.ExecContext(ctx, `update question_references set state='ended',updated_at=clock_timestamp() where runtime_id=$1 and runtime_epoch<>$2 and state<>'ended'`, connection.RuntimeID, connection.RuntimeEpoch); err != nil {
				return ErrDatabaseUnavailable
			}
		}
		var sessions int
		err = tx.QueryRowContext(ctx, `select count(*) from jsonb_to_recordset($2::jsonb) q(session_id uuid)
		 join sessions s on s.id=q.session_id and s.runtime_id=$1 and s.state not in ('archived','unavailable')`, connection.RuntimeID, string(encoded)).Scan(&sessions)
		if err != nil {
			return ErrDatabaseUnavailable
		}
		if sessions != len(items) {
			return ErrQuestionReferencesInvalid
		}
		var recent, incoming int
		err = tx.QueryRowContext(ctx, `select (select count(*) from question_references where runtime_id=$1 and created_at>clock_timestamp()-interval '1 hour'),
		 (select count(*) from jsonb_to_recordset($2::jsonb) q(question_id uuid) where not exists(select 1 from question_references r where r.id=q.question_id))`, connection.RuntimeID, string(encoded)).Scan(&recent, &incoming)
		if err != nil {
			return ErrDatabaseUnavailable
		}
		if recent+incoming > 2048 {
			return ErrQuestionReferencesLimited
		}
		result, err := tx.ExecContext(ctx, `insert into question_references(id,runtime_id,runtime_epoch,connection_id,session_id,kind,state,expires_at)
		 select q.question_id,$1,$2,$3,q.session_id,q.kind,q.state,q.expires_at from jsonb_to_recordset($4::jsonb)
		 q(question_id uuid,session_id uuid,kind text,state text,expires_at timestamptz)
		 on conflict(id) do update set connection_id=excluded.connection_id,state=excluded.state,expires_at=excluded.expires_at,updated_at=clock_timestamp()
		 where question_references.runtime_id=excluded.runtime_id and question_references.runtime_epoch=excluded.runtime_epoch
		 and question_references.session_id=excluded.session_id and question_references.kind=excluded.kind`, connection.RuntimeID, connection.RuntimeEpoch, connection.ConnectionID, string(encoded))
		if err != nil {
			return ErrDatabaseUnavailable
		}
		count, err := result.RowsAffected()
		if err != nil || count != int64(len(items)) {
			return ErrQuestionReferencesInvalid
		}
		_, err = tx.ExecContext(ctx, `update question_references set state='ended',updated_at=clock_timestamp() where runtime_id=$1 and runtime_epoch=$2 and state<>'ended'
		 and id not in (select q.question_id from jsonb_to_recordset($3::jsonb) q(question_id uuid))`, connection.RuntimeID, connection.RuntimeEpoch, string(encoded))
		if err != nil {
			return ErrDatabaseUnavailable
		}
		metadata, _ := json.Marshal(map[string]any{"item_count": len(items), "sequence": sequence, "runtime_epoch": connection.RuntimeEpoch})
		_, err = tx.ExecContext(ctx, `insert into audit_log(org_id,actor_type,actor_id,runtime_id,action,result,metadata)
		 values($1,'installation',$2,$3,'question.references.sync','success',$4::jsonb)`, org, connection.InstallationID, connection.RuntimeID, string(metadata))
		if err != nil {
			return ErrDatabaseUnavailable
		}
	}
	_, err = tx.ExecContext(ctx, `update question_reference_feeds set runtime_epoch=$2,connection_id=$3,key_version=$4,sequence=$5,snapshot_sha256=$6,
	 lease_until=clock_timestamp()+interval '45 seconds',updated_at=clock_timestamp() where runtime_id=$1`, connection.RuntimeID, connection.RuntimeEpoch, connection.ConnectionID, keyVersion, sequence, digest)
	if err != nil {
		return ErrDatabaseUnavailable
	}
	_, err = tx.ExecContext(ctx, `delete from question_references where id in (select id from question_references where runtime_id=$1 and state='ended' and updated_at<clock_timestamp()-interval '7 days' limit 2048)`, connection.RuntimeID)
	if err != nil || tx.Commit() != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}
