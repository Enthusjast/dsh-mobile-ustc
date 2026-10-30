package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrIdentitySnapshot = errors.New("store: identity snapshot is invalid or stale")
var ErrIdentitySyncConflict = errors.New("store: identity synchronization conflicts with recorded state")
var identitySlug = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

type IdentityOrganization struct {
	ID   string `json:"organization_id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}
type IdentitySnapshot struct {
	Version          int                    `json:"v"`
	Complete         bool                   `json:"complete"`
	OperationID      string                 `json:"operation_id"`
	DatabaseEpoch    string                 `json:"database_epoch"`
	Issuer           string                 `json:"issuer"`
	ExpectedRevision int64                  `json:"expected_revision"`
	Revision         int64                  `json:"revision"`
	CapturedAt       time.Time              `json:"captured_at"`
	ExpiresAt        time.Time              `json:"expires_at"`
	Organizations    []IdentityOrganization `json:"organizations"`
	Users            []RecoveryUser         `json:"users"`
}
type IdentitySyncRun struct {
	ID               string           `json:"operation_id"`
	DatabaseEpoch    string           `json:"database_epoch"`
	Issuer           string           `json:"issuer"`
	ExpectedRevision int64            `json:"expected_revision"`
	Revision         int64            `json:"revision"`
	SnapshotSHA256   string           `json:"snapshot_sha256"`
	CapturedAt       time.Time        `json:"captured_at"`
	AppliedAt        time.Time        `json:"applied_at"`
	Counts           map[string]int64 `json:"counts"`
}
type IdentitySyncState struct {
	DatabaseEpoch string     `json:"database_epoch"`
	Issuer        string     `json:"issuer"`
	Revision      int64      `json:"revision"`
	CapturedAt    *time.Time `json:"captured_at"`
	OperationID   *string    `json:"operation_id"`
}

func identityIssuerValid(issuer string) bool {
	u, err := url.Parse(issuer)
	if err != nil || issuer == "" || len(issuer) > 2048 || !utf8.ValidString(issuer) || strings.IndexFunc(issuer, unicode.IsControl) >= 0 || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	return u.Scheme == "https" || u.Scheme == "http" && (u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback())
}

func normalizeIdentitySnapshot(input IdentitySnapshot, epoch, issuer string) (IdentitySnapshot, string, error) {
	if !grantUUIDPattern.MatchString(epoch) || !identityIssuerValid(issuer) || input.DatabaseEpoch != epoch || input.Issuer != issuer || input.ExpectedRevision < 0 || input.ExpectedRevision >= 9007199254740991 || input.Revision != input.ExpectedRevision+1 || input.Organizations == nil || len(input.Organizations) > 256 {
		return IdentitySnapshot{}, "", ErrIdentitySnapshot
	}
	authority := RecoveryAuthority{Version: input.Version, Complete: input.Complete, RecoveryID: input.OperationID, DatabaseEpoch: input.DatabaseEpoch, Issuer: input.Issuer, CapturedAt: input.CapturedAt, ExpiresAt: input.ExpiresAt, Users: input.Users}
	if !authority.valid(epoch, issuer) {
		return IdentitySnapshot{}, "", ErrIdentitySnapshot
	}
	result := input
	result.CapturedAt = input.CapturedAt.UTC().Truncate(time.Microsecond)
	result.ExpiresAt = input.ExpiresAt.UTC().Truncate(time.Microsecond)
	if !result.ExpiresAt.After(result.CapturedAt) || result.ExpiresAt.Sub(result.CapturedAt) > 15*time.Minute {
		return IdentitySnapshot{}, "", ErrIdentitySnapshot
	}
	result.Organizations = append([]IdentityOrganization{}, input.Organizations...)
	orgs, slugs := map[string]bool{}, map[string]bool{}
	for _, org := range result.Organizations {
		if !grantUUIDPattern.MatchString(org.ID) || orgs[org.ID] || !identitySlug.MatchString(org.Slug) || slugs[org.Slug] || org.Name != strings.TrimSpace(org.Name) || len([]rune(org.Name)) < 1 || len([]rune(org.Name)) > 160 || !utf8.ValidString(org.Name) || strings.IndexFunc(org.Name, unicode.IsControl) >= 0 {
			return IdentitySnapshot{}, "", ErrIdentitySnapshot
		}
		orgs[org.ID] = true
		slugs[org.Slug] = true
	}
	sort.Slice(result.Organizations, func(i, j int) bool { return result.Organizations[i].ID < result.Organizations[j].ID })
	result.Users = make([]RecoveryUser, len(input.Users))
	for i, user := range input.Users {
		user.Memberships = append([]RecoveryMembership{}, user.Memberships...)
		for _, m := range user.Memberships {
			if !orgs[m.OrganizationID] {
				return IdentitySnapshot{}, "", ErrIdentitySnapshot
			}
		}
		sort.Slice(user.Memberships, func(i, j int) bool { return user.Memberships[i].OrganizationID < user.Memberships[j].OrganizationID })
		result.Users[i] = user
	}
	sort.Slice(result.Users, func(i, j int) bool { return result.Users[i].Subject < result.Users[j].Subject })
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > 8<<20 {
		return IdentitySnapshot{}, "", ErrIdentitySnapshot
	}
	defer clear(raw)
	digest := sha256.Sum256(raw)
	return result, hex.EncodeToString(digest[:]), nil
}

// ValidateIdentitySnapshot checks bounded structure and ownership before database access.
func ValidateIdentitySnapshot(input IdentitySnapshot, epoch, issuer string) error {
	_, _, err := normalizeIdentitySnapshot(input, epoch, issuer)
	return err
}

func readIdentitySyncRun(ctx context.Context, tx *sql.Tx, id string) (IdentitySyncRun, error) {
	var run IdentitySyncRun
	var counts []byte
	err := tx.QueryRowContext(ctx, `select id::text,database_epoch::text,issuer,expected_revision,revision,snapshot_sha256,captured_at,applied_at,counts from identity_sync_runs where id=$1`, id).Scan(&run.ID, &run.DatabaseEpoch, &run.Issuer, &run.ExpectedRevision, &run.Revision, &run.SnapshotSHA256, &run.CapturedAt, &run.AppliedAt, &counts)
	if errors.Is(err, sql.ErrNoRows) {
		return run, ErrIdentitySyncConflict
	}
	if err != nil {
		return run, transactionFailure(err)
	}
	if json.Unmarshal(counts, &run.Counts) != nil {
		return run, ErrDatabaseUnavailable
	}
	return run, nil
}

func (postgres *Postgres) IdentitySyncStatus(ctx context.Context, epoch, issuer string) (IdentitySyncState, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	state := IdentitySyncState{DatabaseEpoch: epoch, Issuer: issuer}
	if !grantUUIDPattern.MatchString(epoch) || !identityIssuerValid(issuer) {
		return state, ErrIdentitySnapshot
	}
	tx, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return state, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	// A read-only consistent snapshot cannot take the mutating recovery lock.
	recovery, err := recoveryState(ctx, tx, "")
	if err != nil {
		return state, err
	}
	if recovery.Epoch != epoch || recovery.Phase != "ready" {
		return state, ErrRecoveryUnavailable
	}
	err = tx.QueryRowContext(ctx, `select revision,captured_at,operation_id::text from identity_sync_sources where database_epoch=$1 and issuer=$2`, epoch, issuer).Scan(&state.Revision, &state.CapturedAt, &state.OperationID)
	if errors.Is(err, sql.ErrNoRows) {
		return state, nil
	}
	if err != nil {
		return state, ErrDatabaseUnavailable
	}
	return state, nil
}

// ApplyIdentitySnapshot is an explicit offline administrator operation. The input
// must come from the current trusted directory; this method does not authenticate its origin.
func (postgres *Postgres) ApplyIdentitySnapshot(ctx context.Context, epoch, issuer string, input IdentitySnapshot) (IdentitySyncRun, error) {
	snapshot, fingerprint, err := normalizeIdentitySnapshot(input, epoch, issuer)
	if err != nil {
		return IdentitySyncRun{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return retrySerializable(ctx, func() (IdentitySyncRun, error) { return postgres.applyIdentitySnapshotOnce(ctx, snapshot, fingerprint) })
}

func (postgres *Postgres) applyIdentitySnapshotOnce(ctx context.Context, input IdentitySnapshot, fingerprint string) (IdentitySyncRun, error) {
	// Existing registration uses READ COMMITTED with a shared user lock. Take
	// exclusive user locks and use fresh statement snapshots so a registration
	// that commits while we wait is also included in credential retirement.
	tx, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return IdentitySyncRun{}, transactionFailure(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `set local lock_timeout='2s'`); err != nil {
		return IdentitySyncRun{}, transactionFailure(err)
	}
	if _, err = lockRecoveryReady(ctx, tx, input.DatabaseEpoch); err != nil {
		return IdentitySyncRun{}, err
	}
	if prior, err := readIdentitySyncRun(ctx, tx, input.OperationID); err == nil {
		if prior.DatabaseEpoch != input.DatabaseEpoch || prior.Issuer != input.Issuer || prior.SnapshotSHA256 != fingerprint {
			return IdentitySyncRun{}, ErrIdentitySyncConflict
		}
		return prior, nil
	} else if !errors.Is(err, ErrIdentitySyncConflict) {
		return IdentitySyncRun{}, err
	}
	if _, err = tx.ExecContext(ctx, `insert into identity_sync_sources(database_epoch,issuer) values($1,$2) on conflict do nothing`, input.DatabaseEpoch, input.Issuer); err != nil {
		return IdentitySyncRun{}, transactionFailure(err)
	}
	var revision int64
	var captured *time.Time
	var now time.Time
	if err = tx.QueryRowContext(ctx, `select revision,captured_at,clock_timestamp() from identity_sync_sources where database_epoch=$1 and issuer=$2 for update`, input.DatabaseEpoch, input.Issuer).Scan(&revision, &captured, &now); err != nil {
		return IdentitySyncRun{}, transactionFailure(err)
	}
	// Another invocation of this exact operation may have committed while this
	// transaction waited to create or lock the source row.
	if prior, err := readIdentitySyncRun(ctx, tx, input.OperationID); err == nil {
		if prior.DatabaseEpoch != input.DatabaseEpoch || prior.Issuer != input.Issuer || prior.SnapshotSHA256 != fingerprint {
			return IdentitySyncRun{}, ErrIdentitySyncConflict
		}
		return prior, nil
	} else if !errors.Is(err, ErrIdentitySyncConflict) {
		return IdentitySyncRun{}, err
	}
	if revision != input.ExpectedRevision || captured != nil && input.CapturedAt.Before(*captured) {
		return IdentitySyncRun{}, ErrIdentitySyncConflict
	}
	if input.CapturedAt.After(now) || now.Sub(input.CapturedAt) > 15*time.Minute || !input.ExpiresAt.After(now) {
		return IdentitySyncRun{}, ErrIdentitySnapshot
	}
	locked, err := tx.QueryContext(ctx, `select id from users where issuer=$1 order by id for update /* identity_sync_user_fence */`, input.Issuer)
	if err != nil {
		return IdentitySyncRun{}, transactionFailure(err)
	}
	for locked.Next() {
		var id string
		if err = locked.Scan(&id); err != nil {
			locked.Close()
			return IdentitySyncRun{}, transactionFailure(err)
		}
	}
	err = locked.Err()
	locked.Close()
	if err != nil {
		return IdentitySyncRun{}, transactionFailure(err)
	}
	counts := map[string]int64{"snapshot_users": int64(len(input.Users)), "snapshot_organizations": int64(len(input.Organizations))}
	apply := func(name, query string, args ...any) error {
		result, e := tx.ExecContext(ctx, query, args...)
		if e != nil {
			return transactionFailure(e)
		}
		n, e := result.RowsAffected()
		if e != nil {
			return transactionFailure(e)
		}
		if name != "" {
			counts[name] = n
		}
		return nil
	}
	orgs, _ := json.Marshal(input.Organizations)
	users, _ := json.Marshal(input.Users)
	defer clear(orgs)
	defer clear(users)
	var conflict bool
	if err = tx.QueryRowContext(ctx, `select exists(select 1 from jsonb_to_recordset($1::jsonb) as s(organization_id uuid,slug text) join orgs o on o.id=s.organization_id or o.slug=s.slug where o.id<>s.organization_id or o.slug<>s.slug)`, string(orgs)).Scan(&conflict); err != nil {
		return IdentitySyncRun{}, transactionFailure(err)
	}
	if conflict {
		return IdentitySyncRun{}, ErrIdentitySyncConflict
	}
	if err = apply("organizations_changed", `insert into orgs(id,slug,name) select organization_id,slug,name from jsonb_to_recordset($1::jsonb) as s(organization_id uuid,slug text,name text) on conflict(id) do update set name=excluded.name where orgs.slug=excluded.slug and orgs.name is distinct from excluded.name`, string(orgs)); err != nil {
		return IdentitySyncRun{}, err
	}
	if err = tx.QueryRowContext(ctx, `select exists(select 1 from jsonb_to_recordset($1::jsonb) as s(organization_id uuid,slug text) join orgs o on o.id=s.organization_id where o.slug<>s.slug)`, string(orgs)).Scan(&conflict); err != nil {
		return IdentitySyncRun{}, transactionFailure(err)
	}
	if conflict {
		return IdentitySyncRun{}, ErrIdentitySyncConflict
	}
	for _, query := range []string{
		`create temporary table remote_identity_input(subject text primary key,status text not null,memberships jsonb not null) on commit drop`,
		`create temporary table remote_identity_members(user_id uuid not null,org_id uuid not null,role text not null,primary key(user_id,org_id)) on commit drop`,
		`create temporary table remote_identity_lost(user_id uuid not null,org_id uuid not null,primary key(user_id,org_id)) on commit drop`,
		`create temporary table remote_identity_installations(id uuid primary key) on commit drop`,
		`create temporary table remote_identity_devices(id uuid primary key) on commit drop`,
		`create temporary table remote_identity_grants(runtime_id uuid,user_id uuid,org_id uuid,grant_version bigint) on commit drop`,
		`create temporary table remote_identity_user_changes(id uuid primary key,previous_status text,current_status text) on commit drop`,
		`create temporary table remote_identity_membership_changes(user_id uuid,org_id uuid,previous_role text,next_role text) on commit drop`,
		`create temporary table remote_identity_retired_installations(id uuid primary key,org_id uuid) on commit drop`,
	} {
		if err = apply("", query); err != nil {
			return IdentitySyncRun{}, err
		}
	}
	if err = apply("", `insert into pg_temp.remote_identity_input select subject,status,memberships from jsonb_to_recordset($1::jsonb) as s(subject text,status text,memberships jsonb)`, string(users)); err != nil {
		return IdentitySyncRun{}, err
	}
	if err = tx.QueryRowContext(ctx, `select exists(select 1 from users u join pg_temp.remote_identity_input s on s.subject=u.subject where u.issuer=$1 and u.status='deleted' and s.status<>'deleted')`, input.Issuer).Scan(&conflict); err != nil {
		return IdentitySyncRun{}, transactionFailure(err)
	}
	if conflict {
		return IdentitySyncRun{}, ErrIdentitySyncConflict
	}
	if err = apply("users_created", `with created as(insert into users(issuer,subject,status) select $1,subject,status from pg_temp.remote_identity_input order by subject on conflict(issuer,subject) do nothing returning id,status) insert into pg_temp.remote_identity_user_changes select id,null,status from created`, input.Issuer); err != nil {
		return IdentitySyncRun{}, err
	}
	if err = apply("users_changed", `with desired as materialized(select u.id,u.status previous_status,coalesce(s.status,case when u.status='deleted' then 'deleted' else 'suspended' end) current_status from users u left join pg_temp.remote_identity_input s on s.subject=u.subject where u.issuer=$1), changed as(update users u set status=d.current_status from desired d where u.id=d.id and u.status is distinct from d.current_status returning u.id,d.previous_status,u.status) insert into pg_temp.remote_identity_user_changes select * from changed`, input.Issuer); err != nil {
		return IdentitySyncRun{}, err
	}
	if err = apply("", `insert into pg_temp.remote_identity_members select u.id,m.organization_id,m.role from pg_temp.remote_identity_input s join users u on u.issuer=$1 and u.subject=s.subject cross join lateral jsonb_to_recordset(s.memberships) as m(organization_id uuid,role text)`, input.Issuer); err != nil {
		return IdentitySyncRun{}, err
	}
	if err = apply("", `insert into pg_temp.remote_identity_lost select m.user_id,m.org_id from org_memberships m join users u on u.id=m.user_id and u.issuer=$1 left join pg_temp.remote_identity_members wanted on wanted.user_id=m.user_id and wanted.org_id=m.org_id where wanted.user_id is null or m.role='admin' and wanted.role<>'admin'`, input.Issuer); err != nil {
		return IdentitySyncRun{}, err
	}
	if err = apply("", `insert into pg_temp.remote_identity_membership_changes select m.user_id,m.org_id,m.role,wanted.role from org_memberships m join users u on u.id=m.user_id and u.issuer=$1 left join pg_temp.remote_identity_members wanted on wanted.user_id=m.user_id and wanted.org_id=m.org_id where m.role is distinct from wanted.role union all select wanted.user_id,wanted.org_id,null,wanted.role from pg_temp.remote_identity_members wanted left join org_memberships m on m.user_id=wanted.user_id and m.org_id=wanted.org_id where m.user_id is null`, input.Issuer); err != nil {
		return IdentitySyncRun{}, err
	}
	if err = apply("", `insert into pg_temp.remote_identity_installations select i.id from installations i join users u on u.id=i.owner_user_id and u.issuer=$1 join hosts h on h.id=i.host_id where u.status<>'active' or not exists(select 1 from pg_temp.remote_identity_members m where m.user_id=u.id and m.org_id=h.org_id)`, input.Issuer); err != nil {
		return IdentitySyncRun{}, err
	}
	if err = apply("devices_revoked", `with changed as(update devices d set revoked_at=clock_timestamp() from users u where u.id=d.user_id and u.issuer=$1 and u.status<>'active' and d.revoked_at is null returning d.id) insert into pg_temp.remote_identity_devices select id from changed`, input.Issuer); err != nil {
		return IdentitySyncRun{}, err
	}
	if err = apply("installations_revoked", `with changed as(update installations i set revoked_at=clock_timestamp() from hosts h where i.host_id=h.id and i.id in(select id from pg_temp.remote_identity_installations) and i.revoked_at is null returning i.id,h.org_id) insert into pg_temp.remote_identity_retired_installations select * from changed`); err != nil {
		return IdentitySyncRun{}, err
	}
	if err = apply("grants_revoked", `with changed as(update runtime_grants g set revoked_at=clock_timestamp(),grant_version=g.grant_version+1 from runtimes r join installations i on i.id=r.installation_id join hosts h on h.id=i.host_id where g.runtime_id=r.id and g.revoked_at is null and (i.id in(select id from pg_temp.remote_identity_installations) or exists(select 1 from users u where u.id=g.user_id and u.issuer=$1 and u.status<>'active') or exists(select 1 from pg_temp.remote_identity_lost lost where lost.user_id=g.user_id and lost.org_id=h.org_id)) returning g.runtime_id,g.user_id,h.org_id,g.grant_version) insert into pg_temp.remote_identity_grants select * from changed`, input.Issuer); err != nil {
		return IdentitySyncRun{}, err
	}
	for _, operation := range []struct{ name, query string }{
		{"credentials_revoked", `update host_connection_credentials set revoked_at=clock_timestamp() where revoked_at is null and installation_id in(select id from pg_temp.remote_identity_installations)`},
		{"challenges_consumed", `update installation_challenges set consumed_at=clock_timestamp() where consumed_at is null and installation_id in(select id from pg_temp.remote_identity_installations)`},
		{"tickets_consumed", `update realtime_tickets t set consumed_at=clock_timestamp() where consumed_at is null and (device_id in(select id from pg_temp.remote_identity_devices) or exists(select 1 from pg_temp.remote_identity_grants g where g.runtime_id=t.runtime_id and g.user_id=t.user_id))`},
		{"device_events", `insert into control_outbox(topic,payload) select 'device.revoked',jsonb_build_object('device_id',id::text) from pg_temp.remote_identity_devices`},
		{"approval_events", `insert into control_outbox(org_id,topic,payload) select distinct h.org_id,'approval.device.revoked',jsonb_build_object('runtime_id',a.runtime_id::text,'device_id',a.decided_device_id::text) from approvals a join runtimes r on r.id=a.runtime_id join installations i on i.id=r.installation_id join hosts h on h.id=i.host_id where a.metadata_version=1 and a.decided_device_id in(select id from pg_temp.remote_identity_devices) and a.decision='allow_once' and a.state='decision_received' and a.expires_at>clock_timestamp() and a.decision_expires_at>clock_timestamp()`},
		{"grant_events", `insert into control_outbox(org_id,topic,payload) select org_id,'runtime_grant.revoked',jsonb_build_object('runtime_id',runtime_id::text,'user_id',user_id::text,'grant_version',grant_version) from pg_temp.remote_identity_grants`},
		{"runtime_events", `insert into control_outbox(org_id,topic,payload) select retired.org_id,'runtime.revoked',jsonb_build_object('runtime_id',r.id::text) from runtimes r join pg_temp.remote_identity_retired_installations retired on retired.id=r.installation_id`},
	} {
		if err = apply(operation.name, operation.query); err != nil {
			return IdentitySyncRun{}, err
		}
	}
	if err = apply("memberships_removed", `delete from org_memberships m using users u where u.id=m.user_id and u.issuer=$1 and not exists(select 1 from pg_temp.remote_identity_members wanted where wanted.user_id=m.user_id and wanted.org_id=m.org_id)`, input.Issuer); err != nil {
		return IdentitySyncRun{}, err
	}
	if err = apply("memberships_written", `insert into org_memberships(org_id,user_id,role) select org_id,user_id,role from pg_temp.remote_identity_members on conflict(org_id,user_id) do update set role=excluded.role where org_memberships.role is distinct from excluded.role`); err != nil {
		return IdentitySyncRun{}, err
	}
	if err = apply("enrollments_cancelled", `update enrollments e set state='cancelled',decided_at=clock_timestamp() from hosts h where h.id=e.host_id and e.state in('pending','user_confirmed') and (e.installation_id in(select id from pg_temp.remote_identity_installations) or exists(select 1 from users u where u.issuer=$1 and u.id=e.user_confirmed_by and (u.status<>'active' or not exists(select 1 from pg_temp.remote_identity_members m where m.user_id=u.id and m.org_id=h.org_id))))`, input.Issuer); err != nil {
		return IdentitySyncRun{}, err
	}
	for _, operation := range []struct{ name, query string }{
		{"user_audits", `insert into audit_log(actor_type,actor_id,action,result,metadata) select 'system',$1::text,'identity.user','success',jsonb_build_object('operation_id',$1::text,'user_id',id::text,'previous_status',previous_status,'status',current_status) from pg_temp.remote_identity_user_changes`},
		{"membership_audits", `insert into audit_log(org_id,actor_type,actor_id,action,result,metadata) select org_id,'system',$1::text,'identity.membership','success',jsonb_build_object('operation_id',$1::text,'user_id',user_id::text,'previous_role',previous_role,'role',next_role) from pg_temp.remote_identity_membership_changes`},
		{"device_audits", `insert into audit_log(actor_type,actor_id,device_id,action,result,metadata) select 'system',$1::text,id,'device.revoke','success',jsonb_build_object('operation_id',$1::text,'device_id',id::text) from pg_temp.remote_identity_devices`},
		{"installation_audits", `insert into audit_log(org_id,actor_type,actor_id,action,result,metadata) select org_id,'system',$1::text,'installation.revoke','success',jsonb_build_object('operation_id',$1::text,'installation_id',id::text) from pg_temp.remote_identity_retired_installations`},
		{"grant_audits", `insert into audit_log(org_id,actor_type,actor_id,runtime_id,action,result,metadata) select org_id,'system',$1::text,runtime_id,'runtime_grant.revoke','success',jsonb_build_object('operation_id',$1::text,'runtime_id',runtime_id::text,'user_id',user_id::text,'grant_version',grant_version) from pg_temp.remote_identity_grants`},
	} {
		if err = apply(operation.name, operation.query, input.OperationID); err != nil {
			return IdentitySyncRun{}, err
		}
	}
	if err = tx.QueryRowContext(ctx, `select clock_timestamp()`).Scan(&now); err != nil {
		return IdentitySyncRun{}, transactionFailure(err)
	}
	if !input.ExpiresAt.After(now) {
		return IdentitySyncRun{}, ErrIdentitySnapshot
	}
	countJSON, _ := json.Marshal(counts)
	if err = apply("", `insert into identity_sync_runs(id,database_epoch,issuer,expected_revision,revision,snapshot_sha256,captured_at,counts) values($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`, input.OperationID, input.DatabaseEpoch, input.Issuer, input.ExpectedRevision, input.Revision, fingerprint, input.CapturedAt, string(countJSON)); err != nil {
		return IdentitySyncRun{}, err
	}
	if err = apply("", `update identity_sync_sources set revision=$3,captured_at=$4,operation_id=$5 where database_epoch=$1 and issuer=$2`, input.DatabaseEpoch, input.Issuer, input.Revision, input.CapturedAt, input.OperationID); err != nil {
		return IdentitySyncRun{}, err
	}
	if err = recoveryAudit(ctx, tx, input.OperationID, "identity.sync", map[string]any{"operation_id": input.OperationID, "revision": input.Revision, "snapshot_sha256": fingerprint, "counts": counts}); err != nil {
		return IdentitySyncRun{}, err
	}
	run, err := readIdentitySyncRun(ctx, tx, input.OperationID)
	if err != nil {
		return run, err
	}
	if err = tx.Commit(); err != nil {
		return IdentitySyncRun{}, transactionFailure(err)
	}
	return run, nil
}
