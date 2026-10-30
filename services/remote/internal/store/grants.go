package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"time"
)

var ErrAccessDenied = errors.New("store: grant access denied")
var ErrGrantInvalid = errors.New("store: invalid runtime grant")
var ErrGrantNotFound = errors.New("store: runtime grant not found")

var grantUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type GrantScope struct {
	Actions    []string `json:"actions"`
	Workspaces []string `json:"workspaces"`
	Sessions   []string `json:"sessions"`
}

type RuntimeGrantInput struct {
	Role      string     `json:"role"`
	Scope     GrantScope `json:"scope"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

var roleActions = map[string]map[string]struct{}{
	"viewer": actionSet("host.list", "session.list", "session.read", "command.status"),
	"operator": actionSet(
		"host.list", "session.list", "session.read", "command.status", "session.create", "message.submit",
		"session.cancel", "session.archive", "approval.decide", "question.answer", "file.upload", "file.download",
	),
	"owner": actionSet(
		"host.list", "session.list", "session.read", "command.status", "session.create", "message.submit",
		"session.cancel", "session.archive", "approval.decide", "question.answer", "file.upload", "file.download", "grant.manage",
	),
}

func actionSet(actions ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(actions))
	for _, action := range actions {
		set[action] = struct{}{}
	}
	return set
}

func NormalizeRuntimeGrantInput(input RuntimeGrantInput, now time.Time) (RuntimeGrantInput, error) {
	allowedActions, roleExists := roleActions[input.Role]
	if !roleExists {
		return RuntimeGrantInput{}, ErrGrantInvalid
	}
	if input.ExpiresAt != nil {
		expires := input.ExpiresAt.UTC().Truncate(time.Microsecond)
		if !expires.After(now) {
			return RuntimeGrantInput{}, ErrGrantInvalid
		}
		input.ExpiresAt = &expires
	}
	if len(input.Scope.Actions) > len(allowedActions) || len(input.Scope.Workspaces) > 256 || len(input.Scope.Sessions) > 256 {
		return RuntimeGrantInput{}, ErrGrantInvalid
	}
	var err error
	input.Scope.Actions, err = normalizeStrings(input.Scope.Actions, false)
	if err != nil {
		return RuntimeGrantInput{}, err
	}
	input.Scope.Workspaces, err = normalizeStrings(input.Scope.Workspaces, true)
	if err != nil {
		return RuntimeGrantInput{}, err
	}
	input.Scope.Sessions, err = normalizeStrings(input.Scope.Sessions, true)
	if err != nil {
		return RuntimeGrantInput{}, err
	}
	for _, action := range input.Scope.Actions {
		if _, ok := allowedActions[action]; !ok {
			return RuntimeGrantInput{}, ErrGrantInvalid
		}
	}
	if input.Role == "owner" && !slices.Contains(input.Scope.Actions, "grant.manage") {
		return RuntimeGrantInput{}, ErrGrantInvalid
	}
	return input, nil
}

func NormalizeTicketScope(role string, scope GrantScope) (GrantScope, error) {
	allowedActions, ok := roleActions[role]
	if !ok {
		return GrantScope{}, ErrGrantInvalid
	}
	if role == "owner" {
		allowedActions = actionSet(
			"host.list", "session.list", "session.read", "command.status", "session.create", "message.submit",
			"session.cancel", "session.archive", "approval.decide", "question.answer", "file.upload", "file.download",
		)
	}
	if len(scope.Actions) == 0 || len(scope.Actions) > len(allowedActions) || len(scope.Workspaces) > 256 || len(scope.Sessions) > 256 {
		return GrantScope{}, ErrGrantInvalid
	}
	var err error
	scope.Actions, err = normalizeStrings(scope.Actions, false)
	if err != nil {
		return GrantScope{}, err
	}
	scope.Workspaces, err = normalizeStrings(scope.Workspaces, true)
	if err != nil {
		return GrantScope{}, err
	}
	scope.Sessions, err = normalizeStrings(scope.Sessions, true)
	if err != nil {
		return GrantScope{}, err
	}
	for _, action := range scope.Actions {
		if _, ok := allowedActions[action]; !ok {
			return GrantScope{}, ErrGrantInvalid
		}
	}
	return scope, nil
}

func normalizeStrings(values []string, uuidValues bool) ([]string, error) {
	if len(values) == 0 {
		return []string{}, nil
	}
	result := append([]string(nil), values...)
	for _, value := range result {
		if value == "" || uuidValues && !grantUUIDPattern.MatchString(value) {
			return nil, ErrGrantInvalid
		}
	}
	sort.Strings(result)
	for index := 1; index < len(result); index++ {
		if result[index] == result[index-1] {
			return nil, ErrGrantInvalid
		}
	}
	return result, nil
}

func grantScopeSubset(candidate, parent GrantScope) bool {
	return stringSliceSubset(candidate.Actions, parent.Actions) &&
		stringSliceSubset(candidate.Workspaces, parent.Workspaces) &&
		stringSliceSubset(candidate.Sessions, parent.Sessions)
}

func stringSliceSubset(candidate, parent []string) bool {
	allowed := make(map[string]struct{}, len(parent))
	for _, value := range parent {
		allowed[value] = struct{}{}
	}
	for _, value := range candidate {
		if _, ok := allowed[value]; !ok {
			return false
		}
	}
	return true
}

func validGrantActor(deviceID, proofJKT, runtimeID, targetUserID string) bool {
	return grantUUIDPattern.MatchString(deviceID) && keyThumbprintPattern.MatchString(proofJKT) &&
		grantUUIDPattern.MatchString(runtimeID) && grantUUIDPattern.MatchString(targetUserID)
}

func (postgres *Postgres) PutRuntimeGrant(ctx context.Context, identity UserIdentity, deviceID, proofJKT, runtimeID, targetUserID string, input RuntimeGrantInput) (int64, error) {
	if !validGrantActor(deviceID, proofJKT, runtimeID, targetUserID) {
		return 0, ErrGrantInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return retrySerializable(ctx, func() (int64, error) {
		return postgres.putRuntimeGrantOnce(ctx, identity, deviceID, proofJKT, runtimeID, targetUserID, input)
	})
}

func (postgres *Postgres) putRuntimeGrantOnce(ctx context.Context, identity UserIdentity, deviceID, proofJKT, runtimeID, targetUserID string, input RuntimeGrantInput) (int64, error) {
	input, err := NormalizeRuntimeGrantInput(input, time.Now())
	if err != nil {
		return 0, err
	}
	transaction, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return 0, transactionFailure(err)
	}
	defer transaction.Rollback()

	actorID, orgID, actorRole, actorScope, isAdmin, err := postgres.authorizeGrantManager(ctx, transaction, identity, deviceID, proofJKT, runtimeID)
	if err != nil {
		return 0, err
	}
	if input.Role == "owner" && !isAdmin {
		return 0, ErrAccessDenied
	}
	if actorRole != "owner" && !isAdmin {
		return 0, ErrAccessDenied
	}
	if !isAdmin && !grantScopeSubset(input.Scope, actorScope) {
		return 0, ErrAccessDenied
	}
	targetID, err := activeOrganizationUser(ctx, transaction, orgID, targetUserID)
	if err != nil {
		return 0, err
	}
	if err := validateGrantResources(ctx, transaction, runtimeID, input.Scope); err != nil {
		return 0, err
	}

	var previousRole string
	var previousScopeJSON []byte
	var previousVersion int64
	var previousExpiry, previousRevoked sql.NullTime
	err = transaction.QueryRowContext(ctx, `
		select role, scope, grant_version, expires_at, revoked_at
		from runtime_grants where runtime_id = $1 and user_id = $2 for update`, runtimeID, targetID).
		Scan(&previousRole, &previousScopeJSON, &previousVersion, &previousExpiry, &previousRevoked)
	hasPrevious := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, transactionFailure(err)
	}
	if hasPrevious && previousRole == "owner" && previousRevoked.Valid == false &&
		(!previousExpiry.Valid || previousExpiry.Time.After(time.Now())) &&
		(input.Role != "owner" || input.ExpiresAt != nil) {
		remaining, err := countOtherActiveOwners(ctx, transaction, runtimeID, orgID, targetID)
		if err != nil {
			return 0, transactionFailure(err)
		}
		if remaining == 0 && !isAdmin {
			return 0, ErrAccessDenied
		}
	}

	scopeJSON, err := json.Marshal(input.Scope)
	if err != nil {
		return 0, ErrGrantInvalid
	}
	if hasPrevious && previousRevoked.Valid == false && previousRole == input.Role &&
		grantExpiryEqual(previousExpiry, input.ExpiresAt) && grantScopeEqual(previousScopeJSON, input.Scope) {
		if err := transaction.Commit(); err != nil {
			return 0, transactionFailure(err)
		}
		return previousVersion, nil
	}
	version := int64(1)
	if hasPrevious {
		version = previousVersion + 1
	}
	if _, err := transaction.ExecContext(ctx, `
		insert into runtime_grants (runtime_id, user_id, role, scope, grant_version, granted_by, expires_at, revoked_at)
		values ($1, $2, $3, $4::jsonb, $5, $6, $7, null)
		on conflict (runtime_id, user_id) do update set
			role = excluded.role, scope = excluded.scope, grant_version = excluded.grant_version,
			granted_by = excluded.granted_by, expires_at = excluded.expires_at, revoked_at = null`,
		runtimeID, targetID, input.Role, string(scopeJSON), version, actorID, input.ExpiresAt); err != nil {
		return 0, transactionFailure(err)
	}
	if err := writeGrantChange(ctx, transaction, actorID, deviceID, orgID, runtimeID, targetID, input.Role,
		version, input.ExpiresAt, "runtime_grant.updated", "runtime_grant.update", scopeJSON); err != nil {
		return 0, transactionFailure(err)
	}
	if err := transaction.Commit(); err != nil {
		return 0, transactionFailure(err)
	}
	return version, nil
}

func (postgres *Postgres) RevokeRuntimeGrant(ctx context.Context, identity UserIdentity, deviceID, proofJKT, runtimeID, targetUserID string) (int64, error) {
	if !validGrantActor(deviceID, proofJKT, runtimeID, targetUserID) {
		return 0, ErrGrantInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return retrySerializable(ctx, func() (int64, error) {
		return postgres.revokeRuntimeGrantOnce(ctx, identity, deviceID, proofJKT, runtimeID, targetUserID)
	})
}

func (postgres *Postgres) revokeRuntimeGrantOnce(ctx context.Context, identity UserIdentity, deviceID, proofJKT, runtimeID, targetUserID string) (int64, error) {
	transaction, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return 0, transactionFailure(err)
	}
	defer transaction.Rollback()
	actorID, orgID, actorRole, _, isAdmin, err := postgres.authorizeGrantManager(ctx, transaction, identity, deviceID, proofJKT, runtimeID)
	if err != nil {
		return 0, err
	}
	if actorRole != "owner" && !isAdmin {
		return 0, ErrAccessDenied
	}
	var role string
	var version int64
	var revoked, expires sql.NullTime
	err = transaction.QueryRowContext(ctx, `
		select role, grant_version, revoked_at, expires_at
		from runtime_grants where runtime_id = $1 and user_id = $2 for update`, runtimeID, targetUserID).
		Scan(&role, &version, &revoked, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrGrantNotFound
	}
	if err != nil {
		return 0, transactionFailure(err)
	}
	if revoked.Valid {
		if err := transaction.Commit(); err != nil {
			return 0, transactionFailure(err)
		}
		return version, nil
	}
	if role == "owner" && (!expires.Valid || expires.Time.After(time.Now())) && !isAdmin {
		remaining, err := countOtherActiveOwners(ctx, transaction, runtimeID, orgID, targetUserID)
		if err != nil {
			return 0, transactionFailure(err)
		}
		if remaining == 0 {
			return 0, ErrAccessDenied
		}
	}
	version++
	if _, err := transaction.ExecContext(ctx, `
		update runtime_grants set revoked_at = now(), grant_version = $3
		where runtime_id = $1 and user_id = $2 and revoked_at is null`, runtimeID, targetUserID, version); err != nil {
		return 0, transactionFailure(err)
	}
	metadata, _ := json.Marshal(map[string]any{"runtime_id": runtimeID, "user_id": targetUserID, "grant_version": version})
	if _, err := transaction.ExecContext(ctx, `
		insert into control_outbox (org_id, topic, payload) values ($1, 'runtime_grant.revoked', $2::jsonb)`, orgID, string(metadata)); err != nil {
		return 0, transactionFailure(err)
	}
	if _, err := transaction.ExecContext(ctx, `
		insert into audit_log (org_id, actor_type, actor_id, device_id, runtime_id, action, result, metadata)
		values ($1, 'user', $2, $3, $4, 'runtime_grant.revoke', 'success', $5::jsonb)`,
		orgID, actorID, deviceID, runtimeID, string(metadata)); err != nil {
		return 0, transactionFailure(err)
	}
	if err := transaction.Commit(); err != nil {
		return 0, transactionFailure(err)
	}
	return version, nil
}

func (postgres *Postgres) authorizeGrantManager(ctx context.Context, tx *sql.Tx, identity UserIdentity, deviceID, proofJKT, runtimeID string) (actorID, orgID, role string, scope GrantScope, isAdmin bool, err error) {
	if _, err = tx.ExecContext(ctx, `set local lock_timeout='2s'`); err != nil {
		return "", "", "", GrantScope{}, false, transactionFailure(err)
	}
	if _, err = lockRecoveryReady(ctx, tx, ""); err != nil {
		return "", "", "", GrantScope{}, false, err
	}
	actorID, err = postgres.userIDForSerializable(ctx, tx, identity.Issuer, identity.Subject)
	if err != nil {
		return "", "", "", GrantScope{}, false, err
	}
	var current string
	err = tx.QueryRowContext(ctx, `select id::text from devices
	 where id=$1 and user_id=$2 and proof_key_thumbprint=$3 and revoked_at is null
	 for share /* grant_actor_device_fence */`, deviceID, actorID, proofJKT).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", GrantScope{}, false, ErrAccessDenied
	}
	if err != nil {
		return "", "", "", GrantScope{}, false, transactionFailure(err)
	}
	err = tx.QueryRowContext(ctx, `
		select h.org_id::text from runtimes r
		join installations i on i.id = r.installation_id and i.revoked_at is null
		join hosts h on h.id = i.host_id and h.state = 'active'
		where r.id = $1 and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+`
		for share of r, i, h`, runtimeID).Scan(&orgID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", GrantScope{}, false, ErrAccessDenied
	}
	if err != nil {
		return "", "", "", GrantScope{}, false, transactionFailure(err)
	}
	var membershipRole string
	err = tx.QueryRowContext(ctx, `
		select role from org_memberships where org_id = $1 and user_id = $2 for share`, orgID, actorID).Scan(&membershipRole)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", GrantScope{}, false, ErrAccessDenied
	}
	if err != nil {
		return "", "", "", GrantScope{}, false, transactionFailure(err)
	}
	isAdmin = membershipRole == "admin"
	var scopeJSON []byte
	err = tx.QueryRowContext(ctx, `
		select role, scope from runtime_grants
		where runtime_id = $1 and user_id = $2 and revoked_at is null
		  and (expires_at is null or expires_at > now())
		for update`, runtimeID, actorID).Scan(&role, &scopeJSON)
	if errors.Is(err, sql.ErrNoRows) {
		role = ""
	} else if err != nil {
		return "", "", "", GrantScope{}, false, transactionFailure(err)
	} else if err := json.Unmarshal(scopeJSON, &scope); err != nil {
		return "", "", "", GrantScope{}, false, transactionFailure(err)
	}
	if role == "owner" && !slices.Contains(scope.Actions, "grant.manage") {
		role = ""
	}
	if role != "owner" && !isAdmin {
		return "", "", "", GrantScope{}, false, ErrAccessDenied
	}
	return actorID, orgID, role, scope, isAdmin, nil
}

func activeOrganizationUser(ctx context.Context, tx *sql.Tx, orgID, userID string) (string, error) {
	var id string
	err := tx.QueryRowContext(ctx, `
		select u.id::text from users u
		join org_memberships m on m.user_id = u.id and m.org_id = $1
		where u.id = $2 and u.status = 'active'
		for share of u, m`, orgID, userID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrAccessDenied
	}
	if err != nil {
		return "", transactionFailure(err)
	}
	return id, nil
}

func validateGrantResources(ctx context.Context, tx *sql.Tx, runtimeID string, scope GrantScope) error {
	for _, resource := range []struct {
		table string
		ids   []string
	}{{table: "workspaces", ids: scope.Workspaces}, {table: "sessions", ids: scope.Sessions}} {
		if len(resource.ids) == 0 {
			continue
		}
		var count int
		query := "select count(*) from " + resource.table + " where runtime_id = $1 and id::text = any($2::text[])"
		if err := tx.QueryRowContext(ctx, query, runtimeID, resource.ids).Scan(&count); err != nil {
			return transactionFailure(err)
		}
		if count != len(resource.ids) {
			return ErrGrantInvalid
		}
	}
	return nil
}

func countOtherActiveOwners(ctx context.Context, tx *sql.Tx, runtimeID, orgID, excludedUserID string) (int, error) {
	var count int
	err := tx.QueryRowContext(ctx, `
		select count(*) from runtime_grants g
		join users u on u.id = g.user_id and u.status = 'active'
		join org_memberships m on m.user_id = u.id and m.org_id = $2
		where g.runtime_id = $1 and g.user_id <> $3 and g.role = 'owner'
		  and g.scope->'actions' ? 'grant.manage'
		  and g.revoked_at is null and (g.expires_at is null or g.expires_at > now())`, runtimeID, orgID, excludedUserID).Scan(&count)
	return count, err
}

func grantExpiryEqual(previous sql.NullTime, next *time.Time) bool {
	if next == nil {
		return !previous.Valid
	}
	return previous.Valid && previous.Time.Equal(*next)
}

func grantScopeEqual(previousJSON []byte, next GrantScope) bool {
	var previous GrantScope
	if json.Unmarshal(previousJSON, &previous) != nil {
		return false
	}
	return reflect.DeepEqual(previous, next)
}

func writeGrantChange(ctx context.Context, tx *sql.Tx, actorID, deviceID, orgID, runtimeID, targetUserID, role string, version int64, expiresAt *time.Time, topic, action string, scopeJSON []byte) error {
	payload, err := json.Marshal(map[string]any{
		"runtime_id": runtimeID, "user_id": targetUserID, "grant_version": version,
		"role": role, "scope": json.RawMessage(scopeJSON), "expires_at": expiresAt,
	})
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		insert into control_outbox (org_id, topic, payload) values ($1, $2, $3::jsonb)`, orgID, topic, string(payload)); err != nil {
		return err
	}
	metadata, err := json.Marshal(map[string]any{
		"runtime_id": runtimeID, "user_id": targetUserID, "grant_version": version,
		"role": role, "scope": json.RawMessage(scopeJSON), "expires_at": expiresAt,
	})
	if err != nil {
		return err
	}
	var actorDeviceID any
	if deviceID != "" {
		actorDeviceID = deviceID
	}
	_, err = tx.ExecContext(ctx, `
		insert into audit_log (org_id, actor_type, actor_id, device_id, runtime_id, action, result, metadata)
		values ($1, 'user', $2, $3, $4, $5, 'success', $6::jsonb)`,
		orgID, actorID, actorDeviceID, runtimeID, action, string(metadata))
	return err
}
