package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
)

// These read-only inspections select a destination. They never consume a
// credential or grant business authority; the owner repeats full admission.
func (postgres *Postgres) ApprovalRuntimeForRouting(ctx context.Context, identity UserIdentity, jkt, id string) (string, error) {
	if !grantUUIDPattern.MatchString(id) || !auth.ValidProofThumbprint(jkt) {
		return "", ErrAccessDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var runtime, session string
	var workspace sql.NullString
	var raw []byte
	err := postgres.DB.QueryRowContext(ctx, `select a.runtime_id::text,a.session_id::text,a.workspace_id::text,g.scope
        from approvals a join runtimes r on r.id=a.runtime_id and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+`
        join installations i on i.id=r.installation_id and i.revoked_at is null
        join hosts h on h.id=i.host_id and h.state='active'
        join users u on u.issuer=$1 and u.subject=$2 and u.status='active'
        join org_memberships m on m.org_id=h.org_id and m.user_id=u.id
        join devices d on d.user_id=u.id and d.proof_key_thumbprint=$3 and d.revoked_at is null
        join runtime_grants g on g.runtime_id=r.id and g.user_id=u.id and g.role='owner' and g.revoked_at is null
            and (g.expires_at is null or g.expires_at>clock_timestamp())
        where a.id=$4 and a.metadata_version=1`, identity.Issuer, identity.Subject, jkt, id).Scan(&runtime, &session, &workspace, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrAccessDenied
	}
	if err != nil {
		return "", ErrDatabaseUnavailable
	}
	var scope GrantScope
	if json.Unmarshal(raw, &scope) != nil {
		return "", ErrDatabaseUnavailable
	}
	if !slices.Contains(scope.Actions, "approval.decide") || !slices.Contains(scope.Actions, "session.read") || !scopeIncludesSession(scope, session, workspace) {
		return "", ErrAccessDenied
	}
	return runtime, nil
}

type HostFileRouteInspection struct {
	Expected  auth.FileReadExpectation
	PublicJWK []byte
}

func (postgres *Postgres) HostFileForRouting(ctx context.Context, id, token string) (HostFileRouteInspection, error) {
	if !grantUUIDPattern.MatchString(id) || len(token) != 43 {
		return HostFileRouteInspection{}, ErrAccessDenied
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != 32 {
		return HostFileRouteInspection{}, ErrAccessDenied
	}
	clear(decoded)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	digest := sha256.Sum256([]byte(token))
	inspection := HostFileRouteInspection{}
	expected := &inspection.Expected
	err = postgres.DB.QueryRowContext(ctx, `select handoff.installation_id::text,i.public_key_thumbprint,i.public_jwk,
        handoff.runtime_id::text,handoff.runtime_epoch::text,handoff.connection_id::text,handoff.file_id::text
        from file_handoffs handoff join runtimes r on r.id=handoff.runtime_id and r.epoch=handoff.runtime_epoch and r.connection_id=handoff.connection_id
            and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+`
        join installations i on i.id=r.installation_id and i.id=handoff.installation_id and i.revoked_at is null
            and i.key_version=handoff.installation_key_version and r.connection_key_version=i.key_version
        join hosts h on h.id=i.host_id and h.state='active'
        where handoff.id=$1 and handoff.token_sha256=$2 and handoff.state='offered' and handoff.read_started_at is null
            and handoff.lease_until>clock_timestamp() and handoff.expires_at>clock_timestamp() and handoff.credential_expires_at>clock_timestamp()`, id, digest[:]).Scan(&expected.InstallationID, &expected.KeyThumbprint, &inspection.PublicJWK, &expected.RuntimeID, &expected.RuntimeEpoch, &expected.ConnectionID, &expected.FileID)
	if errors.Is(err, sql.ErrNoRows) {
		return HostFileRouteInspection{}, ErrAccessDenied
	}
	if err != nil {
		return HostFileRouteInspection{}, ErrDatabaseUnavailable
	}
	expected.HandoffID, expected.Token = id, token
	return inspection, nil
}
