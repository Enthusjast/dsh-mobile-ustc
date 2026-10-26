package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// This read is part of the caller's own question-answer workflow. It cannot
// substitute for generic command.status or classify an old digest by guessing.
func (postgres *Postgres) QuestionAnswerStatus(ctx context.Context, identity UserIdentity, device, proof, runtime, session, request string, until time.Time) (CommandStatus, error) {
	var result CommandStatus
	for _, id := range []string{device, runtime, session, request} {
		if !grantUUIDPattern.MatchString(id) {
			return result, ErrAccessDenied
		}
	}
	err := postgres.DB.QueryRowContext(ctx, `select c.request_id::text,c.session_id::text,c.state,c.payload_sha256,c.updated_at
	 from users u join devices d on d.user_id=u.id and d.id=$3 and d.revoked_at is null and d.proof_key_thumbprint=$4
	 join commands c on c.user_id=u.id and c.device_id=d.id and c.request_id=$7 and c.runtime_id=$5 and c.session_id=$6 and c.workspace_id is null and c.action='question.answer'
	 join runtimes r on r.id=c.runtime_id and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+`
	 join installations i on i.id=r.installation_id and i.revoked_at is null join hosts h on h.id=i.host_id and h.state='active'
	 join org_memberships m on m.org_id=h.org_id and m.user_id=u.id
	 join sessions s on s.runtime_id=r.id and s.id=c.session_id
	 join runtime_grants g on g.runtime_id=r.id and g.user_id=u.id and g.role in ('owner','operator')
	 where u.issuer=$1 and u.subject=$2 and u.status='active' and $8::timestamptz>clock_timestamp()
	 and g.revoked_at is null and (g.expires_at is null or g.expires_at>clock_timestamp())
	 and g.scope->'actions' @> '["session.read","question.answer"]'::jsonb
	 and (g.scope->'sessions' ? s.id::text or s.workspace_id is not null and g.scope->'workspaces' ? s.workspace_id::text)`,
		identity.Issuer, identity.Subject, device, proof, runtime, session, request, until).Scan(&result.RequestID, &result.SessionID, &result.State, &result.PayloadSHA256, &result.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrAccessDenied
	}
	if err != nil {
		return result, ErrDatabaseUnavailable
	}
	return result, nil
}
