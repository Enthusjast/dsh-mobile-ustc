package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// AppReleaseAccess rechecks the current school user, organization and registered
// phone key in one snapshot. Runtime directory/content grants are unrelated.
func (postgres *Postgres) AppReleaseAccess(ctx context.Context, identity UserIdentity, device, proof, organization string, until time.Time) (string, error) {
	if !grantUUIDPattern.MatchString(device) || !grantUUIDPattern.MatchString(organization) {
		return "", ErrAccessDenied
	}
	var user string
	err := postgres.DB.QueryRowContext(ctx, `select u.id::text from users u
	 join devices d on d.user_id=u.id and d.id=$3 and d.revoked_at is null and d.proof_key_thumbprint=$4
	 join org_memberships m on m.user_id=u.id and m.org_id=$5
	 where u.issuer=$1 and u.subject=$2 and u.status='active' and $6::timestamptz>clock_timestamp()`,
		identity.Issuer, identity.Subject, device, proof, organization, until).Scan(&user)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrAccessDenied
	}
	if err != nil {
		return "", ErrDatabaseUnavailable
	}
	return user, nil
}
