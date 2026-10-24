package store

import (
	"context"
	"database/sql"
)

type OrganizationMembership struct {
	OrganizationID string `json:"organization_id"`
	Role           string `json:"role"`
}

type AccountIdentity struct {
	UserID      string                   `json:"user_id"`
	Memberships []OrganizationMembership `json:"memberships"`
}

// AccountIdentity resolves only the verified issuer/subject pair. The single
// statement observes the active user and memberships in one database snapshot.
// It creates no user, membership, device or grant.
func (postgres *Postgres) AccountIdentity(ctx context.Context, identity UserIdentity) (AccountIdentity, error) {
	rows, err := postgres.DB.QueryContext(ctx, `
		select u.id::text, m.org_id::text, m.role
		from users u
		left join org_memberships m on m.user_id = u.id
		where u.issuer = $1 and u.subject = $2 and u.status = 'active'
		order by m.org_id`, identity.Issuer, identity.Subject)
	if err != nil {
		return AccountIdentity{}, ErrDatabaseUnavailable
	}
	defer rows.Close()
	account := AccountIdentity{Memberships: make([]OrganizationMembership, 0)}
	for rows.Next() {
		var organization, role sql.NullString
		if err := rows.Scan(&account.UserID, &organization, &role); err != nil {
			return AccountIdentity{}, ErrDatabaseUnavailable
		}
		if organization.Valid && role.Valid {
			account.Memberships = append(account.Memberships, OrganizationMembership{OrganizationID: organization.String, Role: role.String})
		}
	}
	if err := rows.Err(); err != nil {
		return AccountIdentity{}, ErrDatabaseUnavailable
	}
	if account.UserID == "" {
		return AccountIdentity{}, ErrIdentityNotProvisioned
	}
	return account, nil
}
