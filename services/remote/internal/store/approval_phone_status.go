package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// PhoneApprovalStatus resolves an authenticated HTTP phone into a read-only
// scope inside the same transaction as the existing approval metadata policy.
// This does not issue a realtime ticket or any approval execution authority.
func (postgres *Postgres) PhoneApprovalStatus(ctx context.Context, identity UserIdentity, deviceID, proofJKT, approvalID string) (ApprovalStatus, error) {
	if !grantUUIDPattern.MatchString(deviceID) || !grantUUIDPattern.MatchString(approvalID) || !keyThumbprintPattern.MatchString(proofJKT) {
		return ApprovalStatus{}, ErrApprovalInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, approvalAdmissionTimeout)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	ticket := TicketRedemption{DeviceID: deviceID, ProofKeyThumbprint: proofJKT}
	var raw []byte
	err = tx.QueryRowContext(ctx, `select u.id::text,d.key_version,a.runtime_id::text,g.grant_version,g.scope
	 from users u join devices d on d.user_id=u.id
	 join approvals a on a.id=$5 and a.metadata_version=1
	 join runtime_grants g on g.runtime_id=a.runtime_id and g.user_id=u.id
	 where u.issuer=$1 and u.subject=$2 and u.status='active'
	 and d.id=$3 and d.proof_key_thumbprint=$4 and d.revoked_at is null
	 for share of u,d`, identity.Issuer, identity.Subject, deviceID, proofJKT, approvalID).
		Scan(&ticket.UserID, &ticket.DeviceKeyVersion, &ticket.RuntimeID, &ticket.GrantVersion, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ApprovalStatus{}, ErrAccessDenied
	}
	if err != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	if json.Unmarshal(raw, &ticket.Scope) != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	// No management, write, file or directory action is inferred from this read.
	// Preserve resource narrowing and use the same owner/action policy as WSS.
	ticket.Scope.Actions = []string{"approval.decide", "session.read"}
	status, err := authorizeApprovalRead(ctx, tx, ticket, approvalID, false)
	if err != nil {
		return ApprovalStatus{}, err
	}
	if err := tx.Commit(); err != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	return status, nil
}
