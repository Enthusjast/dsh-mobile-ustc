package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"dsh-mobile-ustc/services/remote/internal/approval"
)

// ApprovalLeaseProvider uses the accepted decision's original token/assurance
// evidence and grant version. Renewal never refreshes authentication or regrants.
type ApprovalLeaseProvider struct {
	control *ApprovalControl
	signer  *approval.AuthorizationSigner
}

func NewApprovalLeaseProvider(control *ApprovalControl, signer *approval.AuthorizationSigner) (*ApprovalLeaseProvider, error) {
	if control == nil || signer == nil {
		return nil, ErrApprovalInvalid
	}
	return &ApprovalLeaseProvider{control: control, signer: signer}, nil
}

// Issue returns a signed lease only after the current-authority checks, audit
// and outbox commit. Full execution context remains transient.
func (provider *ApprovalLeaseProvider) Issue(ctx context.Context, connection RuntimeConnection, keyVersion int64, rawContext []byte) (string, error) {
	binding, err := provider.control.context(rawContext)
	if err != nil {
		return "", err
	}
	request := binding.Context
	if !validApprovalConnection(connection, keyVersion) || request.InstallationID != connection.InstallationID || request.RuntimeID != connection.RuntimeID || request.RuntimeEpoch != connection.RuntimeEpoch {
		return "", ErrRuntimeConnectionStale
	}
	ctx, cancel := context.WithTimeout(ctx, approvalAdmissionTimeout)
	defer cancel()
	transaction, err := provider.control.database.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	orgID, currentConnection, err := lockApprovalRuntime(ctx, transaction, request, false)
	if err != nil {
		return "", err
	}
	if currentConnection != connection.ConnectionID {
		return "", ErrRuntimeConnectionStale
	}
	var currentKeyVersion int64
	var lastSeen time.Time
	if err := transaction.QueryRowContext(ctx, `select connection_key_version, last_seen_at from runtimes where id = $1`, request.RuntimeID).Scan(&currentKeyVersion, &lastSeen); err != nil {
		return "", ErrDatabaseUnavailable
	}
	if currentKeyVersion != keyVersion {
		return "", ErrRuntimeConnectionStale
	}
	if err := lockApprovalSession(ctx, transaction, request); err != nil {
		return "", err
	}
	status, registeredConnection, err := readApproval(ctx, transaction, request.ApprovalID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrAccessDenied
	}
	if err != nil {
		return "", ErrDatabaseUnavailable
	}
	if registeredConnection != currentConnection {
		return "", ErrRuntimeConnectionStale
	}
	if status.BindingSHA256 != binding.SHA256 || (status.State != "decision_received" && status.State != "denied") {
		return "", ErrAccessDenied
	}

	var key approval.RegisteredKey
	var scopeJSON []byte
	var grantVersion int64
	var grantExpires sql.NullTime
	var compactDecision string
	var authenticated, tokenExpires, decisionExpires time.Time
	err = transaction.QueryRowContext(ctx, `
		select d.user_id::text, d.id::text, d.key_version, d.approval_key_thumbprint, d.approval_public_jwk,
		       g.scope, g.grant_version, g.expires_at, a.decision_jws, a.authenticated_at, a.access_token_expires_at, a.decision_expires_at
		from approvals a
		join users u on u.id = a.decided_by and u.status = 'active'
		join devices d on d.id = a.decided_device_id and d.user_id = u.id and d.revoked_at is null
		join org_memberships m on m.user_id = u.id and m.org_id = $2
		join runtime_grants g on g.user_id = u.id and g.runtime_id = a.runtime_id
		where a.id = $1 and a.metadata_version = 1
		  and ((a.state = 'decision_received' and a.decision = 'allow_once') or (a.state = 'denied' and a.decision = 'reject'))
		  and d.key_version = a.decision_key_version and d.approval_key_thumbprint = a.decision_approval_key_jkt
		  and d.proof_key_thumbprint = a.decision_proof_key_jkt and g.grant_version = a.decision_grant_version
		  and g.role = 'owner' and g.revoked_at is null and (g.expires_at is null or g.expires_at > clock_timestamp())
		for share of u, d, m, g`, request.ApprovalID, orgID).
		Scan(&key.UserID, &key.DeviceID, &key.KeyVersion, &key.ApprovalKeyJKT, &key.PublicJWK,
			&scopeJSON, &grantVersion, &grantExpires, &compactDecision, &authenticated, &tokenExpires, &decisionExpires)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrAccessDenied
	}
	if err != nil {
		return "", ErrDatabaseUnavailable
	}
	var scope GrantScope
	if json.Unmarshal(scopeJSON, &scope) != nil {
		return "", ErrDatabaseUnavailable
	}
	if !slices.Contains(scope.Actions, "approval.decide") || !scopeIncludesSession(scope, request.SessionID, sql.NullString{String: request.Workspace.WorkspaceID, Valid: true}) {
		return "", ErrAccessDenied
	}
	now, err := approvalDatabaseTime(ctx, transaction)
	if err != nil {
		return "", err
	}
	key.Active = true
	decision, err := approval.VerifyDecision(compactDecision, key, rawContext, now)
	if err != nil || decision.PayloadSHA256 != status.PayloadSHA256 {
		return "", ErrAccessDenied
	}
	authority := provider.signer.Authority()
	if authority.ValidFrom.After(now) || !authority.ValidUntil.After(now) || authenticated.After(now) {
		return "", ErrAccessDenied
	}
	// Clip to every independently enforced deadline, including the original
	// access token and authentication age. No refreshed phone token is accepted here.
	expires := now.Add(3 * time.Second)
	for _, deadline := range []time.Time{status.ExpiresAt, decisionExpires, tokenExpires, authenticated.Add(time.Duration(provider.control.policy.MaxAuthAgeSeconds) * time.Second), authority.ValidUntil, lastSeen.Add(45 * time.Second)} {
		if deadline.Before(expires) {
			expires = deadline
		}
	}
	if grantExpires.Valid && grantExpires.Time.Before(expires) {
		expires = grantExpires.Time
	}
	issued := now.UTC().Truncate(time.Millisecond)
	expires = expires.UTC().Truncate(time.Millisecond)
	if !expires.After(now) {
		return "", ErrApprovalExpired
	}
	var publicKey struct {
		Type  string `json:"kty"`
		Curve string `json:"crv"`
		X     string `json:"x"`
		Y     string `json:"y"`
	}
	if json.Unmarshal(key.PublicJWK, &publicKey) != nil {
		return "", ErrDatabaseUnavailable
	}
	public, err := json.Marshal(publicKey)
	if err != nil {
		return "", ErrDatabaseUnavailable
	}
	var leaseID string
	if err := transaction.QueryRowContext(ctx, `select gen_random_uuid()::text`).Scan(&leaseID); err != nil {
		return "", ErrDatabaseUnavailable
	}
	lease := approval.AuthorizationLease{Domain: approval.AuthorizationDomain, ProtocolVersion: 1, Issuer: authority.Issuer, Audience: approval.AuthorizationAudience,
		Identity: request.Identity, ConnectionID: currentConnection, LeaseID: leaseID, Action: "approval.decide", Role: "owner", BindingSHA256: binding.SHA256,
		DecisionPayloadSHA256: decision.PayloadSHA256, PolicyVersion: request.PolicyVersion, UserID: key.UserID, DeviceID: key.DeviceID, KeyVersion: key.KeyVersion,
		ApprovalKeyJKT: key.ApprovalKeyJKT, ApprovalPublicJWK: public, GrantVersion: grantVersion, AssuranceProfile: provider.control.policy.AssuranceProfile,
		AuthenticatedAt: authenticated.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z"), IssuedAt: issued.Format("2006-01-02T15:04:05.000Z"), ExpiresAt: expires.Format("2006-01-02T15:04:05.000Z")}
	metadata, _ := json.Marshal(map[string]any{"approval_id": lease.ApprovalID, "runtime_id": lease.RuntimeID, "runtime_epoch": lease.RuntimeEpoch, "session_id": lease.SessionID,
		"execution_id": lease.ExecutionID, "connection_id": lease.ConnectionID, "lease_id": lease.LeaseID, "binding_sha256": lease.BindingSHA256, "decision_payload_sha256": lease.DecisionPayloadSHA256,
		"user_id": lease.UserID, "device_id": lease.DeviceID, "key_version": lease.KeyVersion, "grant_version": lease.GrantVersion, "policy_version": lease.PolicyVersion,
		"authority_key_id": authority.KeyID, "issued_at": lease.IssuedAt, "expires_at": lease.ExpiresAt})
	if _, err := transaction.ExecContext(ctx, `
		insert into audit_log (org_id, actor_type, actor_id, device_id, runtime_id, session_id, action, result, metadata)
		values ($1, 'installation', $2, $3, $4, $5, 'approval.authorization.prepare', 'success', $6::jsonb)`,
		orgID, connection.InstallationID, key.DeviceID, request.RuntimeID, request.SessionID, string(metadata)); err != nil {
		return "", ErrDatabaseUnavailable
	}
	if _, err := transaction.ExecContext(ctx, `insert into control_outbox (org_id, topic, payload) values ($1, 'approval.authorization.prepared', $2::jsonb)`, orgID, string(metadata)); err != nil {
		return "", ErrDatabaseUnavailable
	}
	checked, err := approvalDatabaseTime(ctx, transaction)
	if err != nil {
		return "", err
	}
	compact, err := provider.signer.Sign(lease, checked)
	if err != nil {
		return "", err
	}
	if err := transaction.Commit(); err != nil {
		return "", ErrDatabaseUnavailable
	}
	if !expires.After(time.Now()) {
		return "", ErrApprovalExpired
	}
	return compact, nil
}
