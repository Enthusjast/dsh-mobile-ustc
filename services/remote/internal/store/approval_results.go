package store

import (
	"context"
	"database/sql"
	"errors"
)

// ApprovalHostResult is an authenticated host journal fact. It cannot request
// execution, change a signed choice, or reconstruct a native callback.
type ApprovalHostResult struct {
	ApprovalID            string `json:"approval_id"`
	SessionID             string `json:"session_id"`
	RuntimeEpoch          string `json:"runtime_epoch"`
	ExecutionID           string `json:"execution_id"`
	BindingSHA256         string `json:"binding_sha256"`
	DecisionPayloadSHA256 string `json:"decision_payload_sha256,omitempty"`
	State                 string `json:"state"`
	Outcome               string `json:"execution_outcome,omitempty"`
}

func (result ApprovalHostResult) valid() bool {
	if !grantUUIDPattern.MatchString(result.ApprovalID) || !grantUUIDPattern.MatchString(result.SessionID) || !grantUUIDPattern.MatchString(result.RuntimeEpoch) ||
		!grantUUIDPattern.MatchString(result.ExecutionID) || !validSHA256Hex(result.BindingSHA256) || (result.DecisionPayloadSHA256 != "" && !validSHA256Hex(result.DecisionPayloadSHA256)) {
		return false
	}
	if result.State == "settled" {
		return result.Outcome == "succeeded" || result.Outcome == "failed" || result.Outcome == "cancelled"
	}
	if result.Outcome != "" {
		return false
	}
	switch result.State {
	case "approved", "denied", "consumed", "expired", "cancelled", "invalidated", "outcome_unknown":
		return true
	}
	return false
}

// RecordResult also accepts settled historical facts from a replacement
// connection of the same installation/runtime. Such reports never issue leases.
func (control *ApprovalControl) RecordResult(ctx context.Context, connection RuntimeConnection, keyVersion int64, result ApprovalHostResult) (ApprovalStatus, error) {
	if !validApprovalConnection(connection, keyVersion) || !result.valid() {
		return ApprovalStatus{}, ErrApprovalInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, approvalAdmissionTimeout)
	defer cancel()
	transaction, err := control.database.DB.BeginTx(ctx, nil)
	if err != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	var orgID string
	err = transaction.QueryRowContext(ctx, `
		select h.org_id::text from runtimes r
		join installations i on i.id = r.installation_id and i.revoked_at is null
		join hosts h on h.id = i.host_id and h.state = 'active'
		where r.id = $1 and i.id = $2 and i.key_version = $3 and r.epoch = $4 and r.connection_id = $5
		  and r.connection_key_version = i.key_version and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+` and r.protocol_version = 1
		  and r.last_seen_at > clock_timestamp() - interval '45 seconds'
		for share of r, i, h`, connection.RuntimeID, connection.InstallationID, keyVersion, connection.RuntimeEpoch, connection.ConnectionID).Scan(&orgID)
	if errors.Is(err, sql.ErrNoRows) {
		return ApprovalStatus{}, ErrRuntimeConnectionStale
	}
	if err != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	status, registeredConnection, err := readApproval(ctx, transaction, result.ApprovalID)
	if errors.Is(err, sql.ErrNoRows) {
		return ApprovalStatus{}, ErrAccessDenied
	}
	if err != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	if status.RuntimeID != connection.RuntimeID || status.RuntimeEpoch != result.RuntimeEpoch || status.SessionID != result.SessionID ||
		status.ExecutionID != result.ExecutionID || status.BindingSHA256 != result.BindingSHA256 {
		return ApprovalStatus{}, ErrApprovalConflict
	}
	if result.DecisionPayloadSHA256 != "" && result.DecisionPayloadSHA256 != status.PayloadSHA256 {
		return ApprovalStatus{}, ErrApprovalConflict
	}
	if result.State == "approved" || result.State == "consumed" || result.State == "settled" || result.State == "outcome_unknown" || result.State == "denied" {
		if result.DecisionPayloadSHA256 == "" || result.DecisionPayloadSHA256 != status.PayloadSHA256 {
			return ApprovalStatus{}, ErrApprovalConflict
		}
	}
	nextState, nextHostState, outcome, err := approvalResultTransition(status, result, registeredConnection == connection.ConnectionID && status.RuntimeEpoch == connection.RuntimeEpoch)
	if err != nil {
		return ApprovalStatus{}, err
	}
	if nextState == status.State && nextHostState == status.HostState && outcome == status.Outcome {
		if err := transaction.Commit(); err != nil {
			return ApprovalStatus{}, ErrDatabaseUnavailable
		}
		return status, nil
	}
	updated, err := transaction.ExecContext(ctx, `
		update approvals set state = $2, host_state = $3, execution_outcome = nullif($4, ''), host_updated_at = clock_timestamp()
		where id = $1 and state = $5 and coalesce(host_state, '') = $6 and coalesce(execution_outcome, '') = $7`,
		result.ApprovalID, nextState, nextHostState, outcome, status.State, status.HostState, status.Outcome)
	if err != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	if rows, err := updated.RowsAffected(); err != nil || rows != 1 {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	status, _, err = readApproval(ctx, transaction, result.ApprovalID)
	if err != nil || approvalChange(ctx, transaction, orgID, "installation", connection.InstallationID, "", "approval.result", status) != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	if err := transaction.Commit(); err != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	return status, nil
}

func approvalResultTransition(current ApprovalStatus, result ApprovalHostResult, originalConnection bool) (string, string, string, error) {
	unchanged := func() (string, string, string, error) { return current.State, current.HostState, current.Outcome, nil }
	conflict := func() (string, string, string, error) { return "", "", "", ErrApprovalConflict }
	if current.HostState == "settled" {
		if result.State == "settled" && result.Outcome != current.Outcome {
			return conflict()
		}
		if result.State == "settled" || result.State == "approved" || result.State == "consumed" || result.State == "outcome_unknown" {
			return unchanged()
		}
		return conflict()
	}
	if current.HostState == "denied" || current.HostState == "expired" || current.HostState == "cancelled" || current.HostState == "invalidated" {
		if result.State == current.HostState {
			return unchanged()
		}
		return conflict()
	}
	if result.State == "approved" {
		if current.Decision != "allow_once" {
			return conflict()
		}
		if current.HostState == "consumed" || current.HostState == "outcome_unknown" || current.HostState == "approved" {
			return unchanged()
		}
		if !originalConnection || current.State != "decision_received" {
			return unchanged()
		}
		return current.State, "approved", "", nil
	}
	if result.State == "consumed" || result.State == "outcome_unknown" || result.State == "settled" {
		if current.Decision != "allow_once" {
			return conflict()
		}
		if current.HostState == "outcome_unknown" && result.State == "consumed" {
			return unchanged()
		}
		if result.State == "settled" {
			return "allowed", "settled", result.Outcome, nil
		}
		if result.State == "outcome_unknown" || !originalConnection || current.State == "outcome_unknown" {
			return "outcome_unknown", result.State, "", nil
		}
		return "allowed", "consumed", "", nil
	}
	if current.HostState == "consumed" || current.HostState == "outcome_unknown" {
		return conflict()
	}
	if result.State == "denied" {
		if current.Decision != "reject" {
			return conflict()
		}
		return "denied", "denied", "", nil
	}
	if current.Decision == "reject" {
		return "denied", result.State, "", nil
	}
	return result.State, result.State, "", nil
}
