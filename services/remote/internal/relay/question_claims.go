package relay

import (
	"context"
	"time"
)

type questionClaim struct {
	questionID string
	claimed    bool
}
type claimPayload struct {
	QuestionID string `json:"question_id,omitempty"`
	ClaimID    string `json:"claim_id,omitempty"`
}
type claimResultPayload struct {
	QuestionID  string     `json:"question_id"`
	RemainingMS *int64     `json:"remaining_ms,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Code        string     `json:"code,omitempty"`
}

func (server *Server) routeQuestionClaim(ctx context.Context, live *liveConnection, envelope wireEnvelope) {
	if !live.supports("question.timed.v1") || !live.supports("session.read.v1") {
		server.sendProtocolError(ctx, live, "protocol.unsupported", &envelope)
		return
	}
	if !uuidPattern.MatchString(envelope.RequestID) || envelope.RuntimeID != live.runtimeID || !uuidPattern.MatchString(envelope.RuntimeEpoch) ||
		!uuidPattern.MatchString(envelope.SessionID) || !uuidPattern.MatchString(envelope.SubscriptionID) || !uuidPattern.MatchString(envelope.SyncID) ||
		envelope.UserID != "" || envelope.DeviceID != "" || envelope.PayloadSHA256 != "" {
		server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
		return
	}
	var payload claimPayload
	if envelope.Type == "question.claim" {
		var input struct {
			QuestionID string `json:"question_id"`
		}
		if decodePayload(envelope.Payload, &input) != nil || !uuidPattern.MatchString(input.QuestionID) {
			server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
			return
		}
		payload.QuestionID = input.QuestionID
	} else {
		var input struct {
			ClaimID string `json:"claim_id"`
		}
		if decodePayload(envelope.Payload, &input) != nil || !uuidPattern.MatchString(input.ClaimID) {
			server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
			return
		}
		payload.ClaimID = input.ClaimID
	}
	server.mu.Lock()
	subscription := server.subscriptions[envelope.SubscriptionID]
	owned := subscription != nil && subscription.device == live && subscription.sessionID == envelope.SessionID && subscription.host.runtimeEpoch == envelope.RuntimeEpoch &&
		subscription.ready && subscription.syncID == envelope.SyncID && !live.closing && !subscription.host.closing && server.hosts[live.runtimeID] == subscription.host
	server.mu.Unlock()
	if !owned {
		server.sendProtocolError(ctx, live, "protocol.resync_required", &envelope)
		return
	}
	if !subscription.timedQuestions {
		server.sendProtocolError(ctx, live, "protocol.unsupported", &envelope)
		return
	}
	if envelope.Type == "question.release" {
		server.mu.Lock()
		existing := subscription.claims[payload.ClaimID]
		delete(subscription.claims, payload.ClaimID)
		server.mu.Unlock()
		if existing != nil {
			if err := subscription.host.sendJSON(ctx, envelope); err != nil {
				_ = subscription.host.conn.CloseNow()
			}
		}
		frame := server.subscriptionFrame(subscription, "question.released", envelope.RequestID, map[string]string{"claim_id": payload.ClaimID})
		frame["sync_id"] = envelope.SyncID
		if err := live.sendJSON(ctx, frame); err != nil {
			_ = live.conn.CloseNow()
		}
		return
	}
	if err := server.database.AuthorizeRealtimeQuestion(ctx, live.peer.redemption, envelope.SessionID); err != nil {
		server.sendProtocolError(ctx, live, commandErrorCode(err), &envelope)
		return
	}
	if err := server.database.TouchRuntimeConnection(ctx, subscription.host.peer.installation.InstallationID, live.runtimeID, subscription.host.runtimeEpoch, subscription.host.connectionID); err != nil {
		server.dropSubscription(ctx, subscription, "runtime.changed", true)
		return
	}
	server.mu.Lock()
	code := ""
	if server.subscriptions[subscription.id] != subscription || live.closing || subscription.host.closing || server.hosts[live.runtimeID] != subscription.host {
		code = "protocol.resync_required"
	} else if _, used := subscription.claimIDs[envelope.RequestID]; used || len(subscription.claims) >= 4 || len(subscription.claimIDs) >= 256 || envelope.RequestID == subscription.requestID || subscription.pages[envelope.RequestID] != "" {
		code = "rate.limited"
	} else {
		subscription.claimIDs[envelope.RequestID] = struct{}{}
		subscription.claims[envelope.RequestID] = &questionClaim{questionID: payload.QuestionID}
	}
	server.mu.Unlock()
	if code != "" {
		server.sendProtocolError(ctx, live, code, &envelope)
		return
	}
	if err := subscription.host.sendJSON(ctx, envelope); err != nil {
		server.dropSubscription(ctx, subscription, "protocol.resync_required", true)
	}
}

func (server *Server) routeQuestionClaimResult(ctx context.Context, live *liveConnection, envelope wireEnvelope) {
	if !live.supports("question.timed.v1") || !uuidPattern.MatchString(envelope.RequestID) || envelope.RuntimeID != live.runtimeID || envelope.RuntimeEpoch != live.runtimeEpoch ||
		!uuidPattern.MatchString(envelope.SubscriptionID) || !uuidPattern.MatchString(envelope.SyncID) || envelope.UserID != "" || envelope.DeviceID != "" || envelope.PayloadSHA256 != "" {
		server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
		return
	}
	var payload claimResultPayload
	if envelope.Type == "question.claimed" {
		var input struct {
			QuestionID  string     `json:"question_id"`
			RemainingMS *int64     `json:"remaining_ms"`
			ExpiresAt   *time.Time `json:"expires_at"`
		}
		if decodePayload(envelope.Payload, &input) != nil {
			server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
			return
		}
		payload.QuestionID, payload.RemainingMS, payload.ExpiresAt = input.QuestionID, input.RemainingMS, input.ExpiresAt
		if payload.RemainingMS == nil || *payload.RemainingMS < 0 || *payload.RemainingMS > 2_147_483_647 || payload.ExpiresAt == nil || payload.Code != "" {
			server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
			return
		}
	} else {
		var input struct {
			QuestionID string `json:"question_id"`
			Code       string `json:"code"`
		}
		if decodePayload(envelope.Payload, &input) != nil {
			server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
			return
		}
		payload.QuestionID, payload.Code = input.QuestionID, input.Code
		if payload.Code != "question.ended" && payload.Code != "interaction.stale" && payload.Code != "rate.limited" && payload.Code != "internal" {
			server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
			return
		}
	}
	if !uuidPattern.MatchString(payload.QuestionID) {
		server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
		return
	}
	server.mu.Lock()
	subscription := server.subscriptions[envelope.SubscriptionID]
	var claim *questionClaim
	if subscription != nil {
		claim = subscription.claims[envelope.RequestID]
	}
	valid := claim != nil && subscription.host == live && server.hosts[live.runtimeID] == live && !live.closing && !subscription.device.closing &&
		subscription.syncID == envelope.SyncID && subscription.sessionID == envelope.SessionID && claim.questionID == payload.QuestionID
	server.mu.Unlock()
	if claim == nil {
		return
	}
	if !valid {
		server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
		return
	}
	if err := server.database.TouchRuntimeConnection(ctx, live.peer.installation.InstallationID, live.runtimeID, live.runtimeEpoch, live.connectionID); err != nil {
		server.dropSubscription(ctx, subscription, "runtime.changed", true)
		return
	}
	if err := server.database.AuthorizeRealtimeQuestion(ctx, subscription.device.peer.redemption, subscription.sessionID); err != nil {
		server.dropSubscription(ctx, subscription, commandErrorCode(err), true)
		return
	}
	server.mu.Lock()
	current := server.subscriptions[subscription.id] == subscription && subscription.claims[envelope.RequestID] == claim && !live.closing && !subscription.device.closing && server.hosts[live.runtimeID] == live
	if current && envelope.Type == "question.claimed" {
		if claim.claimed {
			current = false
		} else {
			claim.claimed = true
		}
	}
	if current && envelope.Type == "question.claim.closed" {
		delete(subscription.claims, envelope.RequestID)
	}
	server.mu.Unlock()
	if current {
		if err := subscription.device.sendJSON(ctx, envelope); err != nil {
			_ = subscription.device.conn.CloseNow()
		}
	}
}
