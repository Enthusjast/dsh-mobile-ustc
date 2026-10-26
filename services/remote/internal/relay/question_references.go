package relay

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

const questionReferencesCapability = "question.references.v1"

type questionReferenceRepository interface {
	SyncRealtimeQuestionReferences(context.Context, store.RuntimeConnection, int64, int64, []store.QuestionReferenceItem) error
}

func (server *Server) routeQuestionReferences(parent context.Context, live *liveConnection, host *store.RuntimeConnection, frame wireEnvelope, raw []byte) {
	if server.questionReferences == nil || !live.supports(questionReferencesCapability) {
		server.sendProtocolError(parent, live, "protocol.unsupported", &frame)
		return
	}
	if live.peer.role != "installation" || host == nil || !live.peer.installation.ExpiresAt.After(time.Now()) {
		server.sendProtocolError(parent, live, "access.denied", &frame)
		return
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 6 || frame.RuntimeID != live.runtimeID || frame.RuntimeEpoch != live.runtimeEpoch || !uuidPattern.MatchString(frame.RequestID) ||
		frame.SessionID != "" || frame.DeviceID != "" || frame.UserID != "" || frame.PayloadSHA256 != "" || frame.SubscriptionID != "" || frame.SyncID != "" {
		server.sendProtocolError(parent, live, "protocol.invalid", &frame)
		return
	}
	for _, key := range []string{"v", "type", "request_id", "runtime_id", "runtime_epoch", "payload"} {
		if len(fields[key]) == 0 || string(fields[key]) == "null" {
			server.sendProtocolError(parent, live, "protocol.invalid", &frame)
			return
		}
	}
	var payload struct {
		Sequence *int64                        `json:"sequence"`
		Items    []store.QuestionReferenceItem `json:"items"`
	}
	if decodePayload(frame.Payload, &payload) != nil || payload.Sequence == nil || *payload.Sequence < 1 || *payload.Sequence > 9007199254740991 || payload.Items == nil || len(payload.Items) > 128 {
		server.sendProtocolError(parent, live, "protocol.invalid", &frame)
		return
	}
	seen := map[string]bool{}
	for _, item := range payload.Items {
		if !item.Valid() || seen[item.ID] {
			server.sendProtocolError(parent, live, "protocol.invalid", &frame)
			return
		}
		seen[item.ID] = true
	}
	if !live.lastQuestionReferences.IsZero() && time.Since(live.lastQuestionReferences) < 100*time.Millisecond {
		server.sendProtocolError(parent, live, "rate.limited", &frame)
		return
	}
	live.lastQuestionReferences = time.Now()
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	err := server.questionReferences.SyncRealtimeQuestionReferences(ctx, *host, live.peer.installation.KeyVersion, *payload.Sequence, payload.Items)
	cancel()
	if err != nil {
		code := "runtime.offline"
		if errors.Is(err, store.ErrQuestionReferencesInvalid) || errors.Is(err, store.ErrQuestionReferencesConflict) {
			code = "protocol.invalid"
		}
		if errors.Is(err, store.ErrQuestionReferencesLimited) {
			code = "rate.limited"
		}
		server.sendProtocolError(parent, live, code, &frame)
		return
	}
	if server.hostForRuntime(live.runtimeID) != live {
		return
	}
	_ = live.sendJSON(parent, map[string]any{"v": 1, "type": "question.references.ack", "request_id": frame.RequestID, "runtime_id": live.runtimeID, "runtime_epoch": live.runtimeEpoch,
		"payload": map[string]any{"sequence": *payload.Sequence, "item_count": len(payload.Items)}})
}
