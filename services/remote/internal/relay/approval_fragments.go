package relay

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

const maxApprovalContextBytes = 128 * 1024
const approvalFragmentBytes = 40 * 1024

type approvalAssembly struct {
	host        *liveConnection
	frame       wireEnvelope
	id, kind    string
	count, next int
	data        []byte
	timer       *time.Timer
}

func approvalFragmentKey(host *liveConnection, requestID string) string {
	return host.connectionID + "/" + requestID
}

func (router *approvalRouter) dropAssemblyLocked(key string, assembly *approvalAssembly) {
	if router.fragments[key] != assembly {
		return
	}
	delete(router.fragments, key)
	router.fragmentBytes -= len(assembly.data)
	if assembly.timer != nil {
		assembly.timer.Stop()
	}
}

func (router *approvalRouter) dropFragmentLocked(host *liveConnection, requestID string) {
	key := approvalFragmentKey(host, requestID)
	if assembly := router.fragments[key]; assembly != nil {
		router.dropAssemblyLocked(key, assembly)
	}
}

func (router *approvalRouter) fragment(host *liveConnection, frame wireEnvelope) (*wireEnvelope, error) {
	var payload struct {
		Kind  string `json:"kind"`
		ID    string `json:"transfer_id"`
		Index *int   `json:"index"`
		Count *int   `json:"count"`
		Data  string `json:"data"`
	}
	if decodeApprovalPayload(frame.Payload, &payload, "kind", "transfer_id", "index", "count", "data") != nil ||
		(payload.Kind != "approval.request" && payload.Kind != "approval.details") || !uuidPattern.MatchString(payload.ID) || payload.Index == nil || payload.Count == nil ||
		*payload.Index < 0 || *payload.Count < 1 || *payload.Count > 4 || *payload.Index >= *payload.Count {
		return nil, store.ErrApprovalInvalid
	}
	chunk, err := base64.StdEncoding.Strict().DecodeString(payload.Data)
	if err != nil || len(chunk) == 0 || len(chunk) > approvalFragmentBytes || base64.StdEncoding.EncodeToString(chunk) != payload.Data {
		return nil, store.ErrApprovalInvalid
	}
	router.mu.Lock()
	defer router.mu.Unlock()
	key := approvalFragmentKey(host, frame.RequestID)
	assembly := router.fragments[key]
	if assembly == nil {
		if *payload.Index != 0 {
			return nil, store.ErrApprovalInvalid
		}
		if payload.Kind == "approval.details" {
			pending := router.requests[frame.RequestID]
			if pending == nil || pending.host != host || pending.answered {
				return nil, store.ErrApprovalInvalid
			}
		}
		byHost := 0
		for _, entry := range router.fragments {
			if entry.host == host {
				byHost++
			}
		}
		if len(router.fragments) >= 64 || byHost >= 4 {
			return nil, store.ErrApprovalLimit
		}
		assembly = &approvalAssembly{host: host, frame: frame, id: payload.ID, kind: payload.Kind, count: *payload.Count}
		router.fragments[key] = assembly
		assembly.timer = time.AfterFunc(approvalRPCTimeout, func() { router.mu.Lock(); router.dropAssemblyLocked(key, assembly); router.mu.Unlock() })
	}
	if assembly.id != payload.ID || assembly.kind != payload.Kind || assembly.next != *payload.Index || assembly.count != *payload.Count || assembly.frame.RuntimeID != frame.RuntimeID ||
		assembly.frame.RuntimeEpoch != frame.RuntimeEpoch || assembly.frame.SessionID != frame.SessionID || len(assembly.data)+len(chunk) > maxApprovalContextBytes || router.fragmentBytes+len(chunk) > 8*1024*1024 {
		router.dropAssemblyLocked(key, assembly)
		return nil, store.ErrApprovalInvalid
	}
	assembly.data = append(assembly.data, chunk...)
	router.fragmentBytes += len(chunk)
	assembly.next++
	if assembly.next != assembly.count {
		return nil, nil
	}
	completed := assembly.frame
	completed.Type = assembly.kind
	completed.Payload, err = json.Marshal(map[string]json.RawMessage{"context": assembly.data})
	router.dropAssemblyLocked(key, assembly)
	if err != nil {
		return nil, store.ErrApprovalInvalid
	}
	return &completed, nil
}

func encodeApprovalContext(kind, requestID string, status store.ApprovalStatus, raw []byte) ([]map[string]any, error) {
	if len(raw) == 0 || len(raw) > maxApprovalContextBytes {
		return nil, store.ErrApprovalInvalid
	}
	frame := approvalFrame(kind, requestID, status, map[string]json.RawMessage{"context": raw})
	encoded, err := json.Marshal(frame)
	if err != nil {
		return nil, err
	}
	if len(encoded) <= maxFrameBytes {
		return []map[string]any{frame}, nil
	}
	id, err := randomUUID()
	if err != nil {
		return nil, err
	}
	count := (len(raw) + approvalFragmentBytes - 1) / approvalFragmentBytes
	frames := make([]map[string]any, 0, count)
	for index := 0; index < count; index++ {
		start, end := index*approvalFragmentBytes, min((index+1)*approvalFragmentBytes, len(raw))
		frames = append(frames, approvalFrame("approval.fragment", requestID, status, map[string]any{"kind": kind, "transfer_id": id, "index": index, "count": count, "data": base64.StdEncoding.EncodeToString(raw[start:end])}))
	}
	return frames, nil
}
