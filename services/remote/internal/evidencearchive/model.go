// Package evidencearchive defines an encrypted, non-executable approval proof.
package evidencearchive

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"
	"unicode/utf8"

	"dsh-mobile-ustc/services/remote/internal/approval"
	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/coldarchive"
)

type Proof struct {
	ApprovalID        string          `json:"approval_id"`
	SourceEpoch       string          `json:"source_epoch"`
	RuntimeID         string          `json:"runtime_id"`
	RuntimeEpoch      string          `json:"runtime_epoch"`
	SessionID         string          `json:"session_id"`
	ExecutionID       string          `json:"execution_id"`
	UserID            string          `json:"user_id"`
	DeviceID          string          `json:"device_id"`
	KeyVersion        int64           `json:"key_version"`
	ApprovalKeyJKT    string          `json:"approval_key_jkt"`
	Decision          string          `json:"decision"`
	BindingSHA256     string          `json:"binding_sha256"`
	PayloadSHA256     string          `json:"payload_sha256"`
	JWSSHA256         string          `json:"jws_sha256"`
	FingerprintSource string          `json:"fingerprint_source"`
	DecidedAt         time.Time       `json:"decided_at"`
	RetainUntil       time.Time       `json:"retain_until"`
	DecisionJWS       string          `json:"decision_jws"`
	PublicJWK         json.RawMessage `json:"public_jwk"`
}

type Payload struct {
	Format         string                 `json:"format"`
	Version        int                    `json:"version"`
	DomainID       string                 `json:"domain_id"`
	ExportID       string                 `json:"export_id"`
	OperationEpoch string                 `json:"operation_epoch"`
	KeyID          string                 `json:"key_id"`
	PreparedAt     time.Time              `json:"prepared_at"`
	Proof          Proof                  `json:"proof"`
	Recoveries     []coldarchive.Recovery `json:"recoveries"`
}

func (Payload) String() string               { return "evidencearchive.Payload" }
func (Payload) GoString() string             { return "evidencearchive.Payload" }
func (Payload) MarshalJSON() ([]byte, error) { return nil, coldarchive.ErrInvalid }
func (Proof) String() string                 { return "evidencearchive.Proof" }
func (Proof) GoString() string               { return "evidencearchive.Proof" }

func utcYear(value time.Time) time.Time {
	value = value.UTC()
	year, month, day := value.Date()
	if month == time.February && day == 29 && ((year+1)%4 != 0 || ((year+1)%100 == 0 && (year+1)%400 != 0)) {
		day = 28
	}
	return time.Date(year+1, month, day, value.Hour(), value.Minute(), value.Second(), value.Nanosecond(), time.UTC)
}

func (payload Payload) Validate() error {
	if payload.Format != "dsh-approval-evidence" || payload.Version != 1 || !coldarchive.UUID(payload.DomainID) || !coldarchive.UUID(payload.ExportID) || !coldarchive.UUID(payload.OperationEpoch) ||
		!coldarchive.KeyID(payload.KeyID) || payload.PreparedAt.IsZero() || payload.Recoveries == nil || len(payload.Recoveries) > coldarchive.MaxRecoveries {
		return coldarchive.ErrInvalid
	}
	p := payload.Proof
	if !coldarchive.UUID(p.SourceEpoch) || p.DecidedAt.IsZero() || p.DecidedAt.After(payload.PreparedAt) || p.RetainUntil.Before(utcYear(p.DecidedAt)) ||
		(p.FingerprintSource != "captured" && p.FingerprintSource != "backfilled") || len(p.DecisionJWS) == 0 || len(p.DecisionJWS) > 16*1024 || len(p.PublicJWK) == 0 || len(p.PublicJWK) > 8*1024 {
		return coldarchive.ErrInvalid
	}
	digest := sha256.Sum256([]byte(p.DecisionJWS))
	if !coldarchive.EqualDigest(hex.EncodeToString(digest[:]), p.JWSSHA256) {
		return coldarchive.ErrInvalid
	}
	record := approval.HistoricalDecisionEvidence{ApprovalID: p.ApprovalID, RuntimeID: p.RuntimeID, RuntimeEpoch: p.RuntimeEpoch, SessionID: p.SessionID, ExecutionID: p.ExecutionID,
		UserID: p.UserID, DeviceID: p.DeviceID, KeyVersion: p.KeyVersion, ApprovalKeyJKT: p.ApprovalKeyJKT, PublicJWK: p.PublicJWK, Decision: p.Decision, BindingSHA256: p.BindingSHA256, PayloadSHA256: p.PayloadSHA256}
	if approval.VerifyHistoricalDecision(p.DecisionJWS, record) != nil {
		return coldarchive.ErrInvalid
	}
	bySource := map[string][]string{}
	seenIDs, seenTargets := map[string]bool{}, map[string]bool{}
	for _, recovery := range payload.Recoveries {
		if !coldarchive.UUID(recovery.ID) || seenIDs[recovery.ID] || !coldarchive.UUID(recovery.SourceEpoch) || !coldarchive.UUID(recovery.TargetEpoch) || recovery.SourceEpoch == recovery.TargetEpoch || seenTargets[recovery.TargetEpoch] ||
			recovery.PreparedAt.IsZero() || recovery.ReleasedAt.Before(recovery.PreparedAt) || recovery.ReleasedAt.After(payload.PreparedAt) || len(recovery.AuthoritySHA256) != 64 ||
			len(recovery.Counts) == 0 || auth.ValidateJSONObject(recovery.Counts) != nil {
			return coldarchive.ErrInvalid
		}
		if _, err := hex.DecodeString(recovery.AuthoritySHA256); err != nil || recovery.AuthoritySHA256 != string(bytes.ToLower([]byte(recovery.AuthoritySHA256))) {
			return coldarchive.ErrInvalid
		}
		seenIDs[recovery.ID], seenTargets[recovery.TargetEpoch] = true, true
		bySource[recovery.SourceEpoch] = append(bySource[recovery.SourceEpoch], recovery.TargetEpoch)
	}
	visited := map[string]uint8{}
	var acyclic func(string) bool
	acyclic = func(epoch string) bool {
		if visited[epoch] == 1 {
			return false
		}
		if visited[epoch] == 2 {
			return true
		}
		visited[epoch] = 1
		for _, next := range bySource[epoch] {
			if !acyclic(next) {
				return false
			}
		}
		visited[epoch] = 2
		return true
	}
	for source := range bySource {
		if !acyclic(source) {
			return coldarchive.ErrInvalid
		}
	}
	seen := map[string]bool{p.SourceEpoch: true}
	queue := []string{p.SourceEpoch}
	for len(queue) > 0 && !seen[payload.OperationEpoch] {
		current := queue[0]
		queue = queue[1:]
		for _, next := range bySource[current] {
			if !seen[next] {
				seen[next] = true
				queue = append(queue, next)
			}
		}
	}
	if !seen[payload.OperationEpoch] {
		return coldarchive.ErrInvalid
	}
	return nil
}

type wirePayload Payload

func Encode(payload Payload) ([]byte, error) {
	if err := payload.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(wirePayload(payload))
	if err != nil || len(raw) > coldarchive.MaxPlaintext || auth.ValidateJSONObject(raw) != nil {
		clear(raw)
		return nil, coldarchive.ErrInvalid
	}
	return raw, nil
}

func Decode(raw []byte) (Payload, error) {
	if len(raw) == 0 || len(raw) > coldarchive.MaxPlaintext || !utf8.Valid(raw) || auth.ValidateJSONObject(raw) != nil {
		return Payload{}, coldarchive.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var wire wirePayload
	if decoder.Decode(&wire) != nil {
		return Payload{}, coldarchive.ErrInvalid
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return Payload{}, coldarchive.ErrInvalid
	}
	payload := Payload(wire)
	if payload.Validate() != nil {
		return Payload{}, coldarchive.ErrInvalid
	}
	return payload, nil
}

func Open(key *coldarchive.Key, artifact []byte, domainID, exportID string) (Payload, error) {
	if key == nil || !coldarchive.UUID(domainID) || !coldarchive.UUID(exportID) {
		return Payload{}, coldarchive.ErrInvalid
	}
	raw, err := coldarchive.OpenEncoded(key, artifact)
	if err != nil {
		return Payload{}, err
	}
	defer clear(raw)
	payload, err := Decode(raw)
	if err != nil || payload.DomainID != domainID || payload.ExportID != exportID || subtle.ConstantTimeCompare([]byte(payload.KeyID), []byte(key.ID())) != 1 {
		return Payload{}, coldarchive.ErrInvalid
	}
	return payload, nil
}

func Sort(payload *Payload) {
	sort.Slice(payload.Recoveries, func(i, j int) bool { return payload.Recoveries[i].ID < payload.Recoveries[j].ID })
}
