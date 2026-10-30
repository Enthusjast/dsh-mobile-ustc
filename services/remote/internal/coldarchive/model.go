// Package coldarchive defines a bounded authenticated export, never a live
// control replay format. Payloads can contain private resource metadata.
package coldarchive

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strconv"
	"time"
	"unicode/utf8"

	"dsh-mobile-ustc/services/remote/internal/auth"
)

const MaxPlaintext = 8 << 20
const MaxAcknowledgements = 8192
const MaxRecoveries = 256

var ErrInvalid = errors.New("cold archive: invalid data")
var ErrUnavailable = errors.New("cold archive: unavailable")
var ErrConflict = errors.New("cold archive: conflicting artifact")

var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var keyID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var topics = map[string]bool{"device.revoked": true, "runtime.revoked": true, "runtime_grant.updated": true, "runtime_grant.revoked": true, "approval.pending": true, "approval.decided": true, "approval.ended": true, "approval.result": true, "approval.authorization.prepared": true, "approval.device.revoked": true}

func UUID(value string) bool  { return uuid.MatchString(value) }
func KeyID(value string) bool { return keyID.MatchString(value) }

type Batch struct {
	ID                  string    `json:"id"`
	DatabaseEpoch       string    `json:"database_epoch"`
	Limit               int       `json:"limit"`
	RetentionYears      int       `json:"retention_years"`
	Cutoff              time.Time `json:"cutoff"`
	ArchivedAt          time.Time `json:"archived_at"`
	RetainUntil         time.Time `json:"retain_until"`
	Events              int       `json:"events"`
	PreviousEpochEvents int       `json:"previous_epoch_events"`
}
type Acknowledgement struct {
	NodeID    string          `json:"node_id"`
	EventID   string          `json:"event_id"`
	AppliedAt time.Time       `json:"applied_at"`
	Source    json.RawMessage `json:"source"`
}
type Event struct {
	ID               string            `json:"id"`
	BatchID          string            `json:"batch_id"`
	BatchEpoch       string            `json:"batch_epoch"`
	DatabaseEpoch    string            `json:"database_epoch"`
	Topic            string            `json:"topic"`
	SourceCreatedAt  time.Time         `json:"source_created_at"`
	Source           json.RawMessage   `json:"source"`
	Reason           string            `json:"reason"`
	ArchivedAt       time.Time         `json:"archived_at"`
	RetainUntil      time.Time         `json:"retain_until"`
	Acknowledgements []Acknowledgement `json:"acknowledgements"`
}
type Recovery struct {
	ID              string          `json:"id"`
	SourceEpoch     string          `json:"source_epoch"`
	TargetEpoch     string          `json:"target_epoch"`
	PreparedAt      time.Time       `json:"prepared_at"`
	ReleasedAt      time.Time       `json:"released_at"`
	AuthoritySHA256 string          `json:"authority_sha256"`
	Counts          json.RawMessage `json:"counts"`
}
type Payload struct {
	Format         string     `json:"format"`
	Version        int        `json:"version"`
	DomainID       string     `json:"domain_id"`
	ExportID       string     `json:"export_id"`
	OperationEpoch string     `json:"operation_epoch"`
	KeyID          string     `json:"key_id"`
	PreparedAt     time.Time  `json:"prepared_at"`
	Batch          Batch      `json:"batch"`
	Events         []Event    `json:"events"`
	Recoveries     []Recovery `json:"recoveries"`
}

func (Payload) String() string               { return "coldarchive.Payload" }
func (Payload) GoString() string             { return "coldarchive.Payload" }
func (Payload) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (Event) String() string                 { return "coldarchive.Event" }
func (Event) GoString() string               { return "coldarchive.Event" }
func (Acknowledgement) String() string       { return "coldarchive.Acknowledgement" }
func (Acknowledgement) GoString() string     { return "coldarchive.Acknowledgement" }
func (Recovery) String() string              { return "coldarchive.Recovery" }
func (Recovery) GoString() string            { return "coldarchive.Recovery" }

// utcYear matches PostgreSQL's UTC calendar-year interval, including Feb 29.
func utcYear(value time.Time, years int) time.Time {
	value = value.UTC()
	year, month, day := value.Date()
	if month == time.February && day == 29 {
		target := year + years
		if target%4 != 0 || (target%100 == 0 && target%400 != 0) {
			day = 28
		}
	}
	return time.Date(year+years, month, day, value.Hour(), value.Minute(), value.Second(), value.Nanosecond(), time.UTC)
}

func sourceObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var value map[string]json.RawMessage
	if len(raw) == 0 || !utf8.Valid(raw) || auth.ValidateJSONObject(raw) != nil || json.Unmarshal(raw, &value) != nil || value == nil {
		return nil, ErrInvalid
	}
	return value, nil
}
func sourceString(value map[string]json.RawMessage, name string) string {
	var text string
	if json.Unmarshal(value[name], &text) != nil {
		return ""
	}
	return text
}
func sourceTime(value map[string]json.RawMessage, name string) (time.Time, error) {
	var result time.Time
	if json.Unmarshal(value[name], &result) != nil || result.IsZero() {
		return time.Time{}, ErrInvalid
	}
	return result, nil
}
func validXID(raw json.RawMessage) bool {
	var value string
	if json.Unmarshal(raw, &value) != nil {
		value = string(raw)
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	return err == nil && parsed > 0 && strconv.FormatUint(parsed, 10) == value
}

func (payload Payload) Validate() error {
	if payload.Format != "dsh-control-archive" || payload.Version != 1 || !UUID(payload.DomainID) || !UUID(payload.ExportID) || !UUID(payload.OperationEpoch) || !KeyID(payload.KeyID) || payload.PreparedAt.IsZero() {
		return ErrInvalid
	}
	b := payload.Batch
	if !UUID(b.ID) || !UUID(b.DatabaseEpoch) || b.Limit < 1 || b.Limit > 128 || b.RetentionYears < 1 || b.RetentionYears > 10 || b.Events < 0 || b.Events > b.Limit || b.PreviousEpochEvents < 0 || b.PreviousEpochEvents > b.Events || b.ArchivedAt.IsZero() || b.Cutoff.After(b.ArchivedAt.Add(-90*24*time.Hour)) || b.RetainUntil.Before(utcYear(b.ArchivedAt, b.RetentionYears)) || len(payload.Events) != b.Events || payload.Events == nil || payload.Recoveries == nil || len(payload.Recoveries) > MaxRecoveries {
		return ErrInvalid
	}
	seenEvents := map[string]bool{}
	needed := map[string]string{}
	if b.DatabaseEpoch != payload.OperationEpoch {
		needed[b.DatabaseEpoch] = payload.OperationEpoch
	}
	previous, totalAcks := 0, 0
	for _, event := range payload.Events {
		if !UUID(event.ID) || seenEvents[event.ID] || event.BatchID != b.ID || event.BatchEpoch != b.DatabaseEpoch || !UUID(event.DatabaseEpoch) || !topics[event.Topic] || event.SourceCreatedAt.IsZero() || event.SourceCreatedAt.After(b.Cutoff) || !event.ArchivedAt.Equal(b.ArchivedAt) || !event.RetainUntil.Equal(b.RetainUntil) || event.Acknowledgements == nil {
			return ErrInvalid
		}
		seenEvents[event.ID] = true
		if event.DatabaseEpoch == b.DatabaseEpoch {
			if event.Reason != "covered" {
				return ErrInvalid
			}
		} else {
			if event.Reason != "recovered_epoch" {
				return ErrInvalid
			}
			previous++
			needed[event.DatabaseEpoch] = b.DatabaseEpoch
		}
		source, err := sourceObject(event.Source)
		if err != nil {
			return err
		}
		for _, name := range []string{"id", "database_epoch", "topic", "created_at", "published_at", "producer_xid", "payload"} {
			if _, ok := source[name]; !ok {
				return ErrInvalid
			}
		}
		created, err := sourceTime(source, "created_at")
		if err != nil || !created.Equal(event.SourceCreatedAt) || sourceString(source, "id") != event.ID || sourceString(source, "database_epoch") != event.DatabaseEpoch || sourceString(source, "topic") != event.Topic || !validXID(source["producer_xid"]) {
			return ErrInvalid
		}
		if _, err := sourceObject(source["payload"]); err != nil {
			return err
		}
		if string(source["published_at"]) != "null" {
			published, err := sourceTime(source, "published_at")
			if err != nil || event.Reason == "covered" && published.After(b.Cutoff) {
				return ErrInvalid
			}
		} else if event.Reason == "covered" {
			return ErrInvalid
		}
		seenNodes := map[string]bool{}
		for _, ack := range event.Acknowledgements {
			totalAcks++
			if totalAcks > MaxAcknowledgements || !UUID(ack.NodeID) || ack.EventID != event.ID || ack.AppliedAt.IsZero() || seenNodes[ack.NodeID] {
				return ErrInvalid
			}
			seenNodes[ack.NodeID] = true
			original, err := sourceObject(ack.Source)
			if err != nil {
				return err
			}
			at, err := sourceTime(original, "applied_at")
			if err != nil || !at.Equal(ack.AppliedAt) || sourceString(original, "node_id") != ack.NodeID || sourceString(original, "event_id") != ack.EventID {
				return ErrInvalid
			}
		}
	}
	if previous != b.PreviousEpochEvents {
		return ErrInvalid
	}
	bySource := map[string][]string{}
	seenRecovery := map[string]bool{}
	seenTargets := map[string]bool{}
	for _, r := range payload.Recoveries {
		if !UUID(r.ID) || seenRecovery[r.ID] || !UUID(r.SourceEpoch) || !UUID(r.TargetEpoch) || seenTargets[r.TargetEpoch] || r.SourceEpoch == r.TargetEpoch || r.PreparedAt.IsZero() || r.ReleasedAt.Before(r.PreparedAt) || !digest.MatchString(r.AuthoritySHA256) {
			return ErrInvalid
		}
		if _, err := sourceObject(r.Counts); err != nil {
			return err
		}
		seenRecovery[r.ID] = true
		seenTargets[r.TargetEpoch] = true
		bySource[r.SourceEpoch] = append(bySource[r.SourceEpoch], r.TargetEpoch)
	}
	for source, target := range needed {
		seen := map[string]bool{source: true}
		queue := []string{source}
		for len(queue) > 0 && !seen[target] {
			current := queue[0]
			queue = queue[1:]
			for _, next := range bySource[current] {
				if !seen[next] {
					seen[next] = true
					queue = append(queue, next)
				}
			}
		}
		if !seen[target] {
			return ErrInvalid
		}
	}
	return nil
}

type wirePayload Payload

func Encode(payload Payload) ([]byte, error) {
	if err := payload.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(wirePayload(payload))
	if err != nil || len(body) > MaxPlaintext || auth.ValidateJSONObject(body) != nil {
		clear(body)
		return nil, ErrInvalid
	}
	return body, nil
}

func Decode(body []byte) (Payload, error) {
	if len(body) == 0 || len(body) > MaxPlaintext || !utf8.Valid(body) || auth.ValidateJSONObject(body) != nil {
		return Payload{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var result wirePayload
	if decoder.Decode(&result) != nil {
		return Payload{}, ErrInvalid
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return Payload{}, ErrInvalid
	}
	payload := Payload(result)
	if payload.Validate() != nil {
		return Payload{}, ErrInvalid
	}
	return payload, nil
}

// Sort canonicalizes query ordering before hashing/retry. It changes no facts.
func Sort(payload *Payload) {
	sort.Slice(payload.Events, func(i, j int) bool { return payload.Events[i].ID < payload.Events[j].ID })
	for i := range payload.Events {
		sort.Slice(payload.Events[i].Acknowledgements, func(a, b int) bool {
			return payload.Events[i].Acknowledgements[a].NodeID < payload.Events[i].Acknowledgements[b].NodeID
		})
	}
	sort.Slice(payload.Recoveries, func(i, j int) bool { return payload.Recoveries[i].ID < payload.Recoveries[j].ID })
}
