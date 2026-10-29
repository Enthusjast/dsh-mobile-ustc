// Package auditarchive defines bounded encrypted audit-history files.
package auditarchive

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strconv"
	"time"
	"unicode/utf8"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/coldarchive"
)

const MaxPlaintext = coldarchive.MaxExtendedPlaintext
const MaxArtifact = coldarchive.MaxExtendedArtifact
const MaxSource = 256 << 10

var databaseUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Batch struct {
	ID             string    `json:"id"`
	DatabaseEpoch  string    `json:"database_epoch"`
	Limit          int       `json:"limit"`
	RetentionYears int       `json:"retention_years"`
	Cutoff         time.Time `json:"cutoff"`
	ArchivedAt     time.Time `json:"archived_at"`
	RetainUntil    time.Time `json:"retain_until"`
	Entries        int       `json:"entries"`
}

type Entry struct {
	SourceID    int64     `json:"source_id"`
	SourceEpoch *string   `json:"source_epoch"`
	SourceTime  time.Time `json:"source_time"`
	Source      []byte    `json:"source_base64"`
}

type Payload struct {
	Format         string                 `json:"format"`
	Version        int                    `json:"version"`
	DomainID       string                 `json:"domain_id"`
	ExportID       string                 `json:"export_id"`
	OperationEpoch string                 `json:"operation_epoch"`
	KeyID          string                 `json:"key_id"`
	PreparedAt     time.Time              `json:"prepared_at"`
	Batch          Batch                  `json:"batch"`
	Entries        []Entry                `json:"entries"`
	Recoveries     []coldarchive.Recovery `json:"recoveries"`
}

func (Payload) String() string               { return "auditarchive.Payload" }
func (Payload) GoString() string             { return "auditarchive.Payload" }
func (Payload) MarshalJSON() ([]byte, error) { return nil, coldarchive.ErrInvalid }
func (Entry) String() string                 { return "auditarchive.Entry" }
func (Entry) GoString() string               { return "auditarchive.Entry" }

func utcYear(value time.Time, years int) time.Time {
	value = value.UTC()
	year, month, day := value.Date()
	target := year + years
	if month == time.February && day == 29 && (target%4 != 0 || (target%100 == 0 && target%400 != 0)) {
		day = 28
	}
	return time.Date(target, month, day, value.Hour(), value.Minute(), value.Second(), value.Nanosecond(), time.UTC)
}

func validateEntry(entry Entry, cutoff time.Time) error {
	if entry.SourceTime.IsZero() || entry.SourceTime.After(cutoff) || len(entry.Source) == 0 || len(entry.Source) > MaxSource || auth.ValidateJSONObject(entry.Source) != nil {
		return coldarchive.ErrInvalid
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(entry.Source, &fields) != nil {
		return coldarchive.ErrInvalid
	}
	for _, name := range []string{"id", "ts", "org_id", "actor_type", "actor_id", "device_id", "runtime_id", "session_id", "action", "result", "metadata", "database_epoch", "producer_xid"} {
		if _, ok := fields[name]; !ok {
			return coldarchive.ErrInvalid
		}
	}
	var sourceID int64
	var sourceTime, actorType string
	var sourceEpoch *string
	if json.Unmarshal(fields["id"], &sourceID) != nil || sourceID != entry.SourceID || json.Unmarshal(fields["ts"], &sourceTime) != nil || json.Unmarshal(fields["database_epoch"], &sourceEpoch) != nil ||
		json.Unmarshal(fields["actor_type"], &actorType) != nil || (actorType != "user" && actorType != "device" && actorType != "installation" && actorType != "system") || auth.ValidateJSONObject(fields["metadata"]) != nil {
		return coldarchive.ErrInvalid
	}
	stamp, err := time.Parse(time.RFC3339Nano, sourceTime)
	if err != nil || !stamp.Equal(entry.SourceTime) || (sourceEpoch == nil) != (entry.SourceEpoch == nil) {
		return coldarchive.ErrInvalid
	}
	if sourceEpoch != nil && (!coldarchive.UUID(*sourceEpoch) || *sourceEpoch != *entry.SourceEpoch) {
		return coldarchive.ErrInvalid
	}
	xid := fields["producer_xid"]
	if string(xid) == "null" {
		if sourceEpoch != nil {
			return coldarchive.ErrInvalid
		}
	} else {
		var text string
		if json.Unmarshal(xid, &text) != nil {
			text = string(xid)
		}
		value, err := strconv.ParseUint(text, 10, 64)
		if err != nil || value == 0 || strconv.FormatUint(value, 10) != text || sourceEpoch == nil {
			return coldarchive.ErrInvalid
		}
	}
	for _, field := range []string{"actor_id", "action", "result"} {
		var value string
		if string(fields[field]) == "null" || json.Unmarshal(fields[field], &value) != nil {
			return coldarchive.ErrInvalid
		}
	}
	for _, field := range []string{"org_id", "device_id", "runtime_id", "session_id"} {
		var value *string
		if json.Unmarshal(fields[field], &value) != nil || value != nil && !databaseUUID.MatchString(*value) {
			return coldarchive.ErrInvalid
		}
	}
	return nil
}

func (payload Payload) Validate() error {
	if payload.Format != "dsh-audit-archive" || payload.Version != 1 || !coldarchive.UUID(payload.DomainID) || !coldarchive.UUID(payload.ExportID) || !coldarchive.UUID(payload.OperationEpoch) ||
		!coldarchive.KeyID(payload.KeyID) || payload.PreparedAt.IsZero() || payload.Entries == nil {
		return coldarchive.ErrInvalid
	}
	b := payload.Batch
	if !coldarchive.UUID(b.ID) || !coldarchive.UUID(b.DatabaseEpoch) || b.Limit < 1 || b.Limit > 128 || b.RetentionYears < 1 || b.RetentionYears > 10 || b.Entries < 0 || b.Entries > b.Limit ||
		len(payload.Entries) != b.Entries || b.ArchivedAt.IsZero() || b.ArchivedAt.After(payload.PreparedAt) || b.Cutoff.After(b.ArchivedAt.Add(-90*24*time.Hour)) || b.RetainUntil.Before(utcYear(b.ArchivedAt, b.RetentionYears)) {
		return coldarchive.ErrInvalid
	}
	seenIDs, seenEpochs := map[int64]bool{}, map[string]bool{}
	paths := []coldarchive.RecoveryPath{{Source: b.DatabaseEpoch, Target: payload.OperationEpoch}}
	for _, entry := range payload.Entries {
		if seenIDs[entry.SourceID] || validateEntry(entry, b.Cutoff) != nil {
			return coldarchive.ErrInvalid
		}
		seenIDs[entry.SourceID] = true
		if entry.SourceEpoch != nil && !seenEpochs[*entry.SourceEpoch] {
			seenEpochs[*entry.SourceEpoch] = true
			paths = append(paths, coldarchive.RecoveryPath{Source: *entry.SourceEpoch, Target: b.DatabaseEpoch})
		}
	}
	if coldarchive.ValidateRecoveryPaths(payload.Recoveries, paths, payload.PreparedAt) != nil {
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
	if err != nil || len(raw) > MaxPlaintext || auth.ValidateJSONObject(raw) != nil {
		clear(raw)
		return nil, coldarchive.ErrInvalid
	}
	return raw, nil
}

func Decode(raw []byte) (Payload, error) {
	if len(raw) == 0 || len(raw) > MaxPlaintext || !utf8.Valid(raw) || auth.ValidateJSONObject(raw) != nil {
		return Payload{}, coldarchive.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var wire wirePayload
	if decoder.Decode(&wire) != nil {
		partial := Payload(wire)
		Clear(&partial)
		return Payload{}, coldarchive.ErrInvalid
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		partial := Payload(wire)
		Clear(&partial)
		return Payload{}, coldarchive.ErrInvalid
	}
	payload := Payload(wire)
	if payload.Validate() != nil {
		Clear(&payload)
		return Payload{}, coldarchive.ErrInvalid
	}
	return payload, nil
}

func Open(key *coldarchive.Key, artifact []byte, domainID, exportID string) (Payload, error) {
	if key == nil || !coldarchive.UUID(domainID) || !coldarchive.UUID(exportID) {
		return Payload{}, coldarchive.ErrInvalid
	}
	raw, err := coldarchive.OpenEncodedWithLimit(key, artifact, MaxPlaintext)
	if err != nil {
		return Payload{}, err
	}
	defer clear(raw)
	payload, err := Decode(raw)
	if err != nil || payload.DomainID != domainID || payload.ExportID != exportID || subtle.ConstantTimeCompare([]byte(payload.KeyID), []byte(key.ID())) != 1 {
		Clear(&payload)
		return Payload{}, coldarchive.ErrInvalid
	}
	return payload, nil
}

func Sort(payload *Payload) {
	sort.Slice(payload.Entries, func(i, j int) bool { return payload.Entries[i].SourceID < payload.Entries[j].SourceID })
	sort.Slice(payload.Recoveries, func(i, j int) bool { return payload.Recoveries[i].ID < payload.Recoveries[j].ID })
}

// Clear releases the caller-owned decoded source buffers after use.
func Clear(payload *Payload) {
	for i := range payload.Entries {
		clear(payload.Entries[i].Source)
		payload.Entries[i].Source = nil
	}
	for i := range payload.Recoveries {
		clear(payload.Recoveries[i].Counts)
		payload.Recoveries[i].Counts = nil
	}
}
