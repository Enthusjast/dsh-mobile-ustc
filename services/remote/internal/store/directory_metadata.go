package store

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"

	"dsh-mobile-ustc/services/remote/internal/auth"
)

const DirectoryMetadataCapability = "session.metadata.v1"

// DirectoryMetadata is an untrusted display projection, never an address or authority.
type DirectoryMetadata struct {
	Version        int     `json:"v"`
	Title          *string `json:"title"`
	WorkspaceTitle *string `json:"workspace_title"`
	TitleSource    *string `json:"title_source"`
	TitleAsOfSeq   *int64  `json:"title_as_of_seq"`
}

func validDirectoryName(value *string) bool {
	if value == nil {
		return true
	}
	if !utf8.ValidString(*value) || len(*value) > 1024 || strings.TrimSpace(*value) == "" {
		return false
	}
	units := 0
	for _, character := range *value {
		if character <= 0x1f || character >= 0x7f && character <= 0x9f || character == 0x061c || character == 0x200e || character == 0x200f ||
			character == 0x2028 || character == 0x2029 || character >= 0x202a && character <= 0x202e || character >= 0x2066 && character <= 0x2069 {
			return false
		}
		units++
		if character > 0xffff {
			units++
		}
		if units > 256 {
			return false
		}
	}
	return true
}

func (metadata *DirectoryMetadata) Valid() bool {
	if metadata == nil {
		return true
	}
	if metadata.Version != 1 || !validDirectoryName(metadata.Title) || !validDirectoryName(metadata.WorkspaceTitle) {
		return false
	}
	if metadata.Title == nil {
		return metadata.TitleSource == nil && metadata.TitleAsOfSeq == nil
	}
	return metadata.TitleSource != nil && (*metadata.TitleSource == "cached" || *metadata.TitleSource == "sequenced") &&
		metadata.TitleAsOfSeq != nil && *metadata.TitleAsOfSeq >= -1 && *metadata.TitleAsOfSeq <= 9007199254740991
}

// UnmarshalJSON requires the complete versioned shape, including authoritative nulls.
func (metadata *DirectoryMetadata) UnmarshalJSON(raw []byte) error {
	var keys map[string]json.RawMessage
	if len(raw) > 4096 || auth.ValidateJSONObject(raw) != nil || json.Unmarshal(raw, &keys) != nil || len(keys) != 5 {
		return ErrSessionCatalogInvalid
	}
	for _, key := range []string{"v", "title", "workspace_title", "title_source", "title_as_of_seq"} {
		if _, exists := keys[key]; !exists {
			return ErrSessionCatalogInvalid
		}
	}
	type plain DirectoryMetadata
	var parsed plain
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&parsed) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrSessionCatalogInvalid
	}
	value := DirectoryMetadata(parsed)
	if !value.Valid() {
		return ErrSessionCatalogInvalid
	}
	*metadata = value
	return nil
}
