package relay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"unicode/utf16"

	"dsh-mobile-ustc/services/remote/internal/canonical"
)

const modelSelectionCapability = "session.model.select.v1"

type modelSelectionPayload struct {
	Provider        string `json:"provider"`
	Model           string `json:"model"`
	ReasoningEffort string `json:"reasoning_effort,omitempty"`
}

func (payload *modelSelectionPayload) UnmarshalJSON(raw []byte) error {
	type plain modelSelectionPayload
	var decoded plain
	if err := decodePayload(raw, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	if _, present := fields["reasoning_effort"]; present && decoded.ReasoningEffort == "" {
		return errors.New("relay: empty or null reasoning effort")
	}
	*payload = modelSelectionPayload(decoded)
	return nil
}

func validModelSelection(payload modelSelectionPayload) bool {
	// Match the existing TypeScript payload's UTF-16 string limits. Identifiers
	// select opaque catalog entries; they do not supply provider configuration.
	length := func(value string) int { return len(utf16.Encode([]rune(value))) }
	return length(payload.Provider) >= 1 && length(payload.Provider) <= 128 &&
		length(payload.Model) >= 1 && length(payload.Model) <= 128 && length(payload.ReasoningEffort) <= 64
}

func modelSelectionDigest(sessionID, epoch string, payload modelSelectionPayload) (string, error) {
	raw, err := json.Marshal(map[string]any{"type": "session.model.select", "runtime_epoch": epoch, "session_id": sessionID, "payload": payload})
	if err != nil {
		return "", err
	}
	encoded, err := canonical.Object(raw)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
