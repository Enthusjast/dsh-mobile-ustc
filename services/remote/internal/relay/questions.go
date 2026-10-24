package relay

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"unicode"
	"unicode/utf8"
)

type questionAnswerPayload struct {
	QuestionID string               `json:"question_id"`
	Answers    []questionAnswerItem `json:"answers"`
}
type questionAnswerItem struct {
	ID       string   `json:"id"`
	Selected []string `json:"selected"`
	Custom   *string  `json:"custom,omitempty"`
}

func (item *questionAnswerItem) UnmarshalJSON(data []byte) error {
	type fields questionAnswerItem
	var decoded fields
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	var raw struct {
		Custom json.RawMessage `json:"custom"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if len(raw.Custom) != 0 && decoded.Custom == nil {
		return errors.New("relay: null question answer text")
	}
	*item = questionAnswerItem(decoded)
	return nil
}

func questionText(value string, max int) bool {
	if utf8.RuneCountInString(value) > max {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) && char != '\t' && char != '\n' && char != '\r' {
			return false
		}
	}
	return true
}

func validQuestionAnswer(payload questionAnswerPayload) bool {
	if !uuidPattern.MatchString(payload.QuestionID) || len(payload.Answers) == 0 || len(payload.Answers) > 32 {
		return false
	}
	ids := map[string]bool{}
	for _, item := range payload.Answers {
		if item.ID == "" || !questionText(item.ID, 128) || ids[item.ID] || item.Selected == nil || len(item.Selected) > 32 || (item.Custom != nil && !questionText(*item.Custom, 16384)) {
			return false
		}
		ids[item.ID] = true
		selected := map[string]bool{}
		for _, label := range item.Selected {
			if !questionText(label, 4096) || selected[label] {
				return false
			}
			selected[label] = true
		}
	}
	return true
}

func questionAnswerDigest(sessionID, epoch string, payload questionAnswerPayload) string {
	return questionAnswerTypeDigest("question.answer", sessionID, epoch, payload)
}

func questionAnswerTypeDigest(kind, sessionID, epoch string, payload questionAnswerPayload) string {
	encoded := []byte(`{"payload":{"answers":[`)
	for index, answer := range payload.Answers {
		if index > 0 {
			encoded = append(encoded, ',')
		}
		encoded = append(encoded, '{')
		if answer.Custom != nil {
			encoded = append(encoded, `"custom":`...)
			encoded = appendJSONString(encoded, *answer.Custom)
			encoded = append(encoded, ',')
		}
		encoded = append(encoded, `"id":`...)
		encoded = appendJSONString(encoded, answer.ID)
		encoded = append(encoded, `,"selected":[`...)
		for index, label := range answer.Selected {
			if index > 0 {
				encoded = append(encoded, ',')
			}
			encoded = appendJSONString(encoded, label)
		}
		encoded = append(encoded, `]}`...)
	}
	encoded = append(encoded, `],"question_id":`...)
	encoded = appendJSONString(encoded, payload.QuestionID)
	encoded = append(encoded, `},"runtime_epoch":`...)
	encoded = appendJSONString(encoded, epoch)
	encoded = append(encoded, `,"session_id":`...)
	encoded = appendJSONString(encoded, sessionID)
	encoded = append(encoded, `,"type":`...)
	encoded = appendJSONString(encoded, kind)
	encoded = append(encoded, '}')
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
