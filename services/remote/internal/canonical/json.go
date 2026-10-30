package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"unicode/utf8"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const MaxBytes = 128 * 1024

var ErrInvalid = errors.New("canonical: invalid JSON object")

// Object applies RFC 8785 to a bounded, unambiguous I-JSON object. Duplicate
// names, invalid UTF-8/UTF-16, non-finite numbers and excessive depth are errors.
func Object(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > MaxBytes || !utf8.Valid(raw) || auth.ValidateJSONObject(raw) != nil {
		return nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return nil, ErrInvalid
	}
	nodes := 0
	if !validValue(value, 0, &nodes) {
		return nil, ErrInvalid
	}
	encoded, err := jsoncanonicalizer.Transform(raw)
	if err != nil || len(encoded) > MaxBytes {
		return nil, ErrInvalid
	}
	return encoded, nil
}

func validValue(value any, depth int, nodes *int) bool {
	*nodes++
	if depth > 32 || *nodes > 16384 {
		return false
	}
	switch item := value.(type) {
	case json.Number:
		number, err := strconv.ParseFloat(string(item), 64)
		return err == nil && !math.IsInf(number, 0) && !math.IsNaN(number)
	case map[string]any:
		for _, member := range item {
			if !validValue(member, depth+1, nodes) {
				return false
			}
		}
	case []any:
		for _, member := range item {
			if !validValue(member, depth+1, nodes) {
				return false
			}
		}
	}
	return true
}
