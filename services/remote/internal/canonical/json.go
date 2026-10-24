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
	if len(raw) == 0 || len(raw) > MaxBytes || !utf8.Valid(raw) || auth.ValidateJSONObject(raw) != nil || !validSurrogates(raw) {
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

// encoding/json replaces lone surrogate escapes. Reject them in the original
// bytes instead of signing a substituted value; escaped literal backslashes
// remain ordinary text.
func validSurrogates(raw []byte) bool {
	for index := 0; index < len(raw); index++ {
		if raw[index] != '\\' {
			continue
		}
		index++
		if index >= len(raw) || raw[index] != 'u' {
			continue
		}
		if index+4 >= len(raw) {
			return false
		}
		code, err := strconv.ParseUint(string(raw[index+1:index+5]), 16, 16)
		if err != nil {
			return false
		}
		index += 4
		if code >= 0xdc00 && code <= 0xdfff {
			return false
		}
		if code < 0xd800 || code > 0xdbff {
			continue
		}
		if index+6 >= len(raw) || raw[index+1] != '\\' || raw[index+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(raw[index+3:index+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		index += 6
	}
	return true
}
