package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"
)

var errInvalidJSON = errors.New("auth: invalid JSON object")

// decodeObject rejects duplicate members so signature and policy checks see one unambiguous value.
func decodeObject(data []byte) (map[string]any, error) {
	if !utf8.Valid(data) || !validJSONSurrogates(data) {
		return nil, errInvalidJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := readJSONValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, errInvalidJSON
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errInvalidJSON
	}
	return value.(map[string]any), nil
}

// ValidateJSONObject rejects duplicate members and invalid Unicode at every nesting level.
func ValidateJSONObject(data []byte) error {
	_, err := decodeObject(data)
	return err
}

func readJSONValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, errInvalidJSON
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, errInvalidJSON
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return nil, errInvalidJSON
				}
				name, ok := key.(string)
				if !ok {
					return nil, errInvalidJSON
				}
				if _, exists := object[name]; exists {
					return nil, errInvalidJSON
				}
				member, err := readJSONValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				object[name] = member
			}
			if _, err := decoder.Token(); err != nil {
				return nil, errInvalidJSON
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				item, err := readJSONValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, item)
			}
			if _, err := decoder.Token(); err != nil {
				return nil, errInvalidJSON
			}
			return array, nil
		default:
			return nil, errInvalidJSON
		}
	default:
		return token, nil
	}
}

// encoding/json replaces lone surrogate escapes. Reject them in the original
// bytes instead of signing a substituted value; escaped literal backslashes
// remain ordinary text.
func validJSONSurrogates(raw []byte) bool {
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
