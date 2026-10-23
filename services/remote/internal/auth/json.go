package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

var errInvalidJSON = errors.New("auth: invalid JSON object")

// decodeObject rejects duplicate members so signature and policy checks see one unambiguous value.
func decodeObject(data []byte) (map[string]any, error) {
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

// ValidateJSONObject rejects duplicate members at every nesting level.
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
