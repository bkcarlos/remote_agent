package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// DecodeStrict rejects unknown fields, duplicate object keys, trailing values,
// and ambiguous JSON before decoding into a typed request structure.
func DecodeStrict(raw []byte, target any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return errors.New("empty JSON value")
	}
	tokens := json.NewDecoder(bytes.NewReader(raw))
	if err := consumeValue(tokens); err != nil {
		return err
	}
	if _, err := tokens.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func consumeValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for dec.More() {
			if err := consumeValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
