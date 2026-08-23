package textfile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/korean"
	textunicode "golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// File contains UTF-8 text and immutable metadata about its source bytes.
// Its methods are safe for concurrent use.
type File struct {
	mu     sync.RWMutex
	text   string
	meta   Metadata
	limits Limits
}

// Decode detects and decodes supported text bytes. It rejects oversized,
// malformed, and binary input before returning a File.
func Decode(data []byte, limits Limits) (*File, error) {
	resolved, err := resolveLimits(limits)
	if err != nil {
		return nil, err
	}
	if len(data) > resolved.MaxInputBytes {
		return nil, fmt.Errorf("%w: input is %d bytes, limit is %d", ErrTooLarge, len(data), resolved.MaxInputBytes)
	}

	text, meta, err := detectAndDecode(data, resolved)
	if err != nil {
		return nil, err
	}
	if len(text) > resolved.MaxDecodedBytes {
		return nil, fmt.Errorf("%w: decoded text is %d bytes, limit is %d", ErrTooLarge, len(text), resolved.MaxDecodedBytes)
	}
	if isBinary(text) {
		return nil, ErrBinary
	}
	meta.NewlineStyle, meta.DominantNewline, meta.LFCount, meta.CRLFCount, meta.CRCount = inspectNewlines(text)
	return &File{text: text, meta: meta, limits: resolved}, nil
}

// Text returns the current decoded UTF-8 text.
func (f *File) Text() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.text
}

// Metadata returns properties detected from the original input.
func (f *File) Metadata() Metadata { return f.meta }

// Encode serializes current text using the original encoding and BOM while
// preserving its current line endings.
func (f *File) Encode() ([]byte, error) {
	return f.EncodeWithNewline(NewlineNone)
}

// EncodeWithNewline serializes current text with an explicit newline style.
// NewlineNone preserves current line endings; LF, CRLF, and CR normalize them.
func (f *File) EncodeWithNewline(style NewlineStyle) ([]byte, error) {
	if style != NewlineNone && style != NewlineLF && style != NewlineCRLF && style != NewlineCR {
		return nil, fmt.Errorf("%w: invalid output newline %q", ErrInvalidOptions, style)
	}
	f.mu.RLock()
	text := f.text
	f.mu.RUnlock()

	normalized, err := normalizeNewlines(text, style, f.limits.MaxEncodedBytes)
	if err != nil {
		return nil, err
	}
	bom := f.meta.BOM.Bytes()
	if len(bom) > f.limits.MaxEncodedBytes {
		return nil, ErrTooLarge
	}
	bodyLimit := f.limits.MaxEncodedBytes - len(bom)
	var body []byte
	if f.meta.Encoding == EncodingUTF8 {
		if len(normalized) > bodyLimit {
			return nil, fmt.Errorf("%w: encoded output exceeds %d bytes", ErrTooLarge, f.limits.MaxEncodedBytes)
		}
		body = []byte(normalized)
	} else {
		enc, ok := transformerFor(f.meta.Encoding)
		if !ok {
			return nil, fmt.Errorf("%w: unsupported encoding %q", ErrInvalidEncoding, f.meta.Encoding)
		}
		body, err = encodeLimited(enc, normalized, bodyLimit)
		if err != nil {
			if errors.Is(err, ErrTooLarge) {
				return nil, fmt.Errorf("%w: encoded output exceeds %d bytes", ErrTooLarge, f.limits.MaxEncodedBytes)
			}
			return nil, fmt.Errorf("%w: cannot encode as %s: %v", ErrInvalidEncoding, f.meta.Encoding, err)
		}
	}
	out := make([]byte, 0, len(bom)+len(body))
	out = append(out, bom...)
	out = append(out, body...)
	return out, nil
}

func detectAndDecode(data []byte, limits Limits) (string, Metadata, error) {
	switch {
	case bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}):
		body := data[3:]
		if !utf8.Valid(body) {
			return "", Metadata{}, fmt.Errorf("%w: malformed UTF-8 after BOM", ErrInvalidEncoding)
		}
		return string(body), Metadata{Encoding: EncodingUTF8, BOM: BOMUTF8, Confidence: 1}, nil
	case bytes.HasPrefix(data, []byte{0xff, 0xfe}):
		return decodeAuthoritativeUTF16(data[2:], EncodingUTF16LE, BOMUTF16LE, limits)
	case bytes.HasPrefix(data, []byte{0xfe, 0xff}):
		return decodeAuthoritativeUTF16(data[2:], EncodingUTF16BE, BOMUTF16BE, limits)
	}

	if text, enc, confidence, ok := detectUTF16(data, limits); ok {
		return text, Metadata{Encoding: enc, BOM: BOMNone, Confidence: confidence}, nil
	}
	if utf8.Valid(data) {
		return string(data), Metadata{Encoding: EncodingUTF8, BOM: BOMNone, Confidence: 0.99}, nil
	}

	type candidate struct {
		enc        Encoding
		transform  encoding.Encoding
		confidence float64
		text       string
	}
	candidates := []candidate{
		{enc: EncodingEUCKR, transform: korean.EUCKR},
		{enc: EncodingShiftJIS, transform: japanese.ShiftJIS},
	}
	var best *candidate
	for i := range candidates {
		decoded, err := decodeLimited(candidates[i].transform, data, limits.MaxDecodedBytes)
		if err != nil || isBinary(decoded) {
			continue
		}
		roundTrip, err := encodeLimited(candidates[i].transform, decoded, limits.MaxInputBytes)
		if err != nil || !bytes.Equal(roundTrip, data) {
			continue
		}
		candidates[i].text = decoded
		candidates[i].confidence = legacyConfidence(candidates[i].enc, decoded, data)
		if best == nil || candidates[i].confidence > best.confidence {
			best = &candidates[i]
		}
	}
	if best != nil {
		return best.text, Metadata{Encoding: best.enc, BOM: BOMNone, Confidence: best.confidence}, nil
	}

	decoded, err := decodeLimited(charmap.ISO8859_1, data, limits.MaxDecodedBytes)
	if err != nil {
		if errors.Is(err, ErrTooLarge) {
			return "", Metadata{}, fmt.Errorf("%w: decoded text exceeds %d bytes", ErrTooLarge, limits.MaxDecodedBytes)
		}
		return "", Metadata{}, fmt.Errorf("%w: ISO-8859-1 fallback failed: %v", ErrInvalidEncoding, err)
	}
	return decoded, Metadata{Encoding: EncodingISO88591, BOM: BOMNone, Confidence: 0.25}, nil
}

func decodeAuthoritativeUTF16(data []byte, enc Encoding, bom BOM, limits Limits) (string, Metadata, error) {
	transformer, _ := transformerFor(enc)
	decoded, err := decodeLimited(transformer, data, limits.MaxDecodedBytes)
	if err != nil {
		if errors.Is(err, ErrTooLarge) {
			return "", Metadata{}, fmt.Errorf("%w: decoded text exceeds %d bytes", ErrTooLarge, limits.MaxDecodedBytes)
		}
		return "", Metadata{}, fmt.Errorf("%w: malformed %s content: %v", ErrInvalidEncoding, enc, err)
	}
	roundTrip, err := encodeLimited(transformer, decoded, limits.MaxInputBytes)
	if err != nil || !bytes.Equal(roundTrip, data) {
		return "", Metadata{}, fmt.Errorf("%w: malformed %s code units", ErrInvalidEncoding, enc)
	}
	return decoded, Metadata{Encoding: enc, BOM: bom, Confidence: 1}, nil
}

func detectUTF16(data []byte, limits Limits) (string, Encoding, float64, bool) {
	if len(data) < 4 || len(data)%2 != 0 {
		return "", "", 0, false
	}
	units := len(data) / 2
	evenZeros, oddZeros := 0, 0
	leNewlines, beNewlines := 0, 0
	for i := 0; i < len(data); i += 2 {
		if data[i] == 0 {
			evenZeros++
		}
		if data[i+1] == 0 {
			oddZeros++
		}
		if (data[i] == '\n' || data[i] == '\r') && data[i+1] == 0 {
			leNewlines++
		}
		if data[i] == 0 && (data[i+1] == '\n' || data[i+1] == '\r') {
			beNewlines++
		}
	}

	type guess struct {
		enc        Encoding
		dominant   int
		opposite   int
		newlines   int
		otherLines int
	}
	guesses := []guess{
		{EncodingUTF16LE, oddZeros, evenZeros, leNewlines, beNewlines},
		{EncodingUTF16BE, evenZeros, oddZeros, beNewlines, leNewlines},
	}
	for _, guess := range guesses {
		zeroSignature := guess.dominant*4 >= units && guess.dominant >= guess.opposite*2+1
		newlineSignature := guess.newlines > 0 && guess.otherLines == 0
		if !zeroSignature && !newlineSignature {
			continue
		}
		transformer, _ := transformerFor(guess.enc)
		decoded, err := decodeLimited(transformer, data, limits.MaxDecodedBytes)
		if err != nil || isBinary(decoded) {
			continue
		}
		roundTrip, err := encodeLimited(transformer, decoded, limits.MaxInputBytes)
		if err != nil || !bytes.Equal(roundTrip, data) {
			continue
		}
		asymmetry := float64(guess.dominant-guess.opposite) / float64(units)
		confidence := 0.80 + 0.18*asymmetry
		if confidence > 0.97 {
			confidence = 0.97
		}
		return decoded, guess.enc, confidence, true
	}
	return "", "", 0, false
}

func transformerFor(enc Encoding) (encoding.Encoding, bool) {
	switch enc {
	case EncodingUTF16LE:
		return textunicode.UTF16(textunicode.LittleEndian, textunicode.IgnoreBOM), true
	case EncodingUTF16BE:
		return textunicode.UTF16(textunicode.BigEndian, textunicode.IgnoreBOM), true
	case EncodingEUCKR:
		return korean.EUCKR, true
	case EncodingShiftJIS:
		return japanese.ShiftJIS, true
	case EncodingISO88591:
		return charmap.ISO8859_1, true
	default:
		return nil, false
	}
}

func decodeLimited(enc encoding.Encoding, data []byte, limit int) (string, error) {
	reader := transform.NewReader(bytes.NewReader(data), enc.NewDecoder())
	out, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return "", err
	}
	if len(out) > limit {
		return "", ErrTooLarge
	}
	if !utf8.Valid(out) {
		return "", ErrInvalidEncoding
	}
	return string(out), nil
}

func encodeLimited(enc encoding.Encoding, text string, limit int) ([]byte, error) {
	reader := transform.NewReader(strings.NewReader(text), enc.NewEncoder())
	out, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(out) > limit {
		return nil, ErrTooLarge
	}
	return out, nil
}

func legacyConfidence(enc Encoding, text string, source []byte) float64 {
	nonASCII, likelyScript := 0, 0
	for _, r := range text {
		if r <= unicode.MaxASCII {
			continue
		}
		nonASCII++
		switch enc {
		case EncodingEUCKR:
			if (r >= 0x1100 && r <= 0x11ff) || (r >= 0x3130 && r <= 0x318f) || (r >= 0xac00 && r <= 0xd7af) {
				likelyScript++
			}
		case EncodingShiftJIS:
			if unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Katakana) {
				likelyScript++
			}
		}
	}
	confidence := 0.70
	if nonASCII > 0 {
		confidence += 0.05 + 0.20*float64(likelyScript)/float64(nonASCII)
	}
	// CP949 (used by x/text's EUC-KR implementation) and Shift-JIS have
	// overlapping byte space. A valid 0x81-0x9f Shift-JIS lead is a strong
	// discriminator for ordinary Japanese text when script scores tie.
	if enc == EncodingShiftJIS && hasShiftJISLowLead(source) {
		confidence += 0.03
	}
	if confidence > 0.98 {
		return 0.98
	}
	return confidence
}

func hasShiftJISLowLead(source []byte) bool {
	for i := 0; i+1 < len(source); i++ {
		lead, trail := source[i], source[i+1]
		if lead >= 0x81 && lead <= 0x9f && ((trail >= 0x40 && trail <= 0x7e) || (trail >= 0x80 && trail <= 0xfc)) {
			return true
		}
	}
	return false
}

func isBinary(text string) bool {
	for _, r := range text {
		if r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func inspectNewlines(text string) (NewlineStyle, NewlineStyle, int, int, int) {
	lf, crlf, cr := 0, 0, 0
	first := NewlineNone
	for i := 0; i < len(text); {
		switch text[i] {
		case '\r':
			if i+1 < len(text) && text[i+1] == '\n' {
				crlf++
				if first == NewlineNone {
					first = NewlineCRLF
				}
				i += 2
			} else {
				cr++
				if first == NewlineNone {
					first = NewlineCR
				}
				i++
			}
		case '\n':
			lf++
			if first == NewlineNone {
				first = NewlineLF
			}
			i++
		default:
			i++
		}
	}
	kinds := 0
	if lf > 0 {
		kinds++
	}
	if crlf > 0 {
		kinds++
	}
	if cr > 0 {
		kinds++
	}
	if kinds == 0 {
		return NewlineNone, NewlineNone, 0, 0, 0
	}
	style := first
	if kinds > 1 {
		style = NewlineMixed
	}
	dominant, max := first, -1
	for _, item := range []struct {
		style NewlineStyle
		count int
	}{{NewlineLF, lf}, {NewlineCRLF, crlf}, {NewlineCR, cr}} {
		if item.count > max || (item.count == max && item.style == first) {
			dominant, max = item.style, item.count
		}
	}
	return style, dominant, lf, crlf, cr
}

func normalizeNewlines(text string, style NewlineStyle, limit int) (string, error) {
	if style == NewlineNone {
		if len(text) > limit {
			return "", ErrTooLarge
		}
		return text, nil
	}
	separator := "\n"
	if style == NewlineCRLF {
		separator = "\r\n"
	} else if style == NewlineCR {
		separator = "\r"
	}
	length := 0
	for i := 0; i < len(text); {
		if text[i] == '\r' {
			if i+1 < len(text) && text[i+1] == '\n' {
				i += 2
			} else {
				i++
			}
			length += len(separator)
		} else if text[i] == '\n' {
			i++
			length += len(separator)
		} else {
			i++
			length++
		}
		if length > limit {
			return "", ErrTooLarge
		}
	}
	var builder strings.Builder
	builder.Grow(length)
	for i := 0; i < len(text); {
		if text[i] == '\r' {
			if i+1 < len(text) && text[i+1] == '\n' {
				i += 2
			} else {
				i++
			}
			builder.WriteString(separator)
		} else if text[i] == '\n' {
			i++
			builder.WriteString(separator)
		} else {
			builder.WriteByte(text[i])
			i++
		}
	}
	return builder.String(), nil
}
