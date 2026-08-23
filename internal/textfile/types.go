// Package textfile provides bounded, encoding-aware text decoding, editing,
// diffing, and re-encoding.
package textfile

import (
	"errors"
	"fmt"
)

const (
	DefaultMaxInputBytes   = 8 << 20
	DefaultMaxDecodedBytes = 16 << 20
	DefaultMaxEncodedBytes = 16 << 20
	DefaultMaxEdits        = 128
	DefaultMaxMatches      = 10_000

	hardMaxBytes   = 64 << 20
	hardMaxEdits   = 4_096
	hardMaxMatches = 1_000_000
)

var (
	ErrTooLarge        = errors.New("textfile: size limit exceeded")
	ErrBinary          = errors.New("textfile: binary content rejected")
	ErrInvalidEncoding = errors.New("textfile: invalid encoded content")
	ErrInvalidOptions  = errors.New("textfile: invalid options")
	ErrNotFound        = errors.New("textfile: replacement target not found")
	ErrAmbiguousMatch  = errors.New("textfile: replacement target is not unique")
	ErrEditConflict    = errors.New("textfile: edits overlap")
	ErrTooManyEdits    = errors.New("textfile: edit limit exceeded")
	ErrDiffTooComplex  = errors.New("textfile: diff complexity limit exceeded")
)

// Encoding identifies the byte encoding of a decoded file.
type Encoding string

const (
	EncodingUTF8     Encoding = "utf-8"
	EncodingUTF16LE  Encoding = "utf-16le"
	EncodingUTF16BE  Encoding = "utf-16be"
	EncodingEUCKR    Encoding = "euc-kr"
	EncodingShiftJIS Encoding = "shift-jis"
	EncodingISO88591 Encoding = "iso-8859-1"
)

// BOM identifies a byte-order mark present in the source.
type BOM string

const (
	BOMNone    BOM = "none"
	BOMUTF8    BOM = "utf-8"
	BOMUTF16LE BOM = "utf-16le"
	BOMUTF16BE BOM = "utf-16be"
)

// Bytes returns a fresh copy of the BOM bytes.
func (b BOM) Bytes() []byte {
	switch b {
	case BOMNone:
		return nil
	case BOMUTF8:
		return []byte{0xef, 0xbb, 0xbf}
	case BOMUTF16LE:
		return []byte{0xff, 0xfe}
	case BOMUTF16BE:
		return []byte{0xfe, 0xff}
	default:
		return nil
	}
}

// NewlineStyle describes line endings in decoded text. Mixed is reported only
// as metadata; it is not a valid output newline override.
type NewlineStyle string

const (
	NewlineNone  NewlineStyle = "none"
	NewlineLF    NewlineStyle = "lf"
	NewlineCRLF  NewlineStyle = "crlf"
	NewlineCR    NewlineStyle = "cr"
	NewlineMixed NewlineStyle = "mixed"
)

// Metadata records properties detected from the original bytes. Confidence is
// in [0,1], where BOM-based detection is 1 and ISO-8859-1 fallback is low.
type Metadata struct {
	Encoding        Encoding
	BOM             BOM
	NewlineStyle    NewlineStyle
	DominantNewline NewlineStyle
	LFCount         int
	CRLFCount       int
	CRCount         int
	Confidence      float64
}

// Limits bounds all externally controlled work and output. Zero fields use
// defaults. Values above the hard package caps are rejected.
type Limits struct {
	MaxInputBytes   int
	MaxDecodedBytes int
	MaxEncodedBytes int
	MaxEdits        int
	MaxMatches      int
}

func DefaultLimits() Limits {
	return Limits{
		MaxInputBytes:   DefaultMaxInputBytes,
		MaxDecodedBytes: DefaultMaxDecodedBytes,
		MaxEncodedBytes: DefaultMaxEncodedBytes,
		MaxEdits:        DefaultMaxEdits,
		MaxMatches:      DefaultMaxMatches,
	}
}

func resolveLimits(in Limits) (Limits, error) {
	out := in
	defaults := DefaultLimits()
	if out.MaxInputBytes == 0 {
		out.MaxInputBytes = defaults.MaxInputBytes
	}
	if out.MaxDecodedBytes == 0 {
		out.MaxDecodedBytes = defaults.MaxDecodedBytes
	}
	if out.MaxEncodedBytes == 0 {
		out.MaxEncodedBytes = defaults.MaxEncodedBytes
	}
	if out.MaxEdits == 0 {
		out.MaxEdits = defaults.MaxEdits
	}
	if out.MaxMatches == 0 {
		out.MaxMatches = defaults.MaxMatches
	}
	if out.MaxInputBytes < 0 || out.MaxInputBytes > hardMaxBytes ||
		out.MaxDecodedBytes < 0 || out.MaxDecodedBytes > hardMaxBytes ||
		out.MaxEncodedBytes < 0 || out.MaxEncodedBytes > hardMaxBytes ||
		out.MaxEdits < 0 || out.MaxEdits > hardMaxEdits ||
		out.MaxMatches < 0 || out.MaxMatches > hardMaxMatches {
		return Limits{}, fmt.Errorf("%w: limits must be positive and within hard caps", ErrInvalidOptions)
	}
	return out, nil
}
