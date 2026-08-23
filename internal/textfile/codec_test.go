package textfile

import (
	"bytes"
	"errors"
	"testing"
)

func encodedFixture(t *testing.T, enc Encoding, bom BOM, text string) []byte {
	t.Helper()
	if enc == EncodingUTF8 {
		return append(bom.Bytes(), []byte(text)...)
	}
	transformer, ok := transformerFor(enc)
	if !ok {
		t.Fatalf("missing transformer for %s", enc)
	}
	body, err := encodeLimited(transformer, text, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return append(bom.Bytes(), body...)
}

func TestDecodeEncodeRoundTripAllEncodings(t *testing.T) {
	tests := []struct {
		name string
		enc  Encoding
		bom  BOM
		text string
	}{
		{name: "utf8", enc: EncodingUTF8, bom: BOMNone, text: "hello, 世界\nnext\n"},
		{name: "utf8-bom", enc: EncodingUTF8, bom: BOMUTF8, text: "hello, 世界\nnext\n"},
		{name: "utf16le-bom", enc: EncodingUTF16LE, bom: BOMUTF16LE, text: "hello, 世界\r\nnext\r\n"},
		{name: "utf16be-bom", enc: EncodingUTF16BE, bom: BOMUTF16BE, text: "hello, 世界\rnext\r"},
		{name: "utf16le-no-bom", enc: EncodingUTF16LE, bom: BOMNone, text: "plain UTF-16 LE\nsecond line\n"},
		{name: "utf16be-no-bom", enc: EncodingUTF16BE, bom: BOMNone, text: "plain UTF-16 BE\nsecond line\n"},
		{name: "euc-kr", enc: EncodingEUCKR, bom: BOMNone, text: "안녕하세요 세계\n다음 줄\n"},
		{name: "shift-jis", enc: EncodingShiftJIS, bom: BOMNone, text: "こんにちは世界\n次の行\n"},
		{name: "iso-8859-1", enc: EncodingISO88591, bom: BOMNone, text: "café £ déjà vu\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := encodedFixture(t, test.enc, test.bom, test.text)
			file, err := Decode(source, Limits{})
			if err != nil {
				t.Fatal(err)
			}
			if file.Text() != test.text {
				t.Fatalf("decoded text = %q, want %q", file.Text(), test.text)
			}
			meta := file.Metadata()
			if meta.Encoding != test.enc || meta.BOM != test.bom {
				t.Fatalf("metadata encoding/BOM = %s/%s, want %s/%s", meta.Encoding, meta.BOM, test.enc, test.bom)
			}
			if meta.Confidence <= 0 || meta.Confidence > 1 {
				t.Fatalf("confidence = %v", meta.Confidence)
			}
			roundTrip, err := file.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(roundTrip, source) {
				t.Fatalf("round trip differs:\n got %x\nwant %x", roundTrip, source)
			}
		})
	}
}

func TestBOMIsAuthoritative(t *testing.T) {
	file, err := Decode([]byte{0xef, 0xbb, 0xbf, 'x'}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if got := file.Metadata(); got.Encoding != EncodingUTF8 || got.BOM != BOMUTF8 || got.Confidence != 1 {
		t.Fatalf("unexpected metadata: %+v", got)
	}
	if !errors.Is(decodeError([]byte{0xef, 0xbb, 0xbf, 0xff}), ErrInvalidEncoding) {
		t.Fatal("malformed BOM-marked UTF-8 was accepted")
	}
	if !errors.Is(decodeError([]byte{0xff, 0xfe, 0x00}), ErrInvalidEncoding) {
		t.Fatal("malformed BOM-marked UTF-16 was accepted")
	}
}

func TestNewlineDetectionPreservationAndExplicitNormalization(t *testing.T) {
	file, err := Decode([]byte("one\r\ntwo\nthree\r\nfour\r"), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	meta := file.Metadata()
	if meta.NewlineStyle != NewlineMixed || meta.DominantNewline != NewlineCRLF {
		t.Fatalf("newline metadata = %+v", meta)
	}
	if meta.LFCount != 1 || meta.CRLFCount != 2 || meta.CRCount != 1 {
		t.Fatalf("newline counts = LF:%d CRLF:%d CR:%d", meta.LFCount, meta.CRLFCount, meta.CRCount)
	}
	preserved, err := file.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(preserved), file.Text(); got != want {
		t.Fatalf("preserved output = %q, want %q", got, want)
	}
	normalized, err := file.EncodeWithNewline(NewlineCRLF)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(normalized), "one\r\ntwo\r\nthree\r\nfour\r\n"; got != want {
		t.Fatalf("normalized output = %q, want %q", got, want)
	}
}

func TestDominantNewlineTieUsesFirstObserved(t *testing.T) {
	file, err := Decode([]byte("a\rb\nc"), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if got := file.Metadata().DominantNewline; got != NewlineCR {
		t.Fatalf("dominant newline = %s, want CR", got)
	}
}

func TestDecodeRejectsBinaryAndOversize(t *testing.T) {
	if !errors.Is(decodeError([]byte{'a', 0, 'b'}), ErrBinary) {
		t.Fatal("NUL-containing binary input was accepted")
	}
	_, err := Decode([]byte("four"), Limits{MaxInputBytes: 3})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized input error = %v", err)
	}
	_, err = Decode([]byte("x"), Limits{MaxInputBytes: hardMaxBytes + 1})
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("invalid limits error = %v", err)
	}
	_, err = Decode([]byte{0xe9}, Limits{MaxDecodedBytes: 1})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("decoded expansion error = %v", err)
	}
	utf16 := encodedFixture(t, EncodingUTF16LE, BOMUTF16LE, "é")
	_, err = Decode(utf16, Limits{MaxDecodedBytes: 1})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("UTF-16 decoded expansion error = %v", err)
	}
}

func TestEncodeRejectsUnrepresentableAndOversize(t *testing.T) {
	source := encodedFixture(t, EncodingISO88591, BOMNone, "café")
	file, err := Decode(source, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Replace("café", "你好", ReplaceOnce); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Encode(); !errors.Is(err, ErrInvalidEncoding) {
		t.Fatalf("unrepresentable output error = %v", err)
	}

	limited, err := Decode([]byte("a\n"), Limits{MaxEncodedBytes: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := limited.Replace("a", "long", ReplaceOnce); err != nil {
		t.Fatal(err)
	}
	if _, err := limited.Encode(); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized encode error = %v", err)
	}

	legacySource := encodedFixture(t, EncodingISO88591, BOMNone, "café")
	legacyLimited, err := Decode(legacySource, Limits{MaxEncodedBytes: len(legacySource)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacyLimited.Replace("c", "cc", ReplaceOnce); err != nil {
		t.Fatal(err)
	}
	if _, err := legacyLimited.Encode(); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("legacy oversized encode error = %v", err)
	}
}

func decodeError(data []byte) error {
	_, err := Decode(data, Limits{})
	return err
}
