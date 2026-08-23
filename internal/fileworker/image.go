package fileworker

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
)

const (
	MaxImageBytes  int64 = 10 << 20
	MaxImagePixels int64 = 40_000_000
)

type ImageResult struct {
	Base64   string
	MIMEType string
	Bytes    int
	SHA256   string
	Width    int
	Height   int
}

func init() {
	// The standard library does not ship a WebP decoder. Register only a bounded
	// DecodeConfig implementation so dimensions can be validated without adding
	// an external or full-image parser.
	image.RegisterFormat("webp", "RIFF????WEBP", decodeWebP, decodeWebPConfig)
}

func (s *Service) readImage(path string, max int64) (ImageResult, error) {
	if max <= 0 || max > MaxImageBytes {
		return ImageResult{}, errors.New("image byte limit is invalid")
	}
	raw, err := s.fs.ReadFile(path, max)
	if err != nil {
		return ImageResult{}, err
	}
	return DecodeImage(raw)
}

// DecodeImage validates an already bounded file by magic bytes, obtains only
// its configuration, and returns the original bytes as canonical base64.
func DecodeImage(raw []byte) (ImageResult, error) {
	if len(raw) == 0 || int64(len(raw)) > MaxImageBytes {
		return ImageResult{}, errors.New("image byte limit exceeded")
	}
	mimeType, expectedFormat, ok := imageFormat(raw)
	if !ok {
		return ImageResult{}, errors.New("unsupported image format")
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil || format != expectedFormat || config.Width <= 0 || config.Height <= 0 {
		return ImageResult{}, errors.New("image data is invalid")
	}
	width, height := int64(config.Width), int64(config.Height)
	if width > MaxImagePixels/height {
		return ImageResult{}, errors.New("image pixel limit exceeded")
	}
	return ImageResult{
		Base64:   base64.StdEncoding.EncodeToString(raw),
		MIMEType: mimeType,
		Bytes:    len(raw),
		SHA256:   digestBytes(raw),
		Width:    config.Width,
		Height:   config.Height,
	}, nil
}

func imageFormat(raw []byte) (mimeType, format string, ok bool) {
	switch {
	case len(raw) >= 8 && bytes.Equal(raw[:8], []byte{'\x89', 'P', 'N', 'G', '\r', '\n', '\x1a', '\n'}):
		return "image/png", "png", true
	case len(raw) >= 3 && raw[0] == 0xff && raw[1] == 0xd8 && raw[2] == 0xff:
		return "image/jpeg", "jpeg", true
	case len(raw) >= 6 && (bytes.Equal(raw[:6], []byte("GIF87a")) || bytes.Equal(raw[:6], []byte("GIF89a"))):
		return "image/gif", "gif", true
	case validWebPMagic(raw):
		return "image/webp", "webp", true
	default:
		return "", "", false
	}
}

func validWebPMagic(raw []byte) bool {
	return len(raw) >= 12 && bytes.Equal(raw[:4], []byte("RIFF")) && bytes.Equal(raw[8:12], []byte("WEBP")) && uint64(binary.LittleEndian.Uint32(raw[4:8]))+8 == uint64(len(raw))
}

func decodeWebP(io.Reader) (image.Image, error) {
	return nil, errors.New("WebP pixel decoding is disabled")
}

func decodeWebPConfig(reader io.Reader) (image.Config, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, MaxImageBytes+1))
	if err != nil || int64(len(raw)) > MaxImageBytes || !validWebPMagic(raw) {
		return image.Config{}, errors.New("invalid WebP data")
	}
	for offset := 12; offset+8 <= len(raw); {
		kind := string(raw[offset : offset+4])
		size := int64(binary.LittleEndian.Uint32(raw[offset+4 : offset+8]))
		payloadStart := int64(offset + 8)
		payloadEnd := payloadStart + size
		if size < 0 || payloadEnd > int64(len(raw)) {
			return image.Config{}, errors.New("invalid WebP chunk")
		}
		payload := raw[payloadStart:payloadEnd]
		width, height, ok := webPDimensions(kind, payload)
		if ok {
			return image.Config{ColorModel: nil, Width: width, Height: height}, nil
		}
		next := payloadEnd + size%2
		if next <= int64(offset) || next > int64(len(raw)) {
			return image.Config{}, errors.New("invalid WebP chunk")
		}
		offset = int(next)
	}
	return image.Config{}, errors.New("WebP dimensions were not found")
}

func webPDimensions(kind string, payload []byte) (int, int, bool) {
	switch kind {
	case "VP8X":
		if len(payload) < 10 {
			return 0, 0, false
		}
		width := 1 + int(payload[4]) + int(payload[5])<<8 + int(payload[6])<<16
		height := 1 + int(payload[7]) + int(payload[8])<<8 + int(payload[9])<<16
		return width, height, true
	case "VP8L":
		if len(payload) < 5 || payload[0] != 0x2f {
			return 0, 0, false
		}
		width := 1 + int(payload[1]) + int(payload[2]&0x3f)<<8
		height := 1 + int(payload[2]>>6) + int(payload[3])<<2 + int(payload[4]&0x0f)<<10
		return width, height, true
	case "VP8 ":
		if len(payload) < 10 || !bytes.Equal(payload[3:6], []byte{0x9d, 0x01, 0x2a}) {
			return 0, 0, false
		}
		width := int(binary.LittleEndian.Uint16(payload[6:8]) & 0x3fff)
		height := int(binary.LittleEndian.Uint16(payload[8:10]) & 0x3fff)
		return width, height, true
	default:
		return 0, 0, false
	}
}
