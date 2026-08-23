package execworker

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"

	"github.com/bkcarlos/remote_agent/internal/protocol"
)

const MaxFrameBytes = 16 << 20

var ErrFrameTooLarge = errors.New("exec worker frame exceeds limit")

// WriteFrame emits a four-byte big-endian length followed by exactly one JSON
// value. Length framing prevents stream concatenation and partial-JSON ambiguity.
func WriteFrame(w io.Writer, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(raw) == 0 || len(raw) > MaxFrameBytes {
		return ErrFrameTooLarge
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, raw)
}

func ReadFrame(r io.Reader, value any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxFrameBytes {
		return ErrFrameTooLarge
	}
	raw := make([]byte, int(size))
	if _, err := io.ReadFull(r, raw); err != nil {
		return err
	}
	return protocol.DecodeStrict(raw, value)
}

func writeAll(w io.Writer, value []byte) error {
	for len(value) > 0 {
		n, err := w.Write(value)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		value = value[n:]
	}
	return nil
}
