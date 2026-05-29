package ipc

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrFrameTooLarge is returned when an incoming frame's declared
// length exceeds MaxFrameBytes. Callers must close the connection on
// this error.
var ErrFrameTooLarge = errors.New("ipc: frame too large")

// ReadFrame reads one length-prefixed JSON frame off r and parses it
// into an Envelope. On EOF before any bytes are read, returns
// io.EOF unchanged so callers can detect a clean disconnect.
func ReadFrame(r io.Reader) (Envelope, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return Envelope{}, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 {
		return Envelope{}, fmt.Errorf("ipc: zero-length frame")
	}
	if int(n) > MaxFrameBytes {
		return Envelope{}, ErrFrameTooLarge
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return Envelope{}, err
	}
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return Envelope{}, fmt.Errorf("ipc: decode frame: %w", err)
	}
	return env, nil
}

// WriteFrame serialises env and writes it to w as one length-prefixed
// JSON frame. Returns the number of body bytes written.
func WriteFrame(w io.Writer, env Envelope) (int, error) {
	body, err := json.Marshal(env)
	if err != nil {
		return 0, fmt.Errorf("ipc: encode frame: %w", err)
	}
	if len(body) > MaxFrameBytes {
		return 0, ErrFrameTooLarge
	}
	var lenBuf [4]byte
	// `len(body) <= MaxFrameBytes` (16 MiB) is enforced above, so the
	// int → uint32 narrowing is always safe; gosec G115 doesn't see
	// the prior bound check.
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body))) //nolint:gosec // bounded by MaxFrameBytes check above
	if _, err := w.Write(lenBuf[:]); err != nil {
		return 0, err
	}
	if _, err := w.Write(body); err != nil {
		return 0, err
	}
	return len(body), nil
}
