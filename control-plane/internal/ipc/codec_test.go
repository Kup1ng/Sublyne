package ipc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"testing"
)

func TestWriteFrame_ReadFrame_Roundtrip(t *testing.T) {
	env := Envelope{
		Type:    "Ping",
		ID:      "abc-123",
		Payload: json.RawMessage(`{"k":"v"}`),
	}
	var buf bytes.Buffer
	if _, err := WriteFrame(&buf, env); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.Type != env.Type || got.ID != env.ID {
		t.Errorf("envelope mismatch: got %+v, want %+v", got, env)
	}
	var payload map[string]string
	if err := json.Unmarshal(got.Payload, &payload); err != nil {
		t.Fatalf("payload decode: %v", err)
	}
	if payload["k"] != "v" {
		t.Errorf("payload mismatch: %v", payload)
	}
}

func TestReadFrame_RejectsOversize(t *testing.T) {
	// Header advertises MaxFrameBytes + 1; ReadFrame must reject before
	// trying to allocate.
	var buf bytes.Buffer
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(MaxFrameBytes+1))
	buf.Write(lenBuf[:])
	_, err := ReadFrame(&buf)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("expected ErrFrameTooLarge, got %v", err)
	}
}

func TestReadFrame_RejectsZeroLength(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0, 0, 0, 0})
	_, err := ReadFrame(&buf)
	if err == nil {
		t.Error("expected error on zero-length frame")
	}
}

func TestReadFrame_EOFCleanly(t *testing.T) {
	var buf bytes.Buffer
	_, err := ReadFrame(&buf)
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF, got %v", err)
	}
}
