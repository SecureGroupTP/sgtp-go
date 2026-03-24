package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// ReadFrame reads exactly one SGTP frame from r.
// It first reads the 64-byte header, validates length limits, then reads
// payload + signature.  The raw frame bytes are also returned so callers
// can verify the ed25519 signature without re-serialising.
func ReadFrame(r io.Reader) (raw []byte, hdr *Header, payload []byte, sig []byte, err error) {
	hdrBuf := make([]byte, HeaderSize)
	if _, err = io.ReadFull(r, hdrBuf); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("sgtp: read header: %w", err)
	}

	hdr, err = UnmarshalHeader(hdrBuf)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	if hdr.PayloadLen > MaxPayloadLength {
		return nil, nil, nil, nil, fmt.Errorf("sgtp: payload_length %d exceeds MAX_PAYLOAD_LENGTH", hdr.PayloadLen)
	}

	rest := make([]byte, int(hdr.PayloadLen)+SignatureSize)
	if _, err = io.ReadFull(r, rest); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("sgtp: read payload+signature: %w", err)
	}

	payload = rest[:hdr.PayloadLen]
	sig = rest[hdr.PayloadLen:]
	raw = append(hdrBuf, rest...)
	return raw, hdr, payload, sig, nil
}

// ValidateTimestamp returns an error when the frame timestamp is outside the
// TIMESTAMP_WINDOW relative to the current wall clock.
func ValidateTimestamp(hdr *Header) error {
	ts := time.UnixMilli(int64(hdr.Timestamp))
	diff := time.Since(ts)
	if diff < 0 {
		diff = -diff
	}
	if diff > TimestampWindow {
		return fmt.Errorf("sgtp: timestamp out of window by %v", diff)
	}
	return nil
}

// Parse takes the raw bytes of a complete frame and returns the appropriate
// concrete packet type.  It does NOT verify the ed25519 signature — callers
// should do that separately using the raw bytes and the sender's public key.
func Parse(raw []byte) (Packet, error) {
	if len(raw) < MinFrameSize {
		return nil, fmt.Errorf("sgtp: frame too short (%d bytes)", len(raw))
	}

	hdr, err := UnmarshalHeader(raw[:HeaderSize])
	if err != nil {
		return nil, err
	}

	if hdr.Version != ProtocolVersion {
		return nil, fmt.Errorf("sgtp: unsupported protocol version 0x%04X", hdr.Version)
	}

	if hdr.PayloadLen > MaxPayloadLength {
		return nil, fmt.Errorf("sgtp: payload_length %d exceeds MAX_PAYLOAD_LENGTH", hdr.PayloadLen)
	}

	expectedLen := HeaderSize + int(hdr.PayloadLen) + SignatureSize
	if len(raw) != expectedLen {
		return nil, fmt.Errorf("sgtp: frame length mismatch: expected %d, got %d", expectedLen, len(raw))
	}

	payload := raw[HeaderSize : HeaderSize+int(hdr.PayloadLen)]
	sig := raw[HeaderSize+int(hdr.PayloadLen):]

	switch hdr.PacketType {
	case TypePing:
		return unmarshalPing(hdr, payload, sig)
	case TypePong:
		return unmarshalPong(hdr, payload, sig)
	case TypeInfo:
		return unmarshalInfo(hdr, payload, sig)
	case TypeChatRequest:
		return unmarshalChatRequest(hdr, payload, sig)
	case TypeChatKey:
		return unmarshalChatKey(hdr, payload, sig)
	case TypeChatKeyACK:
		return unmarshalChatKeyACK(hdr, payload, sig)
	case TypeMessage:
		return unmarshalMessage(hdr, payload, sig)
	case TypeMessageFailed:
		return unmarshalMessageFailed(hdr, payload, sig)
	case TypeMessageFailedACK:
		return unmarshalMessageFailedACK(hdr, payload, sig)
	case TypeStatus:
		return unmarshalStatus(hdr, payload, sig)
	case TypeHSIR:
		return unmarshalHSIR(hdr, payload, sig)
	case TypeHSI:
		return unmarshalHSI(hdr, payload, sig)
	case TypeHSR:
		return unmarshalHSR(hdr, payload, sig)
	case TypeHSRA:
		return unmarshalHSRA(hdr, payload, sig)
	case TypeFIN:
		return unmarshalFIN(hdr, payload, sig)
	case TypeKickRequest:
		return unmarshalKickRequest(hdr, payload, sig)
	case TypeKicked:
		return unmarshalKicked(hdr, payload, sig)
	default:
		return nil, fmt.Errorf("sgtp: unknown packet type 0x%04X", uint16(hdr.PacketType))
	}
}

// BuildIntentFrame builds the minimal connection-intent frame described in
// §3 Step 1: a header-only frame with payload_length = 0, signed by the
// sender.  signFn receives the bytes-to-sign and returns a 64-byte signature.
func BuildIntentFrame(roomUUID, senderUUID [16]byte, signFn func([]byte) [SignatureSize]byte) []byte {
	hdr := &Header{
		RoomUUID:   roomUUID,
		SenderUUID: senderUUID,
		Version:    ProtocolVersion,
		PacketType: 0, // intent frame has no type
		PayloadLen: 0,
		Timestamp:  uint64(time.Now().UnixMilli()),
	}
	b := MarshalHeader(hdr)
	sig := signFn(b)
	return append(b, sig[:]...)
}

// NowMillis returns the current UTC time as Unix milliseconds.
func NowMillis() uint64 {
	return uint64(time.Now().UnixMilli())
}

// UUIDLess returns true when a < b (lexicographic comparison of 16 bytes).
// Used to determine who is the "master" (smallest UUID).
func UUIDLess(a, b [16]byte) bool {
	return binary.BigEndian.Uint64(a[:8]) < binary.BigEndian.Uint64(b[:8]) ||
		(binary.BigEndian.Uint64(a[:8]) == binary.BigEndian.Uint64(b[:8]) &&
			binary.BigEndian.Uint64(a[8:]) < binary.BigEndian.Uint64(b[8:]))
}
