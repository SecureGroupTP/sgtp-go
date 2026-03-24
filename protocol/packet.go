// Package protocol implements the SGTP (Secure Group Transfer Protocol) wire
// format: frame layout, all packet types, serialization and deserialization.
//
// Every frame is:
//
//	[64-byte Base Header] [N-byte Payload] [64-byte ed25519 Signature]
//
// All multi-byte numeric fields are big-endian (network byte order).
package protocol

import (
	"encoding/binary"
	"fmt"
	"time"
)

// ─── Constants ───────────────────────────────────────────────────────────────

const (
	// ProtocolVersion is the only supported wire version.
	ProtocolVersion uint16 = 0x0001

	// HeaderSize is the fixed size of the base header in bytes.
	HeaderSize = 64

	// SignatureSize is the ed25519 signature appended to every frame.
	SignatureSize = 64

	// MinFrameSize is the smallest possible frame: header + signature, no payload.
	MinFrameSize = HeaderSize + SignatureSize

	// MaxPayloadLength is the largest allowed payload (16 MiB).
	MaxPayloadLength = 16 * 1024 * 1024

	// TimestampWindow is the maximum allowed clock skew for incoming frames (30 s).
	TimestampWindow = 30 * time.Second

	// ClientHello is the magic string carried in PING / PONG bodies.
	ClientHello = "Client Hello"

	// CKRotationInterval is how often the master must rotate the Chat Key.
	CKRotationInterval = 180 * time.Second

	// PingTimeout is how long to wait for a PONG before declaring a peer dead.
	PingTimeout = 30 * time.Second

	// MessageFailedRetries is the maximum delivery attempts for MESSAGE_FAILED.
	MessageFailedRetries = 3
)

// BroadcastUUID is the 16-zero-byte receiver address meaning "send to everyone".
var BroadcastUUID = [16]byte{}

// ─── Packet types ────────────────────────────────────────────────────────────

// PacketType identifies the kind of an SGTP frame.
type PacketType uint16

const (
	TypePing             PacketType = 0x01
	TypePong             PacketType = 0x02
	TypeInfo             PacketType = 0x03
	TypeChatRequest      PacketType = 0x04
	TypeChatKey          PacketType = 0x05
	TypeChatKeyACK       PacketType = 0x06
	TypeMessage          PacketType = 0x07
	TypeMessageFailed    PacketType = 0x08
	TypeMessageFailedACK PacketType = 0x09
	TypeStatus           PacketType = 0x0A
	TypeHSIR             PacketType = 0x0B
	TypeHSI              PacketType = 0x0C
	TypeHSR              PacketType = 0x0D
	TypeHSRA             PacketType = 0x0E
	TypeFIN              PacketType = 0x0F
	TypeKickRequest      PacketType = 0x10
	TypeKicked           PacketType = 0x11
)

func (t PacketType) String() string {
	names := map[PacketType]string{
		TypePing: "PING", TypePong: "PONG", TypeInfo: "INFO",
		TypeChatRequest: "CHAT_REQUEST", TypeChatKey: "CHAT_KEY",
		TypeChatKeyACK: "CHAT_KEY_ACK", TypeMessage: "MESSAGE",
		TypeMessageFailed: "MESSAGE_FAILED", TypeMessageFailedACK: "MESSAGE_FAILED_ACK",
		TypeStatus: "STATUS", TypeHSIR: "HSIR", TypeHSI: "HSI",
		TypeHSR: "HSR", TypeHSRA: "HSRA", TypeFIN: "FIN",
		TypeKickRequest: "KICK_REQUEST", TypeKicked: "KICKED",
	}
	if s, ok := names[t]; ok {
		return s
	}
	return fmt.Sprintf("UNKNOWN(0x%02X)", uint16(t))
}

// ─── Base header ─────────────────────────────────────────────────────────────

// Header is the 64-byte common prefix of every SGTP frame.
type Header struct {
	RoomUUID     [16]byte
	ReceiverUUID [16]byte
	SenderUUID   [16]byte
	Version      uint16
	PacketType   PacketType
	PayloadLen   uint32
	Timestamp    uint64 // Unix milliseconds UTC
}

// IsBroadcast returns true when ReceiverUUID is the all-zero broadcast address.
func (h *Header) IsBroadcast() bool { return h.ReceiverUUID == BroadcastUUID }

// TimestampTime returns the header timestamp as a time.Time value.
func (h *Header) TimestampTime() time.Time {
	return time.UnixMilli(int64(h.Timestamp))
}

// MarshalHeader serialises the header into exactly 64 bytes (big-endian).
func MarshalHeader(h *Header) []byte {
	buf := make([]byte, HeaderSize)
	copy(buf[0:16], h.RoomUUID[:])
	copy(buf[16:32], h.ReceiverUUID[:])
	copy(buf[32:48], h.SenderUUID[:])
	binary.BigEndian.PutUint16(buf[48:], h.Version)
	binary.BigEndian.PutUint16(buf[50:], uint16(h.PacketType))
	binary.BigEndian.PutUint32(buf[52:], h.PayloadLen)
	binary.BigEndian.PutUint64(buf[56:], h.Timestamp)
	return buf
}

// UnmarshalHeader parses exactly 64 bytes into a Header.
func UnmarshalHeader(b []byte) (*Header, error) {
	if len(b) < HeaderSize {
		return nil, fmt.Errorf("sgtp: short header: need %d bytes, got %d", HeaderSize, len(b))
	}
	h := &Header{}
	copy(h.RoomUUID[:], b[0:16])
	copy(h.ReceiverUUID[:], b[16:32])
	copy(h.SenderUUID[:], b[32:48])
	h.Version = binary.BigEndian.Uint16(b[48:])
	h.PacketType = PacketType(binary.BigEndian.Uint16(b[50:]))
	h.PayloadLen = binary.BigEndian.Uint32(b[52:])
	h.Timestamp = binary.BigEndian.Uint64(b[56:])
	return h, nil
}

// ─── Packet types ─────────────────────────────────────────────────────────────

// Packet is implemented by every concrete packet type so the generic parser can
// return a unified interface.
type Packet interface {
	GetHeader() *Header
	GetSignature() []byte
	// Type returns the packet type code (convenience).
	Type() PacketType
}

// base embeds the common fields shared by all concrete packets.
type base struct {
	Hdr       Header
	Signature [SignatureSize]byte
}

func (b *base) GetHeader() *Header   { return &b.Hdr }
func (b *base) GetSignature() []byte { return b.Signature[:] }
func (b *base) Type() PacketType     { return b.Hdr.PacketType }

// ─── PING 0x01 ───────────────────────────────────────────────────────────────

// Ping is the first message of the handshake, sent by client B to client A.
type Ping struct {
	base
	PubKeyX25519  [32]byte // ephemeral x25519 public key
	PubKeyEd25519 [32]byte // long-term ed25519 public key
	Body          []byte   // CLIENT_HELLO in plaintext
}

func (p *Ping) Marshal() []byte {
	p.Hdr.Version = ProtocolVersion
	p.Hdr.PacketType = TypePing
	p.Hdr.PayloadLen = uint32(32 + 32 + len(p.Body))
	buf := MarshalHeader(&p.Hdr)
	buf = append(buf, p.PubKeyX25519[:]...)
	buf = append(buf, p.PubKeyEd25519[:]...)
	buf = append(buf, p.Body...)
	buf = append(buf, p.Signature[:]...)
	return buf
}

func unmarshalPing(h *Header, payload, sig []byte) (*Ping, error) {
	if len(payload) < 64 {
		return nil, fmt.Errorf("sgtp: PING payload too short")
	}
	p := &Ping{}
	p.Hdr = *h
	copy(p.PubKeyX25519[:], payload[0:32])
	copy(p.PubKeyEd25519[:], payload[32:64])
	p.Body = append([]byte{}, payload[64:]...)
	copy(p.Signature[:], sig)
	return p, nil
}

// ─── PONG 0x02 ───────────────────────────────────────────────────────────────

// Pong is client A's reply to a Ping. It carries A's ephemeral x25519 key.
type Pong struct {
	base
	PubKeyX25519  [32]byte
	PubKeyEd25519 [32]byte
	Body          []byte // CLIENT_HELLO echo in plaintext
}

func (p *Pong) Marshal() []byte {
	p.Hdr.Version = ProtocolVersion
	p.Hdr.PacketType = TypePong
	p.Hdr.PayloadLen = uint32(32 + 32 + len(p.Body))
	buf := MarshalHeader(&p.Hdr)
	buf = append(buf, p.PubKeyX25519[:]...)
	buf = append(buf, p.PubKeyEd25519[:]...)
	buf = append(buf, p.Body...)
	buf = append(buf, p.Signature[:]...)
	return buf
}

func unmarshalPong(h *Header, payload, sig []byte) (*Pong, error) {
	if len(payload) < 32 {
		return nil, fmt.Errorf("sgtp: PONG payload too short")
	}
	p := &Pong{}
	p.Hdr = *h
	copy(p.PubKeyX25519[:], payload[0:32])
	copy(p.PubKeyEd25519[:], payload[32:64])
	p.Body = append([]byte{}, payload[64:]...)
	copy(p.Signature[:], sig)
	return p, nil
}

// ─── INFO 0x03 ───────────────────────────────────────────────────────────────

// Info covers both INFO-request (UUIDs == nil) and INFO-response.
type Info struct {
	base
	UUIDs [][16]byte // nil / empty means "request"
}

func (p *Info) IsRequest() bool { return len(p.UUIDs) == 0 }

func (p *Info) Marshal() []byte {
	p.Hdr.Version = ProtocolVersion
	p.Hdr.PacketType = TypeInfo
	if p.IsRequest() {
		p.Hdr.PayloadLen = 0
		buf := MarshalHeader(&p.Hdr)
		buf = append(buf, p.Signature[:]...)
		return buf
	}
	count := uint64(len(p.UUIDs))
	p.Hdr.PayloadLen = uint32(8 + count*16)
	buf := MarshalHeader(&p.Hdr)
	cb := make([]byte, 8)
	binary.BigEndian.PutUint64(cb, count)
	buf = append(buf, cb...)
	for _, u := range p.UUIDs {
		buf = append(buf, u[:]...)
	}
	buf = append(buf, p.Signature[:]...)
	return buf
}

func unmarshalInfo(h *Header, payload, sig []byte) (*Info, error) {
	p := &Info{}
	p.Hdr = *h
	copy(p.Signature[:], sig)
	if len(payload) == 0 {
		return p, nil
	}
	if len(payload) < 8 {
		return nil, fmt.Errorf("sgtp: INFO response payload too short")
	}
	count := binary.BigEndian.Uint64(payload[0:8])
	if uint64(len(payload)) < 8+count*16 {
		return nil, fmt.Errorf("sgtp: INFO response truncated")
	}
	p.UUIDs = make([][16]byte, count)
	for i := uint64(0); i < count; i++ {
		copy(p.UUIDs[i][:], payload[8+i*16:8+(i+1)*16])
	}
	return p, nil
}

// ─── CHAT_REQUEST 0x04 ───────────────────────────────────────────────────────

// ChatRequest is sent by a new client to the master to request room entry.
type ChatRequest struct {
	base
	UUIDs [][16]byte // known participants
}

func (p *ChatRequest) Marshal() []byte {
	p.Hdr.Version = ProtocolVersion
	p.Hdr.PacketType = TypeChatRequest
	count := uint64(len(p.UUIDs))
	p.Hdr.PayloadLen = uint32(8 + count*16)
	buf := MarshalHeader(&p.Hdr)
	cb := make([]byte, 8)
	binary.BigEndian.PutUint64(cb, count)
	buf = append(buf, cb...)
	for _, u := range p.UUIDs {
		buf = append(buf, u[:]...)
	}
	buf = append(buf, p.Signature[:]...)
	return buf
}

func unmarshalChatRequest(h *Header, payload, sig []byte) (*ChatRequest, error) {
	if len(payload) < 8 {
		return nil, fmt.Errorf("sgtp: CHAT_REQUEST payload too short")
	}
	count := binary.BigEndian.Uint64(payload[0:8])
	if uint64(len(payload)) < 8+count*16 {
		return nil, fmt.Errorf("sgtp: CHAT_REQUEST truncated")
	}
	p := &ChatRequest{}
	p.Hdr = *h
	p.UUIDs = make([][16]byte, count)
	for i := uint64(0); i < count; i++ {
		copy(p.UUIDs[i][:], payload[8+i*16:8+(i+1)*16])
	}
	copy(p.Signature[:], sig)
	return p, nil
}

// ─── CHAT_KEY 0x05 ───────────────────────────────────────────────────────────

// ChatKey carries a new Chat Key from the master to a single participant.
// Epoch and ChatKey fields are encrypted with the receiver's shared key.
type ChatKey struct {
	base
	// Plaintext after decryption:
	Epoch uint64
	Key   [32]byte
	// Raw encrypted payload (what travels on the wire):
	Ciphertext []byte
}

func (p *ChatKey) Marshal() []byte {
	p.Hdr.Version = ProtocolVersion
	p.Hdr.PacketType = TypeChatKey
	p.Hdr.PayloadLen = uint32(len(p.Ciphertext))
	buf := MarshalHeader(&p.Hdr)
	buf = append(buf, p.Ciphertext...)
	buf = append(buf, p.Signature[:]...)
	return buf
}

func unmarshalChatKey(h *Header, payload, sig []byte) (*ChatKey, error) {
	p := &ChatKey{}
	p.Hdr = *h
	p.Ciphertext = append([]byte{}, payload...)
	copy(p.Signature[:], sig)
	return p, nil
}

// DecodePlaintext fills Epoch and Key from decrypted bytes.
func (p *ChatKey) DecodePlaintext(plain []byte) error {
	if len(plain) < 40 {
		return fmt.Errorf("sgtp: CHAT_KEY plaintext too short")
	}
	p.Epoch = binary.BigEndian.Uint64(plain[0:8])
	copy(p.Key[:], plain[8:40])
	return nil
}

// EncodePlaintext returns the 40-byte plaintext to be encrypted.
func (p *ChatKey) EncodePlaintext() []byte {
	buf := make([]byte, 40)
	binary.BigEndian.PutUint64(buf[0:8], p.Epoch)
	copy(buf[8:40], p.Key[:])
	return buf
}

// ─── CHAT_KEY_ACK 0x06 ───────────────────────────────────────────────────────

// ChatKeyACK acknowledges receipt of a ChatKey. No payload.
type ChatKeyACK struct{ base }

func (p *ChatKeyACK) Marshal() []byte {
	p.Hdr.Version = ProtocolVersion
	p.Hdr.PacketType = TypeChatKeyACK
	p.Hdr.PayloadLen = 0
	buf := MarshalHeader(&p.Hdr)
	buf = append(buf, p.Signature[:]...)
	return buf
}

func unmarshalChatKeyACK(h *Header, _, sig []byte) (*ChatKeyACK, error) {
	p := &ChatKeyACK{}
	p.Hdr = *h
	copy(p.Signature[:], sig)
	return p, nil
}

// ─── MESSAGE 0x07 ────────────────────────────────────────────────────────────

// Message is an encrypted group message. MessageUUID and Nonce are plaintext
// so the master can route/reject without decrypting.
type Message struct {
	base
	MessageUUID [16]byte
	Nonce       uint64
	Ciphertext  []byte // encrypted with current CK
}

func (p *Message) Marshal() []byte {
	p.Hdr.Version = ProtocolVersion
	p.Hdr.PacketType = TypeMessage
	p.Hdr.PayloadLen = uint32(16 + 8 + len(p.Ciphertext))
	buf := MarshalHeader(&p.Hdr)
	buf = append(buf, p.MessageUUID[:]...)
	nb := make([]byte, 8)
	binary.BigEndian.PutUint64(nb, p.Nonce)
	buf = append(buf, nb...)
	buf = append(buf, p.Ciphertext...)
	buf = append(buf, p.Signature[:]...)
	return buf
}

func unmarshalMessage(h *Header, payload, sig []byte) (*Message, error) {
	if len(payload) < 24 {
		return nil, fmt.Errorf("sgtp: MESSAGE payload too short")
	}
	p := &Message{}
	p.Hdr = *h
	copy(p.MessageUUID[:], payload[0:16])
	p.Nonce = binary.BigEndian.Uint64(payload[16:24])
	p.Ciphertext = append([]byte{}, payload[24:]...)
	copy(p.Signature[:], sig)
	return p, nil
}

// ─── MESSAGE_FAILED 0x08 ─────────────────────────────────────────────────────

// MessageFailed notifies a participant that a message was rejected.
// FailedMsgUUID is encrypted with the receiver's shared key.
type MessageFailed struct {
	base
	Ciphertext []byte // encrypted failed_message_uuid (16 bytes plaintext)
}

func (p *MessageFailed) Marshal() []byte {
	p.Hdr.Version = ProtocolVersion
	p.Hdr.PacketType = TypeMessageFailed
	p.Hdr.PayloadLen = uint32(len(p.Ciphertext))
	buf := MarshalHeader(&p.Hdr)
	buf = append(buf, p.Ciphertext...)
	buf = append(buf, p.Signature[:]...)
	return buf
}

func unmarshalMessageFailed(h *Header, payload, sig []byte) (*MessageFailed, error) {
	p := &MessageFailed{}
	p.Hdr = *h
	p.Ciphertext = append([]byte{}, payload...)
	copy(p.Signature[:], sig)
	return p, nil
}

// ─── MESSAGE_FAILED_ACK 0x09 ─────────────────────────────────────────────────

// MessageFailedACK is the sender's acknowledgment of a MessageFailed.
type MessageFailedACK struct{ base }

func (p *MessageFailedACK) Marshal() []byte {
	p.Hdr.Version = ProtocolVersion
	p.Hdr.PacketType = TypeMessageFailedACK
	p.Hdr.PayloadLen = 0
	buf := MarshalHeader(&p.Hdr)
	buf = append(buf, p.Signature[:]...)
	return buf
}

func unmarshalMessageFailedACK(h *Header, _, sig []byte) (*MessageFailedACK, error) {
	p := &MessageFailedACK{}
	p.Hdr = *h
	copy(p.Signature[:], sig)
	return p, nil
}

// ─── STATUS 0x0A ─────────────────────────────────────────────────────────────

// Status is a generic status/error frame. Payload is encrypted with the
// receiver's shared key.
type Status struct {
	base
	// Decrypted fields:
	StatusCode uint16
	StatusMsg  []byte
	// Raw wire payload:
	Ciphertext []byte
}

func (p *Status) Marshal() []byte {
	p.Hdr.Version = ProtocolVersion
	p.Hdr.PacketType = TypeStatus
	p.Hdr.PayloadLen = uint32(len(p.Ciphertext))
	buf := MarshalHeader(&p.Hdr)
	buf = append(buf, p.Ciphertext...)
	buf = append(buf, p.Signature[:]...)
	return buf
}

func unmarshalStatus(h *Header, payload, sig []byte) (*Status, error) {
	p := &Status{}
	p.Hdr = *h
	p.Ciphertext = append([]byte{}, payload...)
	copy(p.Signature[:], sig)
	return p, nil
}

// DecodePlaintext fills StatusCode and StatusMsg from decrypted bytes.
func (p *Status) DecodePlaintext(plain []byte) error {
	if len(plain) < 2 {
		return fmt.Errorf("sgtp: STATUS plaintext too short")
	}
	p.StatusCode = binary.BigEndian.Uint16(plain[0:2])
	p.StatusMsg = append([]byte{}, plain[2:]...)
	return nil
}

// EncodePlaintext serialises StatusCode + StatusMsg for encryption.
func (p *Status) EncodePlaintext() []byte {
	buf := make([]byte, 2+len(p.StatusMsg))
	binary.BigEndian.PutUint16(buf[0:2], p.StatusCode)
	copy(buf[2:], p.StatusMsg)
	return buf
}

// ─── HSIR 0x0B ───────────────────────────────────────────────────────────────

// HSIR is a broadcast History Info Request. No payload.
type HSIR struct{ base }

func (p *HSIR) Marshal() []byte {
	p.Hdr.Version = ProtocolVersion
	p.Hdr.PacketType = TypeHSIR
	p.Hdr.PayloadLen = 0
	buf := MarshalHeader(&p.Hdr)
	buf = append(buf, p.Signature[:]...)
	return buf
}

func unmarshalHSIR(h *Header, _, sig []byte) (*HSIR, error) {
	p := &HSIR{}
	p.Hdr = *h
	copy(p.Signature[:], sig)
	return p, nil
}

// ─── HSI 0x0C ────────────────────────────────────────────────────────────────

// HSI is the reply to HSIR; it carries the local message count.
type HSI struct {
	base
	MessageCount uint64
}

func (p *HSI) Marshal() []byte {
	p.Hdr.Version = ProtocolVersion
	p.Hdr.PacketType = TypeHSI
	p.Hdr.PayloadLen = 8
	buf := MarshalHeader(&p.Hdr)
	cb := make([]byte, 8)
	binary.BigEndian.PutUint64(cb, p.MessageCount)
	buf = append(buf, cb...)
	buf = append(buf, p.Signature[:]...)
	return buf
}

func unmarshalHSI(h *Header, payload, sig []byte) (*HSI, error) {
	if len(payload) < 8 {
		return nil, fmt.Errorf("sgtp: HSI payload too short")
	}
	p := &HSI{}
	p.Hdr = *h
	p.MessageCount = binary.BigEndian.Uint64(payload[0:8])
	copy(p.Signature[:], sig)
	return p, nil
}

// ─── HSR 0x0D ────────────────────────────────────────────────────────────────

// HSR is a unicast request for a batch of history messages.
type HSR struct {
	base
	Offset uint64
	Limit  uint64
}

func (p *HSR) Marshal() []byte {
	p.Hdr.Version = ProtocolVersion
	p.Hdr.PacketType = TypeHSR
	p.Hdr.PayloadLen = 16
	buf := MarshalHeader(&p.Hdr)
	ob := make([]byte, 16)
	binary.BigEndian.PutUint64(ob[0:8], p.Offset)
	binary.BigEndian.PutUint64(ob[8:16], p.Limit)
	buf = append(buf, ob...)
	buf = append(buf, p.Signature[:]...)
	return buf
}

func unmarshalHSR(h *Header, payload, sig []byte) (*HSR, error) {
	if len(payload) < 16 {
		return nil, fmt.Errorf("sgtp: HSR payload too short")
	}
	p := &HSR{}
	p.Hdr = *h
	p.Offset = binary.BigEndian.Uint64(payload[0:8])
	p.Limit = binary.BigEndian.Uint64(payload[8:16])
	copy(p.Signature[:], sig)
	return p, nil
}

// ─── HSRA 0x0E ───────────────────────────────────────────────────────────────

// HSRA carries one batch of historical messages.
// When MessageCount == 0 it is the end-of-stream sentinel.
type HSRA struct {
	base
	BatchNumber  uint64
	MessageCount uint64
	Offsets      []uint64
	Messages     []byte
}

// IsEndOfStream returns true when this is the final sentinel batch.
func (p *HSRA) IsEndOfStream() bool { return p.MessageCount == 0 }

func (p *HSRA) Marshal() []byte {
	p.Hdr.Version = ProtocolVersion
	p.Hdr.PacketType = TypeHSRA
	p.Hdr.PayloadLen = uint32(8 + 8 + len(p.Offsets)*8 + len(p.Messages))
	buf := MarshalHeader(&p.Hdr)
	nb := make([]byte, 16)
	binary.BigEndian.PutUint64(nb[0:8], p.BatchNumber)
	binary.BigEndian.PutUint64(nb[8:16], p.MessageCount)
	buf = append(buf, nb...)
	for _, off := range p.Offsets {
		ob := make([]byte, 8)
		binary.BigEndian.PutUint64(ob, off)
		buf = append(buf, ob...)
	}
	buf = append(buf, p.Messages...)
	buf = append(buf, p.Signature[:]...)
	return buf
}

func unmarshalHSRA(h *Header, payload, sig []byte) (*HSRA, error) {
	if len(payload) < 16 {
		return nil, fmt.Errorf("sgtp: HSRA payload too short")
	}
	p := &HSRA{}
	p.Hdr = *h
	p.BatchNumber = binary.BigEndian.Uint64(payload[0:8])
	p.MessageCount = binary.BigEndian.Uint64(payload[8:16])
	if p.MessageCount > 0 {
		offsetsEnd := 16 + p.MessageCount*8
		if uint64(len(payload)) < offsetsEnd {
			return nil, fmt.Errorf("sgtp: HSRA offsets truncated")
		}
		p.Offsets = make([]uint64, p.MessageCount)
		for i := uint64(0); i < p.MessageCount; i++ {
			p.Offsets[i] = binary.BigEndian.Uint64(payload[16+i*8:])
		}
		p.Messages = append([]byte{}, payload[offsetsEnd:]...)
	}
	copy(p.Signature[:], sig)
	return p, nil
}

// ─── FIN 0x0F ────────────────────────────────────────────────────────────────

// FIN signals orderly disconnect. Broadcast. No payload.
type FIN struct{ base }

func (p *FIN) Marshal() []byte {
	p.Hdr.Version = ProtocolVersion
	p.Hdr.PacketType = TypeFIN
	p.Hdr.PayloadLen = 0
	buf := MarshalHeader(&p.Hdr)
	buf = append(buf, p.Signature[:]...)
	return buf
}

func unmarshalFIN(h *Header, _, sig []byte) (*FIN, error) {
	p := &FIN{}
	p.Hdr = *h
	copy(p.Signature[:], sig)
	return p, nil
}

// ─── KICK_REQUEST 0x10 ───────────────────────────────────────────────────────

// KickRequest asks the master to remove an unresponsive peer.
type KickRequest struct {
	base
	TargetUUID [16]byte
}

func (p *KickRequest) Marshal() []byte {
	p.Hdr.Version = ProtocolVersion
	p.Hdr.PacketType = TypeKickRequest
	p.Hdr.PayloadLen = 16
	buf := MarshalHeader(&p.Hdr)
	buf = append(buf, p.TargetUUID[:]...)
	buf = append(buf, p.Signature[:]...)
	return buf
}

func unmarshalKickRequest(h *Header, payload, sig []byte) (*KickRequest, error) {
	if len(payload) < 16 {
		return nil, fmt.Errorf("sgtp: KICK_REQUEST payload too short")
	}
	p := &KickRequest{}
	p.Hdr = *h
	copy(p.TargetUUID[:], payload[0:16])
	copy(p.Signature[:], sig)
	return p, nil
}

// ─── KICKED 0x11 ─────────────────────────────────────────────────────────────

// Kicked announces that a client has been removed. Broadcast from master.
type Kicked struct {
	base
	TargetUUID [16]byte
}

func (p *Kicked) Marshal() []byte {
	p.Hdr.Version = ProtocolVersion
	p.Hdr.PacketType = TypeKicked
	p.Hdr.PayloadLen = 16
	buf := MarshalHeader(&p.Hdr)
	buf = append(buf, p.TargetUUID[:]...)
	buf = append(buf, p.Signature[:]...)
	return buf
}

func unmarshalKicked(h *Header, payload, sig []byte) (*Kicked, error) {
	if len(payload) < 16 {
		return nil, fmt.Errorf("sgtp: KICKED payload too short")
	}
	p := &Kicked{}
	p.Hdr = *h
	copy(p.TargetUUID[:], payload[0:16])
	copy(p.Signature[:], sig)
	return p, nil
}
