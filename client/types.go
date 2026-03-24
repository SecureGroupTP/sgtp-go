// Package client implements the SGTP client.
//
// Files in this package:
//
//	types.go    — exported types: Config, Event, InboundMessage, Peer
//	client.go   — Client struct, New, Connect, Disconnect, public API
//	handshake.go— PING/PONG/INFO handlers and the peer-discovery loop
//	session.go  — ChatKey, Message, MessageFailed, Status handlers
//	history.go  — HSIR/HSI/HSR/HSRA flow
//	send.go     — sendSigned, sendPingTo, sendInfoResponse, etc.
//	log.go      — internal structured logger (writes to stderr)
package client

import (
	"crypto/ed25519"
	"time"

	"github.com/SecureGroupTP/sgtp-go/protocol"
)

// ─── Peer ────────────────────────────────────────────────────────────────────

// Peer holds the cryptographic material for one remote participant.
type Peer struct {
	UUID          [16]byte
	PubKeyEd25519 ed25519.PublicKey
	SharedSecret  [32]byte // x25519 DH result — used to encrypt control frames
}

// ─── InboundMessage ───────────────────────────────────────────────────────────

// InboundMessage is a fully decrypted and authenticated group message.
type InboundMessage struct {
	SenderUUID  [16]byte
	MessageUUID [16]byte
	Data        []byte
	ReceivedAt  time.Time
}

// ─── Events ──────────────────────────────────────────────────────────────────

// EventKind identifies the category of a client event.
type EventKind int

const (
	// EventPeerJoined fires when a PONG is received and a shared secret is established.
	EventPeerJoined EventKind = iota

	// EventPeerLeft fires when a peer sends FIN.
	EventPeerLeft

	// EventPeerKicked fires when the master sends KICKED for a peer.
	EventPeerKicked

	// EventChatKeyRotated fires after a new CHAT_KEY is received and stored.
	// SendMessage is only safe to call after at least one rotation event.
	EventChatKeyRotated

	// EventMessageFailed fires when the master rejects one of our messages
	// because a CK rotation was in progress.
	EventMessageFailed

	// EventError is a non-fatal error (bad signature, timestamp drift, etc.).
	EventError
)

func (k EventKind) String() string {
	switch k {
	case EventPeerJoined:
		return "PeerJoined"
	case EventPeerLeft:
		return "PeerLeft"
	case EventPeerKicked:
		return "PeerKicked"
	case EventChatKeyRotated:
		return "ChatKeyRotated"
	case EventMessageFailed:
		return "MessageFailed"
	case EventError:
		return "Error"
	default:
		return "Unknown"
	}
}

// Event is emitted on the channel returned by Client.Events().
type Event struct {
	Kind        EventKind
	PeerUUID    [16]byte // set for EventPeerJoined/Left/Kicked
	MessageUUID [16]byte // set for EventMessageFailed
	Err         error    // set for EventError
}

// ─── Config ───────────────────────────────────────────────────────────────────

// Config holds all parameters needed to create a Client.
type Config struct {
	// ServerAddr is the TCP address of the relay server, e.g. "relay.example.com:7777".
	// Only the relay server needs a public IP — clients connect outbound.
	ServerAddr string

	// RoomUUID is the 16-byte room identifier shared by all participants.
	RoomUUID [16]byte

	// UUID is this client's stable identity (must be unique in the room).
	UUID [16]byte

	// PrivateKey is the long-term ed25519 private key (64 bytes).
	// Generate with protocol.GenerateEd25519().
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey

	// Whitelist maps each peer UUID to their trusted ed25519 public key.
	// Frames from peers not in the whitelist are silently dropped.
	Whitelist map[[ed25519.PublicKeySize]byte]struct{}

	// MessageBufferSize is the capacity of the inbound message channel (default 64).
	// If the channel is full, new messages are dropped and an EventError is emitted.
	MessageBufferSize int

	// EventBufferSize is the capacity of the event channel (default 32).
	EventBufferSize int

	// DialTimeout is the TCP connection timeout (default 10s).
	DialTimeout time.Duration

	// InfoDelay is how long to wait after the first PONG before sending INFO
	// (§3 Step 4). Defaults to 500ms. A shorter value speeds up discovery in
	// low-latency environments.
	InfoDelay time.Duration
}

func (cfg *Config) applyDefaults() {
	if cfg.MessageBufferSize == 0 {
		cfg.MessageBufferSize = 64
	}
	if cfg.EventBufferSize == 0 {
		cfg.EventBufferSize = 32
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.InfoDelay == 0 {
		cfg.InfoDelay = 500 * time.Millisecond
	}
}

// ─── HistoryBatch ─────────────────────────────────────────────────────────────

// HistoryBatch wraps a single HSRA frame for the RequestHistory caller.
type HistoryBatch struct {
	BatchNumber  uint64
	MessageCount uint64
	Offsets      []uint64
	Messages     []byte
	// IsLast is true when this is the end-of-stream sentinel (MessageCount == 0).
	IsLast bool
}

// fromHSRA converts a protocol HSRA into a HistoryBatch.
func historyBatchFromHSRA(p *protocol.HSRA) HistoryBatch {
	return HistoryBatch{
		BatchNumber:  p.BatchNumber,
		MessageCount: p.MessageCount,
		Offsets:      p.Offsets,
		Messages:     p.Messages,
		IsLast:       p.IsEndOfStream(),
	}
}
