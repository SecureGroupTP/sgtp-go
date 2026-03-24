package client

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/SecureGroupTP/sgtp-go/protocol"
)

// Client is the main user-facing handle for an SGTP session.
//
// Typical lifecycle:
//
//	c, err := client.New(cfg)
//	err  = c.Connect()
//	// drain c.Messages() and c.Events() in goroutines
//	_, err = c.SendMessage([]byte("hello"))
//	c.Disconnect()
type Client struct {
	cfg Config

	// TCP connection — guarded by connMu
	connMu sync.RWMutex
	conn   net.Conn

	// Long-term ed25519 identity
	uuid   [16]byte
	edPub  ed25519.PublicKey
	edPriv ed25519.PrivateKey

	// Ephemeral x25519 key pair (fresh per Connect call)
	ephPub  [32]byte
	ephPriv [32]byte

	// Per-peer cryptographic state, guarded by peersMu
	peersMu       sync.RWMutex
	peers         map[[16]byte]*Peer
	expectedPeers map[[16]byte]bool // peers from INFO response we must handshake with

	// Have we sent the INFO request after the first PONG?
	infoDone atomic.Bool
	// Have we sent CHAT_REQUEST (non-master clients only)?
	chatReqSent atomic.Bool

	// Active Chat Key and epoch, guarded by ckMu
	ckMu         sync.RWMutex
	chatKey      [32]byte
	chatKeyEpoch uint64
	ckReady      bool // true once at least one CK has been received

	// Monotonic nonce for our outgoing MESSAGEs — reset to 0 on each CK rotation
	sendNonce atomic.Uint64

	// Master: true once the periodic-rotation goroutine has been started
	rotationStarted atomic.Bool

	// firstCKDone: set to true after the very first CK is applied.
	// Used to trigger automatic history fetch on join.
	firstCKDone atomic.Bool

	// User-facing channels
	msgCh   chan InboundMessage
	eventCh chan Event

	// In-flight history request output channel; nil when idle — guarded by histMu
	histMu sync.Mutex
	histCh chan HistoryBatch

	// HSI responses accumulation — guarded by hsiMu
	hsiMu     sync.Mutex
	hsiResult map[[16]byte]uint64

	// Lifecycle
	done   chan struct{}
	closed atomic.Bool
}

// New creates a Client from cfg but does NOT open a network connection.
// Call Connect() to establish the TCP session.
func New(cfg Config) (*Client, error) {
	cfg.applyDefaults()
	if cfg.ServerAddr == "" {
		return nil, fmt.Errorf("github.com/SecureGroupTP/sgtp-go/client: ServerAddr is required")
	}
	if cfg.PrivateKey == nil {
		return nil, fmt.Errorf("github.com/SecureGroupTP/sgtp-go/client: PrivateKey is required")
	}

	ephPub, ephPriv, err := protocol.GenerateX25519()
	if err != nil {
		return nil, fmt.Errorf("github.com/SecureGroupTP/sgtp-go/client: generate x25519: %w", err)
	}

	c := &Client{
		cfg:       cfg,
		uuid:      cfg.UUID,
		edPub:     cfg.PrivateKey.Public().(ed25519.PublicKey),
		edPriv:    cfg.PrivateKey,
		ephPub:    ephPub,
		ephPriv:   ephPriv,
		peers:     make(map[[16]byte]*Peer),
		hsiResult: make(map[[16]byte]uint64),
		msgCh:     make(chan InboundMessage, cfg.MessageBufferSize),
		eventCh:   make(chan Event, cfg.EventBufferSize),
		done:      make(chan struct{}),
	}

	logInfo("client", "created uuid=%s room=%s server=%s",
		fmtUUID(c.uuid), fmtUUID(cfg.RoomUUID), cfg.ServerAddr)
	return c, nil
}

// ─── Public API ───────────────────────────────────────────────────────────────

// Messages returns a read-only channel of decrypted, authenticated inbound
// group messages. Drain continuously; a full buffer drops messages.
func (c *Client) Messages() <-chan InboundMessage { return c.msgCh }

// Events returns a read-only channel of session lifecycle events.
func (c *Client) Events() <-chan Event { return c.eventCh }

// Connect dials the relay server, sends the connection-intent frame (§3 §1),
// and starts the background read loop. Returns when the TCP connection is
// established and the intent frame is sent.
func (c *Client) Connect() error {
	logInfo("client", "dialing %s …", c.cfg.ServerAddr)

	dialer := net.Dialer{Timeout: c.cfg.DialTimeout}
	conn, err := dialer.Dial("tcp", c.cfg.ServerAddr)
	if err != nil {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/client: dial %s: %w", c.cfg.ServerAddr, err)
	}

	c.connMu.Lock()
	c.conn = conn
	c.connMu.Unlock()

	logInfo("client", "connected to %s", conn.RemoteAddr())

	// §3 Step 1 — intent frame: header + signature, no payload.
	intent := protocol.BuildIntentFrame(
		c.cfg.RoomUUID, c.uuid,
		func(msg []byte) [protocol.SignatureSize]byte {
			return protocol.Sign(c.edPriv, msg)
		},
	)
	if _, err := conn.Write(intent); err != nil {
		conn.Close()
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/client: send intent: %w", err)
	}
	logDebug("client", "intent frame sent (%d bytes)", len(intent))

	go c.readLoop()
	return nil
}

// SendMessage encrypts data with the current Chat Key and broadcasts it to the
// room. Returns the UUID assigned to this message.
// Requires at least one EventChatKeyRotated to have fired first.
func (c *Client) SendMessage(data []byte) ([16]byte, error) {
	c.ckMu.RLock()
	ck := c.chatKey
	ready := c.ckReady
	c.ckMu.RUnlock()

	if !ready {
		return [16]byte{}, fmt.Errorf("github.com/SecureGroupTP/sgtp-go/client: no active chat key yet — wait for EventChatKeyRotated")
	}

	nonce := c.sendNonce.Add(1) - 1
	cipher, err := protocol.Encrypt(ck, nonce, data)
	if err != nil {
		return [16]byte{}, fmt.Errorf("github.com/SecureGroupTP/sgtp-go/client: encrypt: %w", err)
	}

	msgUUID := randomUUID()
	pkt := &protocol.Message{
		MessageUUID: msgUUID,
		Nonce:       nonce,
		Ciphertext:  cipher,
	}
	h := pkt.GetHeader()
	h.RoomUUID = c.cfg.RoomUUID
	h.ReceiverUUID = protocol.BroadcastUUID
	h.SenderUUID = c.uuid
	h.Timestamp = protocol.NowMillis()

	if err := c.sendSigned(pkt.Marshal); err != nil {
		return [16]byte{}, err
	}

	// Save own message to history store (handleMessage skips our own echo).
	if c.cfg.HistoryStore != nil {
		c.cfg.HistoryStore.Append(HistoryRecord{
			SenderUUID:  c.uuid,
			MessageUUID: msgUUID,
			Timestamp:   pkt.GetHeader().Timestamp,
			Nonce:       nonce,
			Data:        append([]byte{}, data...),
		})
	}

	logDebug("send", "MESSAGE uuid=%x nonce=%d len=%d", msgUUID[:4], nonce, len(data))
	return msgUUID, nil
}

// SendFIN broadcasts a graceful disconnect notification.
func (c *Client) SendFIN() error {
	logInfo("client", "sending FIN")
	pkt := &protocol.FIN{}
	h := pkt.GetHeader()
	h.RoomUUID = c.cfg.RoomUUID
	h.ReceiverUUID = protocol.BroadcastUUID
	h.SenderUUID = c.uuid
	h.Timestamp = protocol.NowMillis()
	return c.sendSigned(pkt.Marshal)
}

// Disconnect sends FIN and closes the TCP connection. Safe to call multiple times.
func (c *Client) Disconnect() error {
	if c.closed.Swap(true) {
		return nil
	}
	logInfo("client", "disconnecting")
	_ = c.SendFIN()
	close(c.done)
	c.connMu.RLock()
	conn := c.conn
	c.connMu.RUnlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

// KnownPeers returns a snapshot of peers for which a shared secret exists.
func (c *Client) KnownPeers() []*Peer {
	c.peersMu.RLock()
	defer c.peersMu.RUnlock()
	out := make([]*Peer, 0, len(c.peers))
	for _, p := range c.peers {
		cp := *p
		out = append(out, &cp)
	}
	return out
}

// IsMaster returns true when this client has the smallest UUID in the room
// among currently known peers — i.e. it should act as master.
func (c *Client) IsMaster() bool {
	c.peersMu.RLock()
	defer c.peersMu.RUnlock()
	for id := range c.peers {
		if protocol.UUIDLess(id, c.uuid) {
			return false
		}
	}
	return true
}

// DecryptMessageFrame parses a raw MESSAGE frame blob (as returned by history)
// and decrypts it using the current Chat Key.
//
// Signature verification is intentionally skipped: history frames are
// re-signed by the serving peer (not the original sender) and arrive inside
// a verified HSRA frame, so trust is already established at the transport level.
func (c *Client) DecryptMessageFrame(raw []byte) (InboundMessage, error) {
	pkt, err := protocol.Parse(raw)
	if err != nil {
		return InboundMessage{}, fmt.Errorf("DecryptMessageFrame: parse: %w", err)
	}
	p, ok := pkt.(*protocol.Message)
	if !ok {
		return InboundMessage{}, fmt.Errorf("DecryptMessageFrame: not a MESSAGE frame (got %T)", pkt)
	}

	c.ckMu.RLock()
	ck := c.chatKey
	c.ckMu.RUnlock()

	plain, err := protocol.Decrypt(ck, p.Nonce, p.Ciphertext)
	if err != nil {
		return InboundMessage{}, fmt.Errorf("DecryptMessageFrame: decrypt nonce=%d: %w", p.Nonce, err)
	}

	return InboundMessage{
		SenderUUID:  p.GetHeader().SenderUUID,
		MessageUUID: p.MessageUUID,
		Data:        plain,
		ReceivedAt:  p.GetHeader().TimestampTime(),
	}, nil
}

// ─── Read loop ────────────────────────────────────────────────────────────────

func (c *Client) readLoop() {
	logInfo("readloop", "started")
	defer func() {
		if !c.closed.Load() {
			logWarn("readloop", "connection closed unexpectedly")
			c.pushEvent(Event{
				Kind: EventError,
				Err:  fmt.Errorf("github.com/SecureGroupTP/sgtp-go/client: connection closed by server"),
			})
		} else {
			logInfo("readloop", "stopped cleanly")
		}
	}()

	for {
		select {
		case <-c.done:
			return
		default:
		}

		c.connMu.RLock()
		conn := c.conn
		c.connMu.RUnlock()

		raw, hdr, _, _, err := protocol.ReadFrame(conn)
		if err != nil {
			if c.closed.Load() || err == io.EOF {
				return
			}
			logError("readloop", "read frame: %v", err)
			c.pushEvent(Event{Kind: EventError, Err: fmt.Errorf("github.com/SecureGroupTP/sgtp-go/client: read: %w", err)})
			return
		}

		logDebug("readloop", "recv type=%s from=%s payloadLen=%d",
			hdr.PacketType, fmtUUID(hdr.SenderUUID), hdr.PayloadLen)

		if err := protocol.ValidateTimestamp(hdr); err != nil {
			logWarn("readloop", "timestamp rejected: %v", err)
			c.pushEvent(Event{Kind: EventError, Err: err})
			continue
		}

		if err := c.dispatch(raw); err != nil {
			logError("dispatch", "type=%s err=%v", hdr.PacketType, err)
			c.pushEvent(Event{Kind: EventError, Err: err})
		}
	}
}

// dispatch parses the raw frame and routes it to the correct handler.
func (c *Client) dispatch(raw []byte) error {
	// The connection-intent frame (§3 Step 1) has packet_type=0 and no payload.
	// When we receive one, a new peer has joined — send them a PING to start
	// the handshake (§3 Step 2).
	if len(raw) >= protocol.HeaderSize {
		hdr, err := protocol.UnmarshalHeader(raw[:protocol.HeaderSize])
		if err == nil && hdr.PacketType == 0 {
			senderID := hdr.SenderUUID
			logInfo("dispatch", "intent frame from new peer=%s — sending PING", fmtUUID(senderID))
			/*
			   c.peersMu.Lock()
			   			c.peers[senderID] = &Peer{
			   				UUID: uuid.UUID(senderID[:]),
			   				PubKeyEd25519: hdr.,
			   			}
			   			c.peersMu.Unlock()
			*/
			//if _, ok := c.cfg.Whitelist[senderID]; !ok {
			//	logWarn("dispatch", "intent from unlisted peer=%s — ignored", fmtUUID(senderID))
			//	return nil
			//}
			// maybe this is useless check
			return c.sendPingTo(senderID)
		}
	}

	pkt, err := protocol.Parse(raw)
	if err != nil {
		return err
	}

	switch p := pkt.(type) {
	case *protocol.Ping:
		return c.handlePing(raw, p)
	case *protocol.Pong:
		return c.handlePong(raw, p)
	case *protocol.Info:
		return c.handleInfo(p)
	case *protocol.ChatRequest:
		return c.handleChatRequest(raw, p)
	case *protocol.ChatKey:
		return c.handleChatKey(p)
	case *protocol.ChatKeyACK:
		logDebug("dispatch", "CHAT_KEY_ACK from=%s", fmtUUID(p.GetHeader().SenderUUID))
		return nil
	case *protocol.Message:
		return c.handleMessage(raw, p)
	case *protocol.MessageFailed:
		return c.handleMessageFailed(p)
	case *protocol.MessageFailedACK:
		logDebug("dispatch", "MESSAGE_FAILED_ACK from=%s", fmtUUID(p.GetHeader().SenderUUID))
		return nil
	case *protocol.Status:
		return c.handleStatus(p)
	case *protocol.FIN:
		return c.handleFIN(p)
	case *protocol.KickRequest:
		return c.handleKickRequest(p)
	case *protocol.Kicked:
		return c.handleKicked(p)
	case *protocol.HSIR:
		return c.handleHSIR(p)
	case *protocol.HSI:
		return c.handleHSI(p)
	case *protocol.HSR:
		return c.handleHSR(p)
	case *protocol.HSRA:
		return c.handleHSRA(p)
	default:
		logWarn("dispatch", "unhandled packet type=%T", pkt)
	}
	return nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func (c *Client) pushEvent(e Event) {
	select {
	case c.eventCh <- e:
	default:
		logWarn("event", "event channel full, dropping kind=%s", e.Kind)
	}
}
