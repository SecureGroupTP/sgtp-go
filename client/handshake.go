package client

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/SecureGroupTP/sgtp-go/protocol"
)

// ─── PING handler (§3 Step 2→3) ──────────────────────────────────────────────

// handlePing processes an inbound PING from a peer.
// Verifies the ed25519 signature, checks the whitelist using the public key
// carried in the PING payload, computes x25519 shared secret, and replies PONG.
func (c *Client) handlePing(raw []byte, p *protocol.Ping) error {
	senderID := p.GetHeader().SenderUUID
	logInfo("handshake", "PING from=%s", fmtUUID(senderID))

	// The whitelist is keyed by [32]byte ed25519 public key.
	// The PING carries the sender's long-term ed25519 key in PubKeyEd25519.
	if _, ok := c.cfg.Whitelist[p.PubKeyEd25519]; !ok {
		logWarn("handshake", "PING from unlisted peer=%s (key=%x…) — ignored",
			fmtUUID(senderID), p.PubKeyEd25519[:4])
		return nil
	}

	pubEd := ed25519.PublicKey(p.PubKeyEd25519[:])

	// Verify ed25519 signature over the frame bytes minus the trailing sig.
	if !protocol.Verify(pubEd, raw[:len(raw)-protocol.SignatureSize], p.GetSignature()) {
		return fmt.Errorf("handshake: invalid PING signature from %s", fmtUUID(senderID))
	}

	// Verify CLIENT_HELLO body.
	if string(p.Body) != protocol.ClientHello {
		return fmt.Errorf("handshake: PING body mismatch from %s: %q", fmtUUID(senderID), p.Body)
	}

	// x25519 DH: our ephemeral private × peer's ephemeral public.
	shared, err := protocol.X25519SharedSecret(c.ephPriv, p.PubKeyX25519)
	if err != nil {
		return fmt.Errorf("handshake: x25519 DH (PING): %w", err)
	}

	c.peersMu.Lock()
	c.peers[senderID] = &Peer{
		UUID:          senderID,
		PubKeyEd25519: pubEd,
		SharedSecret:  shared,
		LastPongAt:    time.Now(),
	}
	c.peersMu.Unlock()

	logInfo("handshake", "shared secret established with peer=%s (via PING)", fmtUUID(senderID))

	// Reply with PONG carrying our ephemeral public key + long-term ed25519 key.
	pong := &protocol.Pong{Body: []byte(protocol.ClientHello)}
	copy(pong.PubKeyX25519[:], c.ephPub[:])
	copy(pong.PubKeyEd25519[:], c.edPub)
	h := pong.GetHeader()
	h.RoomUUID = c.cfg.RoomUUID
	h.ReceiverUUID = senderID
	h.SenderUUID = c.uuid
	h.Timestamp = protocol.NowMillis()

	if err := c.sendSigned(pong.Marshal); err != nil {
		return fmt.Errorf("handshake: send PONG: %w", err)
	}
	logDebug("handshake", "PONG sent to peer=%s", fmtUUID(senderID))

	c.scheduleInfoIfNeeded()
	c.pushEvent(Event{Kind: EventPeerJoined, PeerUUID: senderID})
	return nil
}

// ─── PONG handler (§3 Step 3 — initiator side) ───────────────────────────────

// handlePong processes an inbound PONG from a peer we previously PINGed.
func (c *Client) handlePong(raw []byte, p *protocol.Pong) error {
	senderID := p.GetHeader().SenderUUID
	logInfo("handshake", "PONG from=%s", fmtUUID(senderID))

	if _, ok := c.cfg.Whitelist[p.PubKeyEd25519]; !ok {
		logWarn("handshake", "PONG from unlisted peer=%s (key=%x…) — ignored",
			fmtUUID(senderID), p.PubKeyEd25519[:4])
		return nil
	}

	pubEd := ed25519.PublicKey(p.PubKeyEd25519[:])

	if !protocol.Verify(pubEd, raw[:len(raw)-protocol.SignatureSize], p.GetSignature()) {
		return fmt.Errorf("handshake: invalid PONG signature from %s", fmtUUID(senderID))
	}

	if string(p.Body) != protocol.ClientHello {
		return fmt.Errorf("handshake: PONG body mismatch from %s: %q", fmtUUID(senderID), p.Body)
	}

	shared, err := protocol.X25519SharedSecret(c.ephPriv, p.PubKeyX25519)
	if err != nil {
		return fmt.Errorf("handshake: x25519 DH (PONG): %w", err)
	}

	c.peersMu.Lock()
	peer, exists := c.peers[senderID]
	if !exists {
		peer = &Peer{UUID: senderID, PubKeyEd25519: pubEd}
		c.peers[senderID] = peer
	}
	peer.SharedSecret = shared
	peer.LastPongAt = time.Now()
	c.peersMu.Unlock()

	logInfo("handshake", "shared secret established with peer=%s (via PONG)", fmtUUID(senderID))

	c.scheduleInfoIfNeeded()
	c.pushEvent(Event{Kind: EventPeerJoined, PeerUUID: senderID})

	// If we are the master and the peer just completed handshake,
	// check if we should send a CHAT_REQUEST or issue CK directly.
	c.maybeSendChatRequestOrIssueKey()
	return nil
}

// ─── INFO handler (§3 Step 4) ────────────────────────────────────────────────

// handleInfo processes both INFO-request and INFO-response frames.
func (c *Client) handleInfo(p *protocol.Info) error {
	if p.IsRequest() {
		logDebug("handshake", "INFO-request from=%s — sending response", fmtUUID(p.GetHeader().SenderUUID))
		return c.sendInfoResponse(p.GetHeader().SenderUUID)
	}

	logInfo("handshake", "INFO-response: %d peers in room", len(p.UUIDs))

	// Record the expected peer set so we know when all handshakes are done.
	c.peersMu.Lock()
	if c.expectedPeers == nil {
		c.expectedPeers = make(map[[16]byte]bool, len(p.UUIDs))
	}
	for _, uid := range p.UUIDs {
		if uid != c.uuid {
			c.expectedPeers[uid] = true
		}
	}
	known := make(map[[16]byte]bool, len(c.peers))
	for id := range c.peers {
		known[id] = true
	}
	c.peersMu.Unlock()

	// PING any peers we don't yet have a shared secret with.
	pinged := false
	for _, uid := range p.UUIDs {
		if uid == c.uuid {
			continue
		}
		if known[uid] {
			logDebug("handshake", "INFO: peer=%s already known — skip", fmtUUID(uid))
			continue
		}
		logInfo("handshake", "INFO: sending PING to new peer=%s", fmtUUID(uid))
		if err := c.sendPingTo(uid); err != nil {
			logError("handshake", "send PING to %s: %v", fmtUUID(uid), err)
		}
		pinged = true
	}

	// If we already know all expected peers (no new PINGs needed), we can
	// send CHAT_REQUEST immediately without waiting for additional PONGs.
	if !pinged {
		c.maybeSendChatRequestOrIssueKey()
	}
	return nil
}

// ─── Discovery timer (§3 Step 4) ─────────────────────────────────────────────

func (c *Client) scheduleInfoIfNeeded() {
	if c.infoDone.Swap(true) {
		return
	}
	delay := c.cfg.InfoDelay
	logInfo("handshake", "scheduling INFO request in %v", delay)
	go func() {
		time.Sleep(delay)

		masterID := c.findMasterUUID()
		if masterID == c.uuid {
			logDebug("handshake", "we are master, no INFO needed")
			// Master: start rotation timer once we have at least one peer.
			c.StartRotationTimer()
			return
		}

		logInfo("handshake", "sending INFO-request to master=%s", fmtUUID(masterID))
		if err := c.sendInfoRequest(masterID); err != nil {
			logError("handshake", "send INFO-request: %v", err)
		}
	}()
}

// findMasterUUID returns the UUID with the smallest value among this client
// and all currently known peers.
func (c *Client) findMasterUUID() [16]byte {
	master := c.uuid
	c.peersMu.RLock()
	defer c.peersMu.RUnlock()
	for id := range c.peers {
		if protocol.UUIDLess(id, master) {
			master = id
		}
	}
	return master
}

// ─── CHAT_REQUEST trigger ─────────────────────────────────────────────────────

// maybeSendChatRequestOrIssueKey is called after every successful PONG.
// Non-master: once all expected peers are known, send CHAT_REQUEST.
// Master: once the first peer joins, start rotation timer (key issued via
//         rotateChatKey after CHAT_REQUEST is received from the newcomer).
func (c *Client) maybeSendChatRequestOrIssueKey() {
	if c.IsMaster() {
		c.StartRotationTimer()
		return
	}

	// Non-master: check if we have handshaked with all expected peers.
	if c.chatReqSent.Load() {
		return
	}

	c.peersMu.RLock()
	expected := c.expectedPeers
	peers := c.peers
	allDone := true
	if expected == nil || len(expected) == 0 {
		allDone = false // haven't received INFO yet
	}
	for uid := range expected {
		if _, ok := peers[uid]; !ok {
			allDone = false
			break
		}
	}
	// Collect known UUIDs for CHAT_REQUEST payload.
	knownUUIDs := make([][16]byte, 0, len(peers)+1)
	knownUUIDs = append(knownUUIDs, c.uuid)
	for id := range peers {
		knownUUIDs = append(knownUUIDs, id)
	}
	c.peersMu.RUnlock()

	if !allDone {
		return
	}

	if !c.chatReqSent.CompareAndSwap(false, true) {
		return
	}

	masterID := c.findMasterUUID()
	logInfo("handshake", "all peers handshaked — sending CHAT_REQUEST to master=%s", fmtUUID(masterID))
	if err := c.sendChatRequest(masterID, knownUUIDs); err != nil {
		logError("handshake", "send CHAT_REQUEST: %v", err)
		c.chatReqSent.Store(false) // allow retry
	}
}
