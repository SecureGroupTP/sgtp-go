package client

import (
	"fmt"
	"time"

	"github.com/SecureGroupTP/sgtp-go/protocol"
)

// ─── PING handler (§3 Step 2→3) ──────────────────────────────────────────────

// handlePing processes an inbound PING from a peer.
// Verifies the ed25519 signature, computes the x25519 shared secret, stores
// the peer state, and replies with PONG.
func (c *Client) handlePing(raw []byte, p *protocol.Ping) error {
	senderID := p.GetHeader().SenderUUID
	logInfo("handshake", "PING from=%s", fmtUUID(senderID))

	// Only accept peers from the whitelist.
	pubEd, ok := c.cfg.Whitelist[senderID]
	if !ok {
		logWarn("handshake", "PING from unlisted peer=%s — ignored", fmtUUID(senderID))
		return nil // not a hard error; could be an unknown node
	}

	// Verify ed25519 signature over the frame bytes minus the trailing sig.
	if !protocol.Verify(pubEd, raw[:len(raw)-protocol.SignatureSize], p.GetSignature()) {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/handshake: invalid PING signature from %s", fmtUUID(senderID))
	}

	// x25519 DH: our ephemeral private × peer's ephemeral public.
	shared, err := protocol.X25519SharedSecret(c.ephPriv, p.PubKeyX25519)
	if err != nil {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/handshake: x25519 DH (PING): %w", err)
	}

	c.peersMu.Lock()
	c.peers[senderID] = &Peer{
		UUID:          senderID,
		PubKeyEd25519: pubEd,
		SharedSecret:  shared,
	}
	c.peersMu.Unlock()

	logInfo("handshake", "shared secret established with peer=%s (via PING)", fmtUUID(senderID))

	// Reply with PONG carrying our ephemeral public key.
	pong := &protocol.Pong{Body: []byte(protocol.ClientHello)}
	copy(pong.PubKeyX25519[:], c.ephPub[:])
	h := pong.GetHeader()
	h.RoomUUID = c.cfg.RoomUUID
	h.ReceiverUUID = senderID
	h.SenderUUID = c.uuid
	h.Timestamp = protocol.NowMillis()

	if err := c.sendSigned(pong.Marshal); err != nil {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/handshake: send PONG: %w", err)
	}
	logDebug("handshake", "PONG sent to peer=%s", fmtUUID(senderID))

	// After establishing a shared secret, schedule INFO discovery if not yet done.
	c.scheduleInfoIfNeeded()

	c.pushEvent(Event{Kind: EventPeerJoined, PeerUUID: senderID})
	return nil
}

// ─── PONG handler (§3 Step 3 — initiator side) ───────────────────────────────

// handlePong processes an inbound PONG from a peer we previously PINGed.
func (c *Client) handlePong(raw []byte, p *protocol.Pong) error {
	senderID := p.GetHeader().SenderUUID
	logInfo("handshake", "PONG from=%s", fmtUUID(senderID))

	pubEd, ok := c.cfg.Whitelist[senderID]
	if !ok {
		logWarn("handshake", "PONG from unlisted peer=%s — ignored", fmtUUID(senderID))
		return nil
	}

	if !protocol.Verify(pubEd, raw[:len(raw)-protocol.SignatureSize], p.GetSignature()) {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/handshake: invalid PONG signature from %s", fmtUUID(senderID))
	}

	shared, err := protocol.X25519SharedSecret(c.ephPriv, p.PubKeyX25519)
	if err != nil {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/handshake: x25519 DH (PONG): %w", err)
	}

	c.peersMu.Lock()
	peer, exists := c.peers[senderID]
	if !exists {
		peer = &Peer{UUID: senderID, PubKeyEd25519: pubEd}
		c.peers[senderID] = peer
	}
	peer.SharedSecret = shared
	c.peersMu.Unlock()

	logInfo("handshake", "shared secret established with peer=%s (via PONG)", fmtUUID(senderID))

	// Schedule INFO discovery after the first successful PONG (§3 Step 4).
	c.scheduleInfoIfNeeded()

	c.pushEvent(Event{Kind: EventPeerJoined, PeerUUID: senderID})
	return nil
}

// ─── INFO handler (§3 Step 4) ────────────────────────────────────────────────

// handleInfo processes both INFO-request and INFO-response frames.
func (c *Client) handleInfo(p *protocol.Info) error {
	if p.IsRequest() {
		logDebug("handshake", "INFO-request from=%s — sending response", fmtUUID(p.GetHeader().SenderUUID))
		return c.sendInfoResponse(p.GetHeader().SenderUUID)
	}

	// INFO response: ping any peers we don't yet have a shared secret with.
	logInfo("handshake", "INFO-response: %d peers in room", len(p.UUIDs))

	c.peersMu.RLock()
	known := make(map[[16]byte]bool, len(c.peers))
	for id := range c.peers {
		known[id] = true
	}
	c.peersMu.RUnlock()

	for _, uid := range p.UUIDs {
		if uid == c.uuid {
			continue
		}
		if known[uid] {
			logDebug("handshake", "INFO: peer=%s already known — skip", fmtUUID(uid))
			continue
		}
		// Check if this peer is in our whitelist before PINGing.
		if _, ok := c.cfg.Whitelist[uid]; !ok {
			logWarn("handshake", "INFO: peer=%s not in whitelist — skip", fmtUUID(uid))
			continue
		}
		logInfo("handshake", "INFO: sending PING to new peer=%s", fmtUUID(uid))
		if err := c.sendPingTo(uid); err != nil {
			logError("handshake", "send PING to %s: %v", fmtUUID(uid), err)
		}
	}
	return nil
}

// ─── Discovery timer (§3 Step 4) ─────────────────────────────────────────────

// scheduleInfoIfNeeded fires a one-shot goroutine that sends an INFO request
// after cfg.InfoDelay. This runs once per connection, after the first PING or
// PONG is received, to discover all room members from the master.
func (c *Client) scheduleInfoIfNeeded() {
	if c.infoDone.Swap(true) {
		return // already scheduled or sent
	}
	delay := c.cfg.InfoDelay
	logInfo("handshake", "scheduling INFO request in %v", delay)
	go func() {
		time.Sleep(delay)

		// Send INFO to the master (smallest UUID among known peers + self).
		masterID := c.findMasterUUID()
		if masterID == c.uuid {
			// We are the only known node or we are the master — broadcast.
			logDebug("handshake", "we are master, no INFO needed")
			return
		}

		logInfo("handshake", "sending INFO-request to master=%s", fmtUUID(masterID))
		if err := c.sendInfoRequest(masterID); err != nil {
			logError("handshake", "send INFO-request: %v", err)
		}
	}()
}

// findMasterUUID returns the UUID with the smallest value among this client
// and all currently known peers (the "master" per §7.3).
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
