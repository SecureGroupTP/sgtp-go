package client

import (
	"fmt"
	"time"

	"github.com/SecureGroupTP/sgtp-go/protocol"
)

// ─── CHAT_KEY handler (§4) ────────────────────────────────────────────────────

// handleChatKey decrypts the new Chat Key sent by the master.
// Wire format: epoch (8B plaintext) || ciphertext-of-key (encrypted with
// shared_secret, nonce=epoch).
func (c *Client) handleChatKey(p *protocol.ChatKey) error {
	senderID := p.GetHeader().SenderUUID
	logInfo("session", "CHAT_KEY from master=%s epoch=%d", fmtUUID(senderID), p.Epoch)

	c.peersMu.RLock()
	peer, ok := c.peers[senderID]
	c.peersMu.RUnlock()
	if !ok {
		return fmt.Errorf("session: CHAT_KEY from unknown peer %s — no shared secret", fmtUUID(senderID))
	}

	// Nonce = epoch (unique per rotation, strictly monotonic).
	plain, err := protocol.Decrypt(peer.SharedSecret, p.Epoch, p.Ciphertext)
	if err != nil {
		return fmt.Errorf("session: CHAT_KEY decrypt epoch=%d: %w", p.Epoch, err)
	}
	if err := p.DecodePlaintext(plain); err != nil {
		return fmt.Errorf("session: CHAT_KEY decode: %w", err)
	}

	c.ckMu.Lock()
	isFirst := !c.ckReady
	c.chatKey = p.Key
	c.chatKeyEpoch = p.Epoch
	c.ckReady = true
	c.ckMu.Unlock()

	// Reset per-epoch nonce counter.
	c.sendNonce.Store(0)

	logInfo("session", "chat key updated epoch=%d", p.Epoch)

	// Mark first CK received (used for auto-history fetch).
	if isFirst {
		c.firstCKDone.Store(true)
	}

	// Send CHAT_KEY_ACK.
	ack := &protocol.ChatKeyACK{}
	h := ack.GetHeader()
	h.RoomUUID = c.cfg.RoomUUID
	h.ReceiverUUID = senderID
	h.SenderUUID = c.uuid
	h.Timestamp = protocol.NowMillis()
	if err := c.sendSigned(ack.Marshal); err != nil {
		return fmt.Errorf("session: send CHAT_KEY_ACK: %w", err)
	}
	logDebug("session", "CHAT_KEY_ACK sent to master=%s", fmtUUID(senderID))

	c.pushEvent(Event{Kind: EventChatKeyRotated})
	return nil
}

// ─── MESSAGE handler (§5) ─────────────────────────────────────────────────────

// handleMessage verifies the ed25519 signature and decrypts a group message.
// If we are the master and a CK rotation is in progress, the message is
// rejected with MESSAGE_FAILED sent unicast to every participant (§4.3).
func (c *Client) handleMessage(raw []byte, p *protocol.Message) error {
	senderID := p.GetHeader().SenderUUID

	// Ignore our own echo (relay server broadcasts to everyone including sender).
	if senderID == c.uuid {
		return nil
	}

	// Master: reject during rotation window.
	if c.IsMaster() && c.ckRotating.Load() {
		return c.rejectMessage(p)
	}

	c.peersMu.RLock()
	peer, ok := c.peers[senderID]
	c.peersMu.RUnlock()
	if !ok {
		logWarn("session", "MESSAGE from unknown peer=%s — dropped", fmtUUID(senderID))
		return nil
	}

	// Verify authenticity.
	if !protocol.Verify(peer.PubKeyEd25519, raw[:len(raw)-protocol.SignatureSize], p.GetSignature()) {
		return fmt.Errorf("session: MESSAGE signature invalid from peer=%s", fmtUUID(senderID))
	}

	c.ckMu.RLock()
	ck := c.chatKey
	c.ckMu.RUnlock()

	plain, err := protocol.Decrypt(ck, p.Nonce, p.Ciphertext)
	if err != nil {
		return fmt.Errorf("session: MESSAGE decrypt nonce=%d: %w", p.Nonce, err)
	}

	logDebug("session", "MESSAGE decrypted from=%s nonce=%d len=%d", fmtUUID(senderID), p.Nonce, len(plain))

	// Persist decoded record to history store.
	if c.cfg.HistoryStore != nil {
		c.cfg.HistoryStore.Append(HistoryRecord{
			SenderUUID:  senderID,
			MessageUUID: p.MessageUUID,
			Timestamp:   p.GetHeader().Timestamp,
			Nonce:       p.Nonce,
			Data:        plain,
		})
	}

	msg := InboundMessage{
		SenderUUID:  senderID,
		MessageUUID: p.MessageUUID,
		Data:        plain,
		ReceivedAt:  time.Now(),
	}
	select {
	case c.msgCh <- msg:
	default:
		logWarn("session", "inbound message buffer full — dropping message from=%s", fmtUUID(senderID))
		c.pushEvent(Event{Kind: EventError, Err: fmt.Errorf("session: inbound buffer full, message dropped")})
	}
	return nil
}

// ─── MESSAGE_FAILED handler (§4.3) ───────────────────────────────────────────

// handleMessageFailed notifies the user that one of their messages was rejected
// during a CK rotation, then sends MESSAGE_FAILED_ACK.
func (c *Client) handleMessageFailed(p *protocol.MessageFailed) error {
	senderID := p.GetHeader().SenderUUID
	logWarn("session", "MESSAGE_FAILED from master=%s", fmtUUID(senderID))

	c.peersMu.RLock()
	peer, ok := c.peers[senderID]
	c.peersMu.RUnlock()
	if !ok {
		return fmt.Errorf("session: MESSAGE_FAILED from unknown peer %s", fmtUUID(senderID))
	}

	// Use the nonce from the frame timestamp (same scheme as sendStatusTo).
	nonce := p.GetHeader().Timestamp
	plain, err := protocol.Decrypt(peer.SharedSecret, nonce, p.Ciphertext)
	if err != nil {
		return fmt.Errorf("session: MESSAGE_FAILED decrypt: %w", err)
	}
	if len(plain) < 16 {
		return fmt.Errorf("session: MESSAGE_FAILED plaintext too short (%d bytes)", len(plain))
	}
	var msgUUID [16]byte
	copy(msgUUID[:], plain[0:16])

	logWarn("session", "message rejected by master: uuid=%x (CK rotation)", msgUUID[:4])
	c.pushEvent(Event{Kind: EventMessageFailed, MessageUUID: msgUUID})

	// Acknowledge.
	ack := &protocol.MessageFailedACK{}
	h := ack.GetHeader()
	h.RoomUUID = c.cfg.RoomUUID
	h.ReceiverUUID = senderID
	h.SenderUUID = c.uuid
	h.Timestamp = protocol.NowMillis()
	if err := c.sendSigned(ack.Marshal); err != nil {
		return fmt.Errorf("session: send MESSAGE_FAILED_ACK: %w", err)
	}
	return nil
}

// ─── STATUS handler ──────────────────────────────────────────────────────────

func (c *Client) handleStatus(p *protocol.Status) error {
	senderID := p.GetHeader().SenderUUID
	logInfo("session", "STATUS from=%s", fmtUUID(senderID))

	c.peersMu.RLock()
	peer, ok := c.peers[senderID]
	c.peersMu.RUnlock()
	if !ok {
		return fmt.Errorf("session: STATUS from unknown peer %s", fmtUUID(senderID))
	}

	// Nonce is the frame timestamp (matches sendStatusTo).
	nonce := p.GetHeader().Timestamp
	plain, err := protocol.Decrypt(peer.SharedSecret, nonce, p.Ciphertext)
	if err != nil {
		return fmt.Errorf("session: STATUS decrypt: %w", err)
	}
	if err := p.DecodePlaintext(plain); err != nil {
		return err
	}

	logWarn("session", "STATUS code=%d msg=%q", p.StatusCode, p.StatusMsg)
	c.pushEvent(Event{
		Kind: EventError,
		Err:  fmt.Errorf("session: STATUS %d from master: %s", p.StatusCode, p.StatusMsg),
	})
	return nil
}

// ─── FIN handler (§7.1) ───────────────────────────────────────────────────────

// handleFIN removes the departing peer from state.
// The FIN payload is encrypted with the sender's current CK nonce so only
// participants who share the key can authenticate the departure (§7.1).
// If we are the master, we rotate the CK for remaining participants.
func (c *Client) handleFIN(p *protocol.FIN) error {
	uid := p.GetHeader().SenderUUID
	logInfo("session", "FIN from peer=%s nonce=%d", fmtUUID(uid), p.Nonce)

	// Authenticate: decrypt the (empty) ciphertext with the current CK.
	// A forged FIN without the correct key will fail the Poly1305 check.
	if len(p.Ciphertext) > 0 {
		c.ckMu.RLock()
		ck := c.chatKey
		ready := c.ckReady
		c.ckMu.RUnlock()
		if ready {
			if _, err := protocol.Decrypt(ck, p.Nonce, p.Ciphertext); err != nil {
				return fmt.Errorf("session: FIN authentication failed from peer=%s: %w", fmtUUID(uid), err)
			}
		}
	}

	c.peersMu.Lock()
	delete(c.peers, uid)
	c.peersMu.Unlock()

	c.pushEvent(Event{Kind: EventPeerLeft, PeerUUID: uid})

	// Master: rotate CK so the departing peer can no longer read (§7.1).
	if c.IsMaster() {
		logInfo("master", "peer left — rotating CK for remaining participants")
		go func() {
			if err := c.rotateChatKey(); err != nil {
				logError("master", "post-FIN CK rotation: %v", err)
			}
		}()
	}
	return nil
}

// ─── KICKED handler (§7.2) ────────────────────────────────────────────────────

func (c *Client) handleKicked(p *protocol.Kicked) error {
	logInfo("session", "KICKED target=%s by master=%s", fmtUUID(p.TargetUUID), fmtUUID(p.GetHeader().SenderUUID))

	c.peersMu.Lock()
	delete(c.peers, p.TargetUUID)
	c.peersMu.Unlock()

	c.pushEvent(Event{Kind: EventPeerKicked, PeerUUID: p.TargetUUID})
	return nil
}
