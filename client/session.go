package client

import (
	"fmt"
	"time"

	"github.com/SecureGroupTP/sgtp-go/protocol"
)

// ─── CHAT_KEY handler (§4) ────────────────────────────────────────────────────

// handleChatKey decrypts the new Chat Key sent by the master, stores it, resets
// the nonce counter, and sends CHAT_KEY_ACK.
func (c *Client) handleChatKey(p *protocol.ChatKey) error {
	senderID := p.GetHeader().SenderUUID
	logInfo("session", "CHAT_KEY from master=%s", fmtUUID(senderID))

	c.peersMu.RLock()
	peer, ok := c.peers[senderID]
	c.peersMu.RUnlock()
	if !ok {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/session: CHAT_KEY from unknown peer %s — no shared secret", fmtUUID(senderID))
	}

	// Control-plane frames use nonce=0 (one-time use per DH session).
	plain, err := protocol.Decrypt(peer.SharedSecret, 0, p.Ciphertext)
	if err != nil {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/session: CHAT_KEY decrypt: %w", err)
	}
	if err := p.DecodePlaintext(plain); err != nil {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/session: CHAT_KEY decode: %w", err)
	}

	c.ckMu.Lock()
	c.chatKey = p.Key
	c.chatKeyEpoch = p.Epoch
	c.ckReady = true
	c.ckMu.Unlock()

	// Reset per-epoch nonce counter.
	c.sendNonce.Store(0)

	logInfo("session", "chat key updated epoch=%d", p.Epoch)

	// Acknowledge.
	ack := &protocol.ChatKeyACK{}
	h := ack.GetHeader()
	h.RoomUUID = c.cfg.RoomUUID
	h.ReceiverUUID = senderID
	h.SenderUUID = c.uuid
	h.Timestamp = protocol.NowMillis()
	if err := c.sendSigned(ack.Marshal); err != nil {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/session: send CHAT_KEY_ACK: %w", err)
	}
	logDebug("session", "CHAT_KEY_ACK sent to master=%s", fmtUUID(senderID))

	c.pushEvent(Event{Kind: EventChatKeyRotated})
	return nil
}

// ─── MESSAGE handler (§5) ─────────────────────────────────────────────────────

// handleMessage verifies the ed25519 signature and decrypts a group message.
func (c *Client) handleMessage(raw []byte, p *protocol.Message) error {
	senderID := p.GetHeader().SenderUUID

	// Ignore our own echo (relay server broadcasts to everyone including sender).
	if senderID == c.uuid {
		return nil
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
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/session: MESSAGE signature invalid from peer=%s", fmtUUID(senderID))
	}

	c.ckMu.RLock()
	ck := c.chatKey
	c.ckMu.RUnlock()

	plain, err := protocol.Decrypt(ck, p.Nonce, p.Ciphertext)
	if err != nil {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/session: MESSAGE decrypt nonce=%d: %w", p.Nonce, err)
	}

	logDebug("session", "MESSAGE decrypted from=%s nonce=%d len=%d", fmtUUID(senderID), p.Nonce, len(plain))

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
		c.pushEvent(Event{Kind: EventError, Err: fmt.Errorf("github.com/SecureGroupTP/sgtp-go/client: inbound buffer full, message dropped")})
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
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/session: MESSAGE_FAILED from unknown peer %s", fmtUUID(senderID))
	}

	plain, err := protocol.Decrypt(peer.SharedSecret, 0, p.Ciphertext)
	if err != nil {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/session: MESSAGE_FAILED decrypt: %w", err)
	}
	if len(plain) < 16 {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/session: MESSAGE_FAILED plaintext too short (%d bytes)", len(plain))
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
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/session: send MESSAGE_FAILED_ACK: %w", err)
	}
	return nil
}

// ─── STATUS handler (§STATUS) ────────────────────────────────────────────────

// handleStatus decrypts and logs a STATUS frame from the master.
func (c *Client) handleStatus(p *protocol.Status) error {
	senderID := p.GetHeader().SenderUUID
	logInfo("session", "STATUS from=%s", fmtUUID(senderID))

	c.peersMu.RLock()
	peer, ok := c.peers[senderID]
	c.peersMu.RUnlock()
	if !ok {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/session: STATUS from unknown peer %s", fmtUUID(senderID))
	}

	plain, err := protocol.Decrypt(peer.SharedSecret, 0, p.Ciphertext)
	if err != nil {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/session: STATUS decrypt: %w", err)
	}
	if err := p.DecodePlaintext(plain); err != nil {
		return err
	}

	logWarn("session", "STATUS code=%d msg=%q", p.StatusCode, p.StatusMsg)
	c.pushEvent(Event{
		Kind: EventError,
		Err:  fmt.Errorf("github.com/SecureGroupTP/sgtp-go/session: STATUS %d from master: %s", p.StatusCode, p.StatusMsg),
	})
	return nil
}

// ─── FIN handler (§7.1) ───────────────────────────────────────────────────────

// handleFIN removes the departing peer from our state.
func (c *Client) handleFIN(p *protocol.FIN) error {
	uid := p.GetHeader().SenderUUID
	logInfo("session", "FIN from peer=%s", fmtUUID(uid))

	c.peersMu.Lock()
	delete(c.peers, uid)
	c.peersMu.Unlock()

	c.pushEvent(Event{Kind: EventPeerLeft, PeerUUID: uid})
	return nil
}

// ─── KICKED handler (§7.2) ────────────────────────────────────────────────────

// handleKicked removes the kicked peer from state.
func (c *Client) handleKicked(p *protocol.Kicked) error {
	logInfo("session", "KICKED target=%s by master=%s", fmtUUID(p.TargetUUID), fmtUUID(p.GetHeader().SenderUUID))

	c.peersMu.Lock()
	delete(c.peers, p.TargetUUID)
	c.peersMu.Unlock()

	c.pushEvent(Event{Kind: EventPeerKicked, PeerUUID: p.TargetUUID})
	return nil
}
