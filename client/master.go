package client

import (
	"fmt"
	"sync"
	"time"

	"github.com/SecureGroupTP/sgtp-go/protocol"
)

// epochCounter is a global monotonic epoch counter used by the master.
// It only ever increases — even across CK rotations — ensuring each
// CHAT_KEY is encrypted with a unique (shared_secret, nonce) pair.
var epochMu sync.Mutex
var epochVal uint64

func nextEpoch() uint64 {
	epochMu.Lock()
	epochVal++
	v := epochVal
	epochMu.Unlock()
	return v
}

// ─── CHAT_REQUEST handler (§4.1) ─────────────────────────────────────────────

// handleChatRequest is called on the master when a new participant requests
// entry to the room.  It verifies that every listed peer trusts the newcomer,
// then rotates the Chat Key for all participants including the newcomer.
// Rotation on join is correct: the newcomer should not access messages sent
// before they arrived (forward secrecy per epoch).
func (c *Client) handleChatRequest(raw []byte, p *protocol.ChatRequest) error {
	if !c.IsMaster() {
		logDebug("master", "CHAT_REQUEST received but we are not master — ignoring")
		return nil
	}

	senderID := p.GetHeader().SenderUUID
	logInfo("master", "CHAT_REQUEST from newcomer=%s (lists %d peers)", fmtUUID(senderID), len(p.UUIDs))

	c.peersMu.RLock()
	peer, ok := c.peers[senderID]
	c.peersMu.RUnlock()
	if !ok {
		logWarn("master", "CHAT_REQUEST from unknown peer=%s — no shared secret", fmtUUID(senderID))
		return c.sendStatusTo(senderID, 403, "handshake not complete")
	}

	if !protocol.Verify(peer.PubKeyEd25519, raw[:len(raw)-protocol.SignatureSize], p.GetSignature()) {
		return fmt.Errorf("master: CHAT_REQUEST signature invalid from %s", fmtUUID(senderID))
	}

	c.peersMu.RLock()
	for _, uid := range p.UUIDs {
		if uid == c.uuid || uid == senderID {
			continue
		}
		if _, exists := c.peers[uid]; !exists {
			c.peersMu.RUnlock()
			logWarn("master", "CHAT_REQUEST rejected: peer=%s not known to master", fmtUUID(uid))
			return c.sendStatusTo(senderID, 403, fmt.Sprintf("peer %x not known", uid[:4]))
		}
	}
	c.peersMu.RUnlock()

	logInfo("master", "CHAT_REQUEST accepted — rotating CK for all participants")
	return c.rotateChatKey()
}

// ─── Chat Key issuance / rotation ─────────────────────────────────────────────

// sendChatKeyTo encrypts ck with epoch as nonce and sends CHAT_KEY to one peer.
func (c *Client) sendChatKeyTo(peerID [16]byte, ck [32]byte, epoch uint64) error {
	c.peersMu.RLock()
	peer, ok := c.peers[peerID]
	c.peersMu.RUnlock()
	if !ok {
		return fmt.Errorf("master: sendChatKeyTo: no shared secret with %s", fmtUUID(peerID))
	}

	cipher, err := protocol.Encrypt(peer.SharedSecret, epoch, ck[:])
	if err != nil {
		return fmt.Errorf("master: sendChatKeyTo encrypt: %w", err)
	}

	pkt := &protocol.ChatKey{
		Epoch:      epoch,
		Ciphertext: cipher,
	}
	h := pkt.GetHeader()
	h.RoomUUID = c.cfg.RoomUUID
	h.ReceiverUUID = peerID
	h.SenderUUID = c.uuid
	h.Timestamp = protocol.NowMillis()

	if err := c.sendSigned(pkt.Marshal); err != nil {
		return fmt.Errorf("master: sendChatKeyTo send: %w", err)
	}
	logInfo("master", "CHAT_KEY sent to peer=%s epoch=%d", fmtUUID(peerID), epoch)
	return nil
}

// rotateChatKey generates a new Chat Key and sends it to every known peer.
// While the rotation window is open (from first CHAT_KEY sent to last ACK
// received) the ckRotating flag is true and incoming MESSAGE frames are
// rejected with MESSAGE_FAILED (§4.2–4.3).
func (c *Client) rotateChatKey() error {
	logInfo("master", "rotating Chat Key")

	ck, err := protocol.NewChatKey()
	if err != nil {
		return fmt.Errorf("master: generate CK: %w", err)
	}
	epoch := nextEpoch()

	c.peersMu.RLock()
	peerIDs := make([][16]byte, 0, len(c.peers))
	for id := range c.peers {
		peerIDs = append(peerIDs, id)
	}
	c.peersMu.RUnlock()

	if len(peerIDs) == 0 {
		logWarn("master", "rotateChatKey: no peers to send CK to")
		return nil
	}

	// Open the rotation window: block MESSAGE processing until all ACKs arrive.
	c.pendingAckMu.Lock()
	c.pendingAcks = make(map[[16]byte]struct{}, len(peerIDs))
	for _, id := range peerIDs {
		c.pendingAcks[id] = struct{}{}
	}
	c.pendingAckMu.Unlock()
	c.ckRotating.Store(true)
	logInfo("master", "rotation window opened: waiting ACK from %d peers epoch=%d", len(peerIDs), epoch)

	plain := ck[:] // 32-byte key only; epoch travels plaintext in the frame

	for _, peerID := range peerIDs {
		c.peersMu.RLock()
		peer, ok := c.peers[peerID]
		c.peersMu.RUnlock()
		if !ok {
			// Peer disappeared during rotation — remove from pending.
			c.pendingAckMu.Lock()
			delete(c.pendingAcks, peerID)
			c.pendingAckMu.Unlock()
			continue
		}

		// Encrypt the key with the peer's shared secret, using epoch as AEAD
		// nonce.  Because epoch is strictly monotonic, the (key, nonce) pair
		// is never reused even across multiple rotations.
		cipher, err := protocol.Encrypt(peer.SharedSecret, epoch, plain)
		if err != nil {
			logError("master", "encrypt CK for peer=%s: %v", fmtUUID(peerID), err)
			c.pendingAckMu.Lock()
			delete(c.pendingAcks, peerID)
			c.pendingAckMu.Unlock()
			continue
		}

		pkt := &protocol.ChatKey{
			Epoch:      epoch,
			Ciphertext: cipher,
		}
		h := pkt.GetHeader()
		h.RoomUUID = c.cfg.RoomUUID
		h.ReceiverUUID = peerID
		h.SenderUUID = c.uuid
		h.Timestamp = protocol.NowMillis()

		if err := c.sendSigned(pkt.Marshal); err != nil {
			logError("master", "send CK to peer=%s: %v", fmtUUID(peerID), err)
			c.pendingAckMu.Lock()
			delete(c.pendingAcks, peerID)
			c.pendingAckMu.Unlock()
		} else {
			logInfo("master", "CHAT_KEY sent to peer=%s epoch=%d", fmtUUID(peerID), epoch)
		}
	}

	// Apply the new key locally immediately so the master can encrypt with it
	// as soon as the rotation window closes.
	c.ckMu.Lock()
	isFirst := !c.ckReady
	c.chatKey = ck
	c.chatKeyEpoch = epoch
	c.ckReady = true
	c.ckMu.Unlock()
	c.sendNonce.Store(0)

	if isFirst {
		c.firstCKDone.Store(true)
	}

	logInfo("master", "CK applied locally epoch=%d — waiting for ACKs", epoch)

	// Check if all peers already disappeared (sends failed for all) — if so,
	// close the rotation window immediately.
	c.pendingAckMu.Lock()
	remaining := len(c.pendingAcks)
	c.pendingAckMu.Unlock()
	if remaining == 0 {
		c.ckRotating.Store(false)
		logInfo("master", "rotation window closed immediately (no pending ACKs)")
		c.pushEvent(Event{Kind: EventChatKeyRotated})
	}

	return nil
}

// handleChatKeyACK is called on the master when a peer acknowledges the new
// Chat Key.  Once all expected ACKs have arrived the rotation window is closed
// and MESSAGE processing resumes (§4.2).
func (c *Client) handleChatKeyACK(p *protocol.ChatKeyACK) error {
	senderID := p.GetHeader().SenderUUID
	logDebug("master", "CHAT_KEY_ACK from=%s", fmtUUID(senderID))

	if !c.IsMaster() {
		// Non-master clients ignore stray ACKs.
		return nil
	}

	c.pendingAckMu.Lock()
	delete(c.pendingAcks, senderID)
	remaining := len(c.pendingAcks)
	c.pendingAckMu.Unlock()

	logInfo("master", "ACK received from=%s remaining=%d", fmtUUID(senderID), remaining)

	if remaining == 0 && c.ckRotating.CompareAndSwap(true, false) {
		logInfo("master", "all ACKs received — rotation window closed")
		c.pushEvent(Event{Kind: EventChatKeyRotated})
	}
	return nil
}

// rejectMessage is called by the master when a MESSAGE arrives during an active
// rotation window.  It sends MESSAGE_FAILED unicast to every participant
// (including the sender) encrypted with each peer's individual shared key (§4.3).
func (c *Client) rejectMessage(p *protocol.Message) error {
	msgUUID := p.MessageUUID
	logWarn("master", "rejecting MESSAGE uuid=%x (rotation in progress)", msgUUID[:4])

	c.peersMu.RLock()
	peerIDs := make([][16]byte, 0, len(c.peers))
	for id := range c.peers {
		peerIDs = append(peerIDs, id)
	}
	c.peersMu.RUnlock()

	// Also notify the sender itself (it is a peer in the map).
	for _, peerID := range peerIDs {
		for attempt := 1; attempt <= protocol.MessageFailedRetries; attempt++ {
			if err := c.sendMessageFailed(peerID, msgUUID); err != nil {
				logError("master", "MESSAGE_FAILED attempt %d to peer=%s: %v", attempt, fmtUUID(peerID), err)
			} else {
				logDebug("master", "MESSAGE_FAILED sent to peer=%s attempt=%d", fmtUUID(peerID), attempt)
				break
			}
		}
	}
	return nil
}

// sendMessageFailed encrypts the failed message UUID and sends MESSAGE_FAILED
// to a single peer (§4.3).
func (c *Client) sendMessageFailed(peerID [16]byte, failedMsgUUID [16]byte) error {
	c.peersMu.RLock()
	peer, ok := c.peers[peerID]
	c.peersMu.RUnlock()
	if !ok {
		return fmt.Errorf("master: sendMessageFailed: no shared secret with %s", fmtUUID(peerID))
	}

	nonce := protocol.NowMillis()
	cipher, err := protocol.Encrypt(peer.SharedSecret, nonce, failedMsgUUID[:])
	if err != nil {
		return fmt.Errorf("master: sendMessageFailed encrypt: %w", err)
	}

	pkt := &protocol.MessageFailed{Ciphertext: cipher}
	h := pkt.GetHeader()
	h.RoomUUID = c.cfg.RoomUUID
	h.ReceiverUUID = peerID
	h.SenderUUID = c.uuid
	h.Timestamp = nonce // timestamp == nonce so receiver can decrypt
	return c.sendSigned(pkt.Marshal)
}

// StartRotationTimer starts a background goroutine that rotates the Chat Key
// every CK_ROTATION_INTERVAL.  Must be called only by the master, once.
func (c *Client) StartRotationTimer() {
	if !c.rotationStarted.CompareAndSwap(false, true) {
		return // already running
	}
	go func() {
		ticker := time.NewTicker(protocol.CKRotationInterval)
		defer ticker.Stop()
		for {
			select {
			case <-c.done:
				return
			case <-ticker.C:
				if !c.IsMaster() {
					logInfo("master", "rotation tick: no longer master, stopping timer")
					return
				}
				logInfo("master", "periodic CK rotation triggered")
				if err := c.rotateChatKey(); err != nil {
					logError("master", "periodic rotation: %v", err)
				}
			}
		}
	}()
}

// IssueChatKey generates a new Chat Key and sends it to a single peer.
// Kept for backwards-compat but prefer rotateChatKey/IssueChatKeyToAll.
func (c *Client) IssueChatKey(peerUUID [16]byte) error {
	logInfo("master", "IssueChatKey → peer=%s", fmtUUID(peerUUID))
	c.peersMu.RLock()
	_, ok := c.peers[peerUUID]
	c.peersMu.RUnlock()
	if !ok {
		return fmt.Errorf("master: no shared secret with peer %s", fmtUUID(peerUUID))
	}
	return c.rotateChatKey()
}

// IssueChatKeyToAll issues a Chat Key to every known peer.
// Delegates to rotateChatKey.
func (c *Client) IssueChatKeyToAll() error {
	return c.rotateChatKey()
}

// ─── KICK_REQUEST handler (§7.2) ──────────────────────────────────────────────

// handleKickRequest processes a KICK_REQUEST from any peer.
// If we are the master, we attempt a PING to the target; if no PONG arrives
// within PING_TIMEOUT we send KICKED and rotate CK.
func (c *Client) handleKickRequest(p *protocol.KickRequest) error {
	targetID := p.TargetUUID
	senderID := p.GetHeader().SenderUUID
	logWarn("master", "KICK_REQUEST for target=%s from peer=%s", fmtUUID(targetID), fmtUUID(senderID))

	if !c.IsMaster() {
		return nil // only master acts
	}

	go func() {
		logInfo("master", "pinging target=%s to verify liveness", fmtUUID(targetID))
		if err := c.sendPingTo(targetID); err != nil {
			logError("master", "ping target=%s: %v", fmtUUID(targetID), err)
		}

		timer := time.NewTimer(protocol.PingTimeout)
		defer timer.Stop()

		// Poll until we see an updated LastPongAt or the timer fires.
		pollTick := time.NewTicker(200 * time.Millisecond)
		defer pollTick.Stop()
		start := time.Now()

		for {
			select {
			case <-c.done:
				return
			case <-timer.C:
				logWarn("master", "target=%s did not respond — sending KICKED", fmtUUID(targetID))
				if err := c.sendKicked(targetID); err != nil {
					logError("master", "send KICKED: %v", err)
				}
				// Remove peer and rotate CK.
				c.peersMu.Lock()
				delete(c.peers, targetID)
				c.peersMu.Unlock()
				c.pushEvent(Event{Kind: EventPeerKicked, PeerUUID: targetID})
				if err := c.rotateChatKey(); err != nil {
					logError("master", "post-kick CK rotation: %v", err)
				}
				return
			case <-pollTick.C:
				c.peersMu.RLock()
				peer, ok := c.peers[targetID]
				c.peersMu.RUnlock()
				if !ok {
					return // already gone
				}
				if peer.LastPongAt.After(start) {
					logInfo("master", "target=%s responded to PING — NOT kicking", fmtUUID(targetID))
					return
				}
			}
		}
	}()
	return nil
}

// sendKicked broadcasts a KICKED frame.
func (c *Client) sendKicked(targetID [16]byte) error {
	pkt := &protocol.Kicked{TargetUUID: targetID}
	h := pkt.GetHeader()
	h.RoomUUID = c.cfg.RoomUUID
	h.ReceiverUUID = protocol.BroadcastUUID
	h.SenderUUID = c.uuid
	h.Timestamp = protocol.NowMillis()
	return c.sendSigned(pkt.Marshal)
}

// sendStatusTo sends an encrypted STATUS frame to a specific peer.
func (c *Client) sendStatusTo(peerID [16]byte, code uint16, msg string) error {
	c.peersMu.RLock()
	peer, ok := c.peers[peerID]
	c.peersMu.RUnlock()
	if !ok {
		return fmt.Errorf("master: sendStatus: no shared secret with %s", fmtUUID(peerID))
	}

	st := &protocol.Status{
		StatusCode: code,
		StatusMsg:  []byte(msg),
	}
	plain := st.EncodePlaintext()

	// Use a nonce derived from current time (ms truncated to uint64) to avoid
	// reuse; status frames are rare and one-shot.
	nonce := protocol.NowMillis()
	cipher, err := protocol.Encrypt(peer.SharedSecret, nonce, plain)
	if err != nil {
		return fmt.Errorf("master: sendStatus encrypt: %w", err)
	}
	st.Ciphertext = cipher

	h := st.GetHeader()
	h.RoomUUID = c.cfg.RoomUUID
	h.ReceiverUUID = peerID
	h.SenderUUID = c.uuid
	h.Timestamp = protocol.NowMillis()

	return c.sendSigned(st.Marshal)
}

// ─── HSIR / HSR server-side handlers ──────────────────────────────────────────

// handleHSIR responds to a broadcast HSIR with our local message count.
// We count stored messages by inspecting the inbound channel length (simplistic
// placeholder — a production impl would keep a persistent log).
func (c *Client) handleHSIR(p *protocol.HSIR) error {
	senderID := p.GetHeader().SenderUUID
	if senderID == c.uuid {
		return nil // ignore our own echo
	}
	logDebug("history", "HSIR from=%s — replying HSI", fmtUUID(senderID))

	// Encode our stored message count.  We track this via the history store;
	// for now emit 0 if no history store is attached.
	var count uint64
	if c.cfg.HistoryStore != nil {
		count = c.cfg.HistoryStore.Count()
	}

	hsi := &protocol.HSI{MessageCount: count}
	h := hsi.GetHeader()
	h.RoomUUID = c.cfg.RoomUUID
	h.ReceiverUUID = senderID
	h.SenderUUID = c.uuid
	h.Timestamp = protocol.NowMillis()
	return c.sendSigned(hsi.Marshal)
}

// handleHSR serves a batch of stored messages to the requesting peer.
// Each stored plaintext is re-encrypted with the current CK so the requester
// (who has only the current epoch key) can decrypt them.
func (c *Client) handleHSR(p *protocol.HSR) error {
	senderID := p.GetHeader().SenderUUID
	logInfo("history", "HSR from=%s offset=%d limit=%d", fmtUUID(senderID), p.Offset, p.Limit)

	if c.cfg.HistoryStore == nil {
		return c.sendHSRAEOS(senderID, 0)
	}

	records := c.cfg.HistoryStore.Fetch(p.Offset, p.Limit)
	if len(records) == 0 {
		return c.sendHSRAEOS(senderID, 0)
	}

	c.ckMu.RLock()
	ck := c.chatKey
	c.ckMu.RUnlock()

	// Re-encrypt each record as a fresh MESSAGE frame using the current CK.
	// We use the record's original nonce so the requester gets consistent ordering,
	// but prepend a high bit so it never collides with live message nonces.
	const historyNonceBit = uint64(1) << 63

	const batchSize = 64
	batchNum := uint64(0)

	for i := 0; i < len(records); i += batchSize {
		end := i + batchSize
		if end > len(records) {
			end = len(records)
		}
		batch := records[i:end]

		var blob []byte
		offsets := make([]uint64, len(batch))

		for j, rec := range batch {
			nonce := historyNonceBit | rec.Nonce
			cipher, err := protocol.Encrypt(ck, nonce, rec.Data)
			if err != nil {
				logError("history", "re-encrypt record %d: %v", i+j, err)
				continue
			}

			// Build a MESSAGE frame for this record.
			msg := &protocol.Message{
				MessageUUID: rec.MessageUUID,
				Nonce:       nonce,
				Ciphertext:  cipher,
			}
			h := msg.GetHeader()
			h.RoomUUID = c.cfg.RoomUUID
			h.ReceiverUUID = senderID
			h.SenderUUID = rec.SenderUUID
			h.Timestamp = rec.Timestamp
			h.Version = protocol.ProtocolVersion

			// Sign with our key (we are serving, not the original sender).
			frame := msg.Marshal()
			sig := protocol.Sign(c.edPriv, frame[:len(frame)-protocol.SignatureSize])
			copy(frame[len(frame)-protocol.SignatureSize:], sig[:])

			offsets[j] = uint64(len(blob))
			blob = append(blob, frame...)
		}

		hsra := &protocol.HSRA{
			BatchNumber:  batchNum,
			MessageCount: uint64(len(batch)),
			Offsets:      offsets,
			Messages:     blob,
		}
		hh := hsra.GetHeader()
		hh.RoomUUID = c.cfg.RoomUUID
		hh.ReceiverUUID = senderID
		hh.SenderUUID = c.uuid
		hh.Timestamp = protocol.NowMillis()
		if err := c.sendSigned(hsra.Marshal); err != nil {
			return err
		}
		batchNum++
	}

	return c.sendHSRAEOS(senderID, batchNum)
}

func (c *Client) sendHSRAEOS(receiverID [16]byte, totalSent uint64) error {
	eos := &protocol.HSRA{
		BatchNumber:  totalSent,
		MessageCount: 0,
	}
	h := eos.GetHeader()
	h.RoomUUID = c.cfg.RoomUUID
	h.ReceiverUUID = receiverID
	h.SenderUUID = c.uuid
	h.Timestamp = protocol.NowMillis()
	return c.sendSigned(eos.Marshal)
}

// ─── Deprecated low-level helpers (kept for package-internal use) ─────────────



