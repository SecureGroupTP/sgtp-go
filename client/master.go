package client

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"

	"github.com/SecureGroupTP/sgtp-go/protocol"
)

// epochCounter is a global monotonic epoch counter used by the master.
var epochCounter atomic.Uint64

// IssueChatKey generates a new Chat Key and sends it to the given peer.
// The Chat Key is encrypted with the shared secret established during the
// PING/PONG handshake with that peer.
//
// This method should only be called by the master (client with the smallest UUID).
// After calling IssueChatKey for all peers, the master also applies the new key
// locally so it can send and receive messages.
//
// For a two-node session: call IssueChatKey once after the peer's PONG arrives.
// For n-node sessions: call IssueChatKey for each peer, then wait for all ACKs.
func (c *Client) IssueChatKey(peerUUID [16]byte) error {
	logInfo("master", "issuing chat key to peer=%s", fmtUUID(peerUUID))

	c.peersMu.RLock()
	peer, ok := c.peers[peerUUID]
	c.peersMu.RUnlock()
	if !ok {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/master: no shared secret with peer %s — handshake not complete", fmtUUID(peerUUID))
	}

	// Generate a fresh Chat Key.
	ck, err := protocol.NewChatKey()
	if err != nil {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/master: generate chat key: %w", err)
	}

	epoch := epochCounter.Add(1)

	// Encode plaintext: [epoch uint64 BE][ck 32 bytes] = 40 bytes.
	plain := make([]byte, 40)
	binary.BigEndian.PutUint64(plain[0:8], epoch)
	copy(plain[8:40], ck[:])

	// Encrypt with the peer's shared secret, nonce=0.
	cipher, err := protocol.Encrypt(peer.SharedSecret, 0, plain)
	if err != nil {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/master: encrypt chat key: %w", err)
	}

	pkt := &protocol.ChatKey{Ciphertext: cipher}
	h := pkt.GetHeader()
	h.RoomUUID = c.cfg.RoomUUID
	h.ReceiverUUID = peerUUID
	h.SenderUUID = c.uuid
	h.Timestamp = protocol.NowMillis()

	if err := c.sendSigned(pkt.Marshal); err != nil {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/master: send chat key: %w", err)
	}

	logInfo("master", "chat key sent to peer=%s epoch=%d", fmtUUID(peerUUID), epoch)

	// Apply the same key locally so the master can also send/receive.
	c.ckMu.Lock()
	c.chatKey = ck
	c.chatKeyEpoch = epoch
	c.ckReady = true
	c.ckMu.Unlock()
	c.sendNonce.Store(0)

	logInfo("master", "chat key applied locally epoch=%d", epoch)
	c.pushEvent(Event{Kind: EventChatKeyRotated})
	return nil
}

// IssueChatKeyToAll generates one Chat Key and sends it to every known peer,
// then applies it locally. Use this for n-node rooms after all handshakes are
// complete.
func (c *Client) IssueChatKeyToAll() error {
	logInfo("master", "issuing chat key to all peers")

	c.peersMu.RLock()
	peerIDs := make([][16]byte, 0, len(c.peers))
	for id := range c.peers {
		peerIDs = append(peerIDs, id)
	}
	c.peersMu.RUnlock()

	if len(peerIDs) == 0 {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/master: no peers to issue chat key to")
	}

	// Generate a single key for this epoch.
	ck, err := protocol.NewChatKey()
	if err != nil {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/master: generate chat key: %w", err)
	}
	epoch := epochCounter.Add(1)

	plain := make([]byte, 40)
	binary.BigEndian.PutUint64(plain[0:8], epoch)
	copy(plain[8:40], ck[:])

	for _, peerID := range peerIDs {
		c.peersMu.RLock()
		peer, ok := c.peers[peerID]
		c.peersMu.RUnlock()
		if !ok {
			logWarn("master", "peer=%s disappeared before chat key send", fmtUUID(peerID))
			continue
		}

		cipher, err := protocol.Encrypt(peer.SharedSecret, 0, plain)
		if err != nil {
			logError("master", "encrypt chat key for peer=%s: %v", fmtUUID(peerID), err)
			continue
		}

		pkt := &protocol.ChatKey{Ciphertext: cipher}
		h := pkt.GetHeader()
		h.RoomUUID = c.cfg.RoomUUID
		h.ReceiverUUID = peerID
		h.SenderUUID = c.uuid
		h.Timestamp = protocol.NowMillis()

		if err := c.sendSigned(pkt.Marshal); err != nil {
			logError("master", "send chat key to peer=%s: %v", fmtUUID(peerID), err)
		} else {
			logInfo("master", "chat key sent to peer=%s epoch=%d", fmtUUID(peerID), epoch)
		}
	}

	// Apply locally.
	c.ckMu.Lock()
	c.chatKey = ck
	c.chatKeyEpoch = epoch
	c.ckReady = true
	c.ckMu.Unlock()
	c.sendNonce.Store(0)

	logInfo("master", "chat key applied locally epoch=%d", epoch)
	c.pushEvent(Event{Kind: EventChatKeyRotated})
	return nil
}
