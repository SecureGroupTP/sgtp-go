package client

import (
	"crypto/rand"
	"fmt"

	"github.com/SecureGroupTP/sgtp-go/protocol"
)

// ─── Core send ────────────────────────────────────────────────────────────────

// sendSigned signs the frame produced by marshalFn and transmits it over the
// active TCP connection.
//
// Contract: marshalFn must return a complete frame whose last SignatureSize
// bytes are a writable zero slot. sendSigned computes the ed25519 signature
// over everything except those trailing bytes and writes it in place.
func (c *Client) sendSigned(marshalFn func() []byte) error {
	frame := marshalFn()
	if len(frame) < protocol.SignatureSize {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/send: frame too short to sign (%d bytes)", len(frame))
	}

	withoutSig := frame[:len(frame)-protocol.SignatureSize]
	sig := protocol.Sign(c.edPriv, withoutSig)
	copy(frame[len(frame)-protocol.SignatureSize:], sig[:])

	c.connMu.RLock()
	conn := c.conn
	c.connMu.RUnlock()

	if conn == nil {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/send: not connected")
	}

	n, err := conn.Write(frame)
	if err != nil {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/send: write: %w", err)
	}
	logDebug("send", "wrote %d bytes", n)
	return nil
}

// ─── Handshake helpers ────────────────────────────────────────────────────────

// sendPingTo sends a PING to targetUUID carrying our ephemeral x25519 key and
// long-term ed25519 public key.
func (c *Client) sendPingTo(targetUUID [16]byte) error {
	logDebug("send", "PING → %s", fmtUUID(targetUUID))

	ping := &protocol.Ping{Body: []byte(protocol.ClientHello)}
	copy(ping.PubKeyX25519[:], c.ephPub[:])
	copy(ping.PubKeyEd25519[:], c.edPub)

	h := ping.GetHeader()
	h.RoomUUID = c.cfg.RoomUUID
	h.ReceiverUUID = targetUUID
	h.SenderUUID = c.uuid
	h.Timestamp = protocol.NowMillis()

	return c.sendSigned(ping.Marshal)
}

// sendInfoRequest sends an INFO request (empty payload) to the given receiver.
func (c *Client) sendInfoRequest(receiverUUID [16]byte) error {
	logDebug("send", "INFO-request → %s", fmtUUID(receiverUUID))

	pkt := &protocol.Info{} // IsRequest() == true when UUIDs is nil/empty
	h := pkt.GetHeader()
	h.RoomUUID = c.cfg.RoomUUID
	h.ReceiverUUID = receiverUUID
	h.SenderUUID = c.uuid
	h.Timestamp = protocol.NowMillis()

	return c.sendSigned(pkt.Marshal)
}

// sendInfoResponse sends an INFO response to receiverUUID listing all UUIDs
// this client currently knows (itself + all peers).
func (c *Client) sendInfoResponse(receiverUUID [16]byte) error {
	c.peersMu.RLock()
	uuids := make([][16]byte, 0, len(c.peers)+1)
	uuids = append(uuids, c.uuid)
	for id := range c.peers {
		uuids = append(uuids, id)
	}
	c.peersMu.RUnlock()

	logDebug("send", "INFO-response → %s (%d uuids)", fmtUUID(receiverUUID), len(uuids))

	pkt := &protocol.Info{UUIDs: uuids}
	h := pkt.GetHeader()
	h.RoomUUID = c.cfg.RoomUUID
	h.ReceiverUUID = receiverUUID
	h.SenderUUID = c.uuid
	h.Timestamp = protocol.NowMillis()

	return c.sendSigned(pkt.Marshal)
}

// sendChatRequest sends CHAT_REQUEST to the master (§4.1).
// Called by a non-master client after handshaking with all known peers.
func (c *Client) sendChatRequest(masterID [16]byte, knownUUIDs [][16]byte) error {
	logInfo("send", "CHAT_REQUEST → master=%s (peers=%d)", fmtUUID(masterID), len(knownUUIDs))

	pkt := &protocol.ChatRequest{UUIDs: knownUUIDs}
	h := pkt.GetHeader()
	h.RoomUUID = c.cfg.RoomUUID
	h.ReceiverUUID = masterID
	h.SenderUUID = c.uuid
	h.Timestamp = protocol.NowMillis()
	return c.sendSigned(pkt.Marshal)
}

// ─── Utility ─────────────────────────────────────────────────────────────────

// randomUUID generates a random RFC 4122 v4 UUID.
func randomUUID() [16]byte {
	var u [16]byte
	_, _ = rand.Read(u[:])
	u[6] = (u[6] & 0x0f) | 0x40 // version 4
	u[8] = (u[8] & 0x3f) | 0x80 // variant bits
	return u
}
