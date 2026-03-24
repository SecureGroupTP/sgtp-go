// Package server implements a simple SGTP relay server.
//
// The relay server is a transparent byte forwarder. It reads complete SGTP
// frames from connected clients and routes them:
//
//   - receiver_uuid == BROADCAST_UUID → all clients in the room except the sender
//   - receiver_uuid != BROADCAST_UUID → unicast to that specific client
//
// When a new client connects and sends the intent frame, the server broadcasts
// that intent frame to existing room members so they learn a new peer has
// arrived and can initiate the PING handshake (§3 Step 2).
//
// The server does NOT decrypt, validate signatures, or maintain session state.
// A public IP is required only for this process — clients connect outbound.
package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"github.com/SecureGroupTP/sgtp-go/protocol"
)

// ─── room ─────────────────────────────────────────────────────────────────────

type room struct {
	mu      sync.RWMutex
	clients map[[16]byte]*conn
}

func newRoom() *room {
	return &room{clients: make(map[[16]byte]*conn)}
}

func (r *room) add(c *conn) {
	r.mu.Lock()
	r.clients[c.uuid] = c
	r.mu.Unlock()
}

func (r *room) remove(uuid [16]byte) {
	r.mu.Lock()
	delete(r.clients, uuid)
	r.mu.Unlock()
}

func (r *room) isEmpty() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.clients) == 0
}

func (r *room) count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.clients)
}

// broadcast sends raw to all clients except the one with senderID.
func (r *room) broadcast(senderID [16]byte, raw []byte) {
	r.mu.RLock()
	targets := make([]*conn, 0, len(r.clients))
	for id, c := range r.clients {
		if id != senderID {
			targets = append(targets, c)
		}
	}
	r.mu.RUnlock()
	for _, c := range targets {
		c.send(raw)
	}
}

// unicast sends raw to the single client with receiverID.
func (r *room) unicast(receiverID [16]byte, raw []byte) {
	r.mu.RLock()
	c, ok := r.clients[receiverID]
	r.mu.RUnlock()
	if ok {
		c.send(raw)
	}
}

// ─── conn ─────────────────────────────────────────────────────────────────────

type conn struct {
	uuid    [16]byte
	roomID  [16]byte
	netConn net.Conn
	mu      sync.Mutex // serialises Write calls
}

func (c *conn) send(raw []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, _ = c.netConn.Write(raw)
}

// ─── Server ───────────────────────────────────────────────────────────────────

// Server is the SGTP relay server.
type Server struct {
	addr   string
	logger *log.Logger

	roomsMu sync.RWMutex
	rooms   map[[16]byte]*room
}

// New creates a Server that will listen on addr (e.g. ":7777").
// If logger is nil, log.Default() is used.
func New(addr string, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.Default()
	}
	return &Server{
		addr:   addr,
		rooms:  make(map[[16]byte]*room),
		logger: logger,
	}
}

// ListenAndServe starts the TCP listener and blocks until it returns an error.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/server: listen %s: %w", s.addr, err)
	}
	s.logger.Printf("[server] listening on %s", s.addr)
	for {
		tc, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("github.com/SecureGroupTP/sgtp-go/server: accept: %w", err)
		}
		go s.handleConn(tc)
	}
}

// handleConn manages one TCP connection for its lifetime.
func (s *Server) handleConn(nc net.Conn) {
	defer nc.Close()
	remote := nc.RemoteAddr().String()
	s.logger.Printf("[server] new connection from %s", remote)

	// ── Read the connection-intent frame (§3 Step 1) ──────────────────────────
	// Format: [64-byte header][0-byte payload][64-byte signature] = 128 bytes.
	hdrBuf := make([]byte, protocol.HeaderSize)
	if _, err := io.ReadFull(nc, hdrBuf); err != nil {
		s.logger.Printf("[server] %s: read intent header: %v", remote, err)
		return
	}

	hdr, err := protocol.UnmarshalHeader(hdrBuf)
	if err != nil {
		s.logger.Printf("[server] %s: parse intent header: %v", remote, err)
		return
	}

	// Validate payload length before allocating.
	if hdr.PayloadLen > protocol.MaxPayloadLength {
		s.logger.Printf("[server] %s: intent frame payload_length %d too large — closing", remote, hdr.PayloadLen)
		return
	}

	// Read payload (typically 0 bytes) + 64-byte signature.
	tail := make([]byte, int(hdr.PayloadLen)+protocol.SignatureSize)
	if _, err := io.ReadFull(nc, tail); err != nil {
		s.logger.Printf("[server] %s: read intent tail: %v", remote, err)
		return
	}

	roomID := hdr.RoomUUID
	senderID := hdr.SenderUUID
	intentRaw := append(hdrBuf, tail...)

	s.logger.Printf("[server] intent from uuid=%x room=%x", senderID[:4], roomID[:4])

	// ── Register client in room ───────────────────────────────────────────────
	s.roomsMu.Lock()
	r, ok := s.rooms[roomID]
	if !ok {
		r = newRoom()
		s.rooms[roomID] = r
	}
	s.roomsMu.Unlock()

	// Broadcast the intent frame to EXISTING members BEFORE adding the new
	// client — this is what triggers the PING handshake on the other side.
	r.broadcast(senderID, intentRaw)
	s.logger.Printf("[server] intent broadcast to %d existing members", r.count())

	cn := &conn{uuid: senderID, roomID: roomID, netConn: nc}
	r.add(cn)
	s.logger.Printf("[server] uuid=%x joined room=%x (members now: %d)", senderID[:4], roomID[:4], r.count())

	defer func() {
		r.remove(senderID)
		if r.isEmpty() {
			s.roomsMu.Lock()
			delete(s.rooms, roomID)
			s.roomsMu.Unlock()
		}
		s.logger.Printf("[server] uuid=%x left room=%x (members now: %d)", senderID[:4], roomID[:4], r.count())
	}()

	// ── Forward loop ──────────────────────────────────────────────────────────
	for {
		raw, fhdr, err := readRawFrame(nc)
		if err != nil {
			if err != io.EOF {
				s.logger.Printf("[server] uuid=%x read error: %v", senderID[:4], err)
			}
			return
		}

		s.logger.Printf("[server] relay type=0x%02x from=%x to=%x len=%d",
			uint16(fhdr.PacketType), senderID[:4], fhdr.ReceiverUUID[:4], len(raw))

		if fhdr.ReceiverUUID == protocol.BroadcastUUID {
			r.broadcast(senderID, raw)
		} else {
			r.unicast(fhdr.ReceiverUUID, raw)
		}
	}
}

// readRawFrame reads exactly one complete SGTP frame from r.
// It only inspects the header to find boundaries — it does not parse content.
func readRawFrame(r io.Reader) ([]byte, *protocol.Header, error) {
	hdrBuf := make([]byte, protocol.HeaderSize)
	if _, err := io.ReadFull(r, hdrBuf); err != nil {
		return nil, nil, err
	}

	payloadLen := binary.BigEndian.Uint32(hdrBuf[52:56])
	if payloadLen > protocol.MaxPayloadLength {
		return nil, nil, fmt.Errorf("github.com/SecureGroupTP/sgtp-go/server: payload_length %d exceeds maximum", payloadLen)
	}

	rest := make([]byte, int(payloadLen)+protocol.SignatureSize)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, nil, err
	}

	hdr, err := protocol.UnmarshalHeader(hdrBuf)
	if err != nil {
		return nil, nil, err
	}

	return append(hdrBuf, rest...), hdr, nil
}
