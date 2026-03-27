// Command webbridge is a WebSocket-to-SGTP bridge.
//
// Exposes an HTTP server; browsers connect over WebSocket. For each session
// the bridge creates a full SGTP client and forwards messages bidirectionally.
//
// ZERO extra dependencies — WebSocket is implemented per RFC 6455 using only
// the Go standard library. golang.org/x/crypto is used indirectly via the
// sgtp packages (already in go.mod).
//
// Usage:
//
//	# Terminal 1 – relay server
//	go run ./cmd/server -addr :7777
//
//	# Terminal 2 – web bridge (serves ./web/index.html on :8080)
//	go run ./cmd/webbridge -relay localhost:7777 -http :8080 -whitelist ./keys/
//
//	# Browser
//	open http://localhost:8080
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	sgtp "github.com/SecureGroupTP/sgtp-go/client"
	"github.com/SecureGroupTP/sgtp-go/protocol"
)

// ── main ──────────────────────────────────────────────────────────────────────

var KeyPath string

func main() {
	relayAddr := flag.String("relay", "localhost:7777", "SGTP relay server address")
	httpAddr := flag.String("http", ":8080", "HTTP/WebSocket listen address")
	whitelistDir := flag.String("whitelist", "", "directory with trusted ed25519 public keys")
	webDir := flag.String("web", "./web", "directory to serve static files (web/index.html)")
	keyPath := flag.String("key", "", "Path to private key")
	flag.Parse()
	KeyPath = *keyPath
	log.SetOutput(os.Stderr)
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	whitelist := make(map[[32]byte]struct{})
	if *whitelistDir != "" {
		loaded, skipped := loadWhitelistDir(*whitelistDir, whitelist)
		log.Printf("whitelist: loaded %d, skipped %d", len(loaded), len(skipped))
	} else {
		log.Printf("WARNING: no -whitelist — every SGTP peer is trusted")
	}

	hub := &Hub{relayAddr: *relayAddr, whitelist: whitelist}

	http.Handle("/ws", http.HandlerFunc(hub.serveWS))
	http.Handle("/", http.FileServer(http.Dir(*webDir)))

	log.Printf("webbridge on %s  (relay=%s, web=%s)", *httpAddr, *relayAddr, *webDir)
	if err := http.ListenAndServe(*httpAddr, nil); err != nil {
		log.Fatalf("http: %v", err)
	}
}

// ── Hub ───────────────────────────────────────────────────────────────────────

type Hub struct {
	relayAddr string
	whitelist map[[32]byte]struct{}
}

func (h *Hub) serveWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgradeWebSocket(w, r)
	if err != nil {
		log.Printf("ws upgrade: %v", err)
		return
	}
	sess := &Session{
		conn:      conn,
		relayAddr: h.relayAddr,
		whitelist: h.whitelist,
		send:      make(chan []byte, 256),
		quit:      make(chan struct{}),
		peers:     make(map[string]string),
	}
	sess.run()
}

// ── Session ───────────────────────────────────────────────────────────────────

type Session struct {
	conn      *wsConn
	relayAddr string
	whitelist map[[32]byte]struct{}

	client *sgtp.Client
	uuid   [16]byte
	pubHex string

	send chan []byte
	quit chan struct{}

	peersMu sync.RWMutex
	peers   map[string]string

	seqMu sync.Mutex
	seq   uint64
}

// ── Bridge wire types ─────────────────────────────────────────────────────────

// BridgeCommand is sent by the browser to the bridge.
type BridgeCommand struct {
	Cmd     string          `json:"cmd"`
	Server  string          `json:"server,omitempty"`  // init: relay addr override
	Room    string          `json:"room,omitempty"`    // init: room uuid hex (empty = new)
	KeyHex  string          `json:"key,omitempty"`     // init: 64-byte ed25519 privkey hex
	Nick    string          `json:"nick,omitempty"`    // init: display name
	Payload json.RawMessage `json:"payload,omitempty"` // msg: ChatPayload JSON
}

// BridgeEvent is sent by the bridge to the browser.
type BridgeEvent struct {
	Evt     string          `json:"evt"`
	UUID    string          `json:"uuid,omitempty"`
	Room    string          `json:"room,omitempty"`
	PubKey  string          `json:"pubkey,omitempty"`
	Nick    string          `json:"nick,omitempty"`
	From    string          `json:"from,omitempty"`
	TS      int64           `json:"ts,omitempty"`
	SeqNo   uint64          `json:"seq,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Msg     string          `json:"msg,omitempty"`
}

// ── Session lifecycle ─────────────────────────────────────────────────────────

func (s *Session) run() {
	go s.writer()
	defer func() {
		close(s.quit)
		if s.client != nil {
			_ = s.client.Disconnect()
		}
		s.conn.close()
	}()

	for {
		raw, err := s.conn.readMessage()
		if err != nil {
			return
		}
		var cmd BridgeCommand
		if err := json.Unmarshal(raw, &cmd); err != nil {
			s.pushErr("bad JSON: " + err.Error())
			continue
		}
		s.dispatch(cmd)
	}
}

func (s *Session) dispatch(cmd BridgeCommand) {
	switch cmd.Cmd {
	case "init":
		s.handleInit(cmd)
	case "msg":
		s.handleMsg(cmd)
	case "history":
		s.push(BridgeEvent{Evt: "history_done"})
	case "quit":
		if s.client != nil {
			_ = s.client.Disconnect()
			s.client = nil
		}
	default:
		s.pushErr("unknown cmd: " + cmd.Cmd)
	}
}

// ── handleInit ────────────────────────────────────────────────────────────────

func (s *Session) handleInit(cmd BridgeCommand) {
	if s.client != nil {
		s.pushErr("already connected — send quit first")
		return
	}

	relay := s.relayAddr
	if cmd.Server != "" {
		relay = cmd.Server
	}

	// Keypair.
	var pubKey, privKey []byte
	if cmd.KeyHex != "" {
		raw, err := hex.DecodeString(cmd.KeyHex)
		if err != nil || len(raw) != 64 {
			s.pushErr("key: need 128 hex chars (64-byte raw ed25519 privkey)")
			return
		}
		privKey = raw
		pubKey = raw[32:]
	} else {
		pub, priv, err := protocol.LoadEd25519FromOpenSSHFile(KeyPath)
		if err != nil {
			s.pushErr("keygen: " + err.Error())
			return
		}
		pubKey = pub
		privKey = priv
	}

	// Room UUID.
	var roomID [16]byte
	if cmd.Room != "" {
		clean := strings.ReplaceAll(cmd.Room, "-", "")
		b, err := hex.DecodeString(clean)
		if err != nil || len(b) != 16 {
			s.pushErr("room: need 32 hex chars")
			return
		}
		copy(roomID[:], b)
	} else {
		roomID = randomUUID()
	}

	myUUID := uuidV7()

	wl := make(map[[32]byte]struct{}, len(s.whitelist)+1)
	for k, v := range s.whitelist {
		wl[k] = v
	}
	var arr [32]byte
	copy(arr[:], pubKey)
	wl[arr] = struct{}{}

	c, err := sgtp.New(sgtp.Config{
		ServerAddr:   relay,
		RoomUUID:     roomID,
		UUID:         myUUID,
		PrivateKey:   privKey,
		PublicKey:    pubKey,
		Whitelist:    wl,
		InfoDelay:    500 * time.Millisecond,
		HistoryStore: newMemStore(),
	})
	if err != nil {
		s.pushErr("client: " + err.Error())
		return
	}

	s.client = c
	s.uuid = myUUID
	s.pubHex = hex.EncodeToString(pubKey)

	go s.eventLoop()
	go s.msgLoop()

	if err := c.Connect(); err != nil {
		s.pushErr("connect: " + err.Error())
		s.client = nil
		return
	}

	s.push(BridgeEvent{
		Evt:    "ready",
		UUID:   fmtUUID(myUUID),
		Room:   hex.EncodeToString(roomID[:]),
		PubKey: s.pubHex,
		Nick:   cmd.Nick,
	})
}

// ── handleMsg ─────────────────────────────────────────────────────────────────

func (s *Session) handleMsg(cmd BridgeCommand) {
	if s.client == nil {
		s.pushErr("not connected")
		return
	}
	if len(cmd.Payload) == 0 {
		s.pushErr("msg: empty payload")
		return
	}
	msgUUID, err := s.client.SendMessage(cmd.Payload)
	if err != nil {
		s.pushErr("send: " + err.Error())
		return
	}
	s.seqMu.Lock()
	s.seq++
	seq := s.seq
	s.seqMu.Unlock()

	s.push(BridgeEvent{
		Evt:     "msg_echo",
		UUID:    hex.EncodeToString(msgUUID[:]),
		From:    fmtUUID(s.uuid),
		TS:      time.Now().UnixMilli(),
		SeqNo:   seq,
		Payload: cmd.Payload,
	})
}

// ── eventLoop / msgLoop ───────────────────────────────────────────────────────

func (s *Session) eventLoop() {
	for {
		select {
		case <-s.quit:
			return
		case ev, ok := <-s.client.Events():
			if !ok {
				return
			}
			switch ev.Kind {
			case sgtp.EventPeerJoined:
				pubHex := ""
				for _, p := range s.client.KnownPeers() {
					if p.UUID == ev.PeerUUID {
						pubHex = hex.EncodeToString(p.PubKeyEd25519)
						break
					}
				}
				uid := fmtUUID(ev.PeerUUID)
				s.peersMu.Lock()
				s.peers[uid] = pubHex
				s.peersMu.Unlock()
				s.push(BridgeEvent{Evt: "peer_join", UUID: uid, PubKey: pubHex})
			case sgtp.EventPeerLeft, sgtp.EventPeerKicked:
				uid := fmtUUID(ev.PeerUUID)
				s.peersMu.Lock()
				delete(s.peers, uid)
				s.peersMu.Unlock()
				evt := "peer_leave"
				if ev.Kind == sgtp.EventPeerKicked {
					evt = "peer_kick"
				}
				s.push(BridgeEvent{Evt: evt, UUID: uid})
			case sgtp.EventChatKeyRotated:
				s.push(BridgeEvent{Evt: "ck_rotated"})
			case sgtp.EventMessageFailed:
				s.push(BridgeEvent{Evt: "msg_failed", UUID: hex.EncodeToString(ev.MessageUUID[:])})
			case sgtp.EventError:
				if ev.Err != nil {
					s.pushErr(ev.Err.Error())
				}
			}
		}
	}
}

func (s *Session) msgLoop() {
	for {
		select {
		case <-s.quit:
			return
		case im, ok := <-s.client.Messages():
			if !ok {
				return
			}
			payload := json.RawMessage(im.Data)
			if !json.Valid(payload) {
				payload, _ = json.Marshal(map[string]string{"type": "text", "text": string(im.Data)})
			}
			s.seqMu.Lock()
			s.seq++
			seq := s.seq
			s.seqMu.Unlock()

			s.push(BridgeEvent{
				Evt:     "msg",
				UUID:    hex.EncodeToString(im.MessageUUID[:]),
				From:    fmtUUID(im.SenderUUID),
				TS:      im.ReceivedAt.UnixMilli(),
				SeqNo:   seq,
				Payload: payload,
			})
		}
	}
}

// ── writer ────────────────────────────────────────────────────────────────────

func (s *Session) writer() {
	for {
		select {
		case <-s.quit:
			return
		case msg := <-s.send:
			if err := s.conn.writeMessage(msg); err != nil {
				return
			}
		}
	}
}

func (s *Session) push(ev BridgeEvent) {
	raw, _ := json.Marshal(ev)
	select {
	case s.send <- raw:
	default:
	}
}

func (s *Session) pushErr(msg string) {
	s.push(BridgeEvent{Evt: "error", Msg: msg})
}

// ── In-memory history store ───────────────────────────────────────────────────

type memStore struct {
	mu      sync.Mutex
	records []sgtp.HistoryRecord
}

func newMemStore() *memStore { return &memStore{} }

func (m *memStore) Count() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return uint64(len(m.records))
}

func (m *memStore) Fetch(offset, limit uint64) []sgtp.HistoryRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	if offset >= uint64(len(m.records)) {
		return nil
	}
	end := uint64(len(m.records))
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	out := make([]sgtp.HistoryRecord, end-offset)
	copy(out, m.records[offset:end])
	return out
}

func (m *memStore) Append(r sgtp.HistoryRecord) {
	m.mu.Lock()
	m.records = append(m.records, r)
	m.mu.Unlock()
}

// ── Whitelist loader ──────────────────────────────────────────────────────────

func loadWhitelistDir(dir string, wl map[[32]byte]struct{}) (loaded, skipped []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("whitelist: cannot read dir %s: %v", dir, err)
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		pub, err := tryLoadPubKey(path)
		if err != nil {
			skipped = append(skipped, e.Name())
			continue
		}
		var arr [32]byte
		copy(arr[:], pub)
		wl[arr] = struct{}{}
		loaded = append(loaded, e.Name())
	}
	return
}

func tryLoadPubKey(path string) ([]byte, error) {
	pub, _, err := protocol.LoadEd25519FromOpenSSHFile(path)
	if err == nil && len(pub) == 32 {
		return pub, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 32 {
		return data, nil
	}
	return nil, fmt.Errorf("not an ed25519 pubkey")
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func fmtUUID(u [16]byte) string { return hex.EncodeToString(u[:]) }

func randomUUID() [16]byte {
	var u [16]byte
	_, _ = rand.Read(u[:])
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return u
}

func uuidV7() [16]byte {
	var u [16]byte
	now := uint64(time.Now().UnixMilli())
	u[0] = byte(now >> 40)
	u[1] = byte(now >> 32)
	u[2] = byte(now >> 24)
	u[3] = byte(now >> 16)
	u[4] = byte(now >> 8)
	u[5] = byte(now)
	_, _ = rand.Read(u[6:])
	u[6] = (u[6] & 0x0f) | 0x70
	u[8] = (u[8] & 0x3f) | 0x80
	return u
}

// ── Zero-dependency WebSocket (RFC 6455) ──────────────────────────────────────

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// upgradeWebSocket performs the HTTP→WS handshake and hijacks the TCP connection.
func upgradeWebSocket(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, fmt.Errorf("not a WebSocket upgrade")
	}
	key := r.Header.Get("Sec-Websocket-Key")
	if key == "" {
		return nil, fmt.Errorf("missing Sec-WebSocket-Key")
	}
	h := sha1.New()
	h.Write([]byte(key + wsGUID))
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("hijacking not supported")
	}
	netConn, bufrw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := bufrw.WriteString(resp); err != nil {
		netConn.Close()
		return nil, err
	}
	if err := bufrw.Flush(); err != nil {
		netConn.Close()
		return nil, err
	}
	return &wsConn{conn: netConn, br: bufrw.Reader}, nil
}

// wsConn wraps a hijacked TCP connection and implements WebSocket framing.
type wsConn struct {
	conn net.Conn
	br   *bufio.Reader
	wmu  sync.Mutex
}

func (c *wsConn) close() { c.conn.Close() }

// readMessage reads a complete WebSocket message (reassembling fragments).
func (c *wsConn) readMessage() ([]byte, error) {
	var msg []byte
	for {
		fin, opcode, payload, err := c.readFrame()
		if err != nil {
			return nil, err
		}
		switch opcode {
		case 8: // close
			return nil, io.EOF
		case 9: // ping → pong
			_ = c.writeFrame(10, payload)
			continue
		case 10: // pong
			continue
		}
		msg = append(msg, payload...)
		if fin {
			return msg, nil
		}
	}
}

func (c *wsConn) readFrame() (fin bool, opcode byte, payload []byte, err error) {
	b0, e := c.br.ReadByte()
	if e != nil {
		return false, 0, nil, e
	}
	fin = b0&0x80 != 0
	opcode = b0 & 0x0f

	b1, e := c.br.ReadByte()
	if e != nil {
		return false, 0, nil, e
	}
	masked := b1&0x80 != 0
	length := int64(b1 & 0x7f)

	switch length {
	case 126:
		var ext [2]byte
		if _, e = io.ReadFull(c.br, ext[:]); e != nil {
			return false, 0, nil, e
		}
		length = int64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, e = io.ReadFull(c.br, ext[:]); e != nil {
			return false, 0, nil, e
		}
		length = int64(binary.BigEndian.Uint64(ext[:]))
	}

	var mask [4]byte
	if masked {
		if _, e = io.ReadFull(c.br, mask[:]); e != nil {
			return false, 0, nil, e
		}
	}

	data := make([]byte, length)
	if _, e = io.ReadFull(c.br, data); e != nil {
		return false, 0, nil, e
	}
	if masked {
		for i := range data {
			data[i] ^= mask[i%4]
		}
	}
	return fin, opcode, data, nil
}

func (c *wsConn) writeMessage(payload []byte) error { return c.writeFrame(1, payload) }

func (c *wsConn) writeFrame(opcode byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	n := len(payload)
	header := []byte{0x80 | opcode}
	switch {
	case n <= 125:
		header = append(header, byte(n))
	case n <= 65535:
		header = append(header, 126, byte(n>>8), byte(n))
	default:
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		header = append(header, 127)
		header = append(header, ext[:]...)
	}
	if _, err := c.conn.Write(header); err != nil {
		return err
	}
	if n > 0 {
		_, err := c.conn.Write(payload)
		return err
	}
	return nil
}
