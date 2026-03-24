// Command chat is an interactive multi-party SGTP console client.
//
// Usage:
//
//	# Start the relay server once (any machine with a public IP):
//	go run ./cmd/server
//
//	# Each participant:
//	go run ./cmd/chat \
//	    -key       ./keys/ed1   \   # your ed25519 private key (OpenSSH or raw)
//	    -whitelist ./keys/       \   # directory with trusted public keys
//	    -room      <32-hex>      \   # shared room UUID; omit to generate one
//	    -server    localhost:7777
//
// -whitelist scans the directory for files, tries to load each as an ed25519
// public key (OpenSSH or raw 32-byte). Files that don't parse as ed25519 pub
// keys (private keys, RSA, ECDSA, etc.) are silently skipped.
//
// When a client joins a room that already has participants, it automatically
// requests message history and replays it to the terminal.
//
// I/O convention:
//
//	stdout — prompts and messages (pipe-friendly)
//	stderr — structured log output
package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	sgtp "github.com/SecureGroupTP/sgtp-go/client"
	"github.com/SecureGroupTP/sgtp-go/protocol"
)

// ─── main ─────────────────────────────────────────────────────────────────────

func main() {
	serverAddr  := flag.String("server", "localhost:7777", "relay server address (host:port)")
	keyFile     := flag.String("key", "", "path to your ed25519 private key file (required)")
	whitelistDir := flag.String("whitelist", "", "directory containing trusted ed25519 public key files")
	roomHex    := flag.String("room", "", "room UUID as 32 hex chars; omit to generate a new one")
	infoDelay  := flag.Duration("infodelay", 500*time.Millisecond, "peer-discovery delay after first handshake")
	flag.Parse()

	log.SetOutput(os.Stderr)
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	// ── 1. Load identity key ──────────────────────────────────────────────────
	if *keyFile == "" {
		fmt.Fprintln(os.Stderr,
			"error: -key is required\n\nExample:\n"+
				"  go run ./cmd/chat -key ./keys/ed1 -whitelist ./keys/ -room <hex>")
		os.Exit(1)
	}
	pubKey, privKey, err := loadKeyPair(*keyFile)
	must(err, "load identity key from "+*keyFile)
	logErr("Identity key: %s (from %s)", hex.EncodeToString(pubKey), *keyFile)

	// ── 2. Build whitelist from directory ─────────────────────────────────────
	whitelist := make(map[[32]byte]struct{})
	addKey(whitelist, pubKey) // always trust ourselves

	if *whitelistDir != "" {
		loaded, skipped := loadWhitelistDir(*whitelistDir, whitelist)
		logErr("")
		logErr("Whitelist directory: %s", *whitelistDir)
		if len(loaded) == 0 {
			logErr("  (no valid ed25519 public keys found)")
		} else {
			logErr("  Loaded %d key(s):", len(loaded))
			for _, name := range loaded {
				logErr("    ✓ %s", name)
			}
		}
		if len(skipped) > 0 {
			logErr("  Skipped %d file(s) (not a valid ed25519 public key):", len(skipped))
			for _, name := range skipped {
				logErr("    – %s", name)
			}
		}
		logErr("")
	} else {
		logErr("WARNING: no -whitelist specified — only your own key is trusted")
	}

	// ── 3. Room UUID ──────────────────────────────────────────────────────────
	var roomID [16]byte
	if *roomHex != "" {
		clean := strings.ReplaceAll(*roomHex, "-", "")
		b, err := hex.DecodeString(clean)
		if err != nil || len(b) != 16 {
			fmt.Fprintf(os.Stderr, "error: invalid -room %q (need 32 hex chars)\n", *roomHex)
			os.Exit(1)
		}
		copy(roomID[:], b)
		logErr("Room UUID: %s (from -room)", hex.EncodeToString(roomID[:]))
	} else {
		roomID = randomUUID()
		fmt.Printf("\n")
		fmt.Printf("┌─────────────────────────────────────────────────────────────┐\n")
		fmt.Printf("│  New room created. Share this UUID with your peers:         │\n")
		fmt.Printf("│                                                             │\n")
		fmt.Printf("│  %s  │\n", hex.EncodeToString(roomID[:]))
		fmt.Printf("│                                                             │\n")
		fmt.Printf("│  -room %s  │\n", hex.EncodeToString(roomID[:]))
		fmt.Printf("└─────────────────────────────────────────────────────────────┘\n")
		fmt.Printf("\n")
	}

	myUUID := randomUUID()
	logErr("Client UUID: %s", hex.EncodeToString(myUUID[:]))

	// ── 4. Build client ───────────────────────────────────────────────────────
	store := newMemStore()
	c, err := sgtp.New(sgtp.Config{
		ServerAddr:   *serverAddr,
		RoomUUID:     roomID,
		UUID:         myUUID,
		PrivateKey:   privKey,
		PublicKey:    pubKey,
		Whitelist:    whitelist,
		InfoDelay:    *infoDelay,
		HistoryStore: store,
	})
	must(err, "create client")

	// ── 5. Background loops ───────────────────────────────────────────────────
	ckReady     := make(chan struct{}, 1)
	historyDone := make(chan struct{})

	go runEventLoop(c, ckReady, historyDone)
	go runMessageLoop(c)

	// ── 6. Connect ────────────────────────────────────────────────────────────
	logErr("Connecting to %s …", *serverAddr)
	must(c.Connect(), "connect")
	logErr("Connected. Waiting for peers and Chat Key …")

	// ── 7. Ctrl+C ─────────────────────────────────────────────────────────────
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		fmt.Println("\nDisconnecting …")
		_ = c.Disconnect()
		os.Exit(0)
	}()

	// ── 8. Wait for Chat Key ──────────────────────────────────────────────────
	fmt.Println("(waiting for Chat Key …)")
	select {
	case <-ckReady:
	case <-time.After(120 * time.Second):
		log.Fatal("[FATAL] timeout waiting for Chat Key (120 s)")
	}

	// ── 9. Wait for history replay ────────────────────────────────────────────
	select {
	case <-historyDone:
	case <-time.After(10 * time.Second):
	}

	// ── 10. Input loop ────────────────────────────────────────────────────────
	fmt.Println("─── ready ─── Commands: /quit  /peers  /master  /history")
	stdin := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("> ")
		line, err := stdin.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}

		switch line {
		case "/quit", "/exit":
			goto done

		case "/peers":
			peers := c.KnownPeers()
			if len(peers) == 0 {
				fmt.Println("  (no peers)")
			}
			for _, p := range peers {
				fmt.Printf("  • %s\n", hex.EncodeToString(p.UUID[:]))
			}

		case "/master":
			fmt.Printf("  IsMaster: %v\n", c.IsMaster())

		case "/history":
			go fetchAndDisplayHistory(c, false)

		default:
			if strings.HasPrefix(line, "/") {
				fmt.Println("  unknown command. Use: /quit /peers /master /history")
				continue
			}
			if _, err := c.SendMessage([]byte(line)); err != nil {
				fmt.Fprintf(os.Stderr, "[ERR] send: %v\n", err)
			}
		}
	}

done:
	fmt.Fprintln(os.Stderr, "Disconnecting …")
	_ = c.Disconnect()
}

// ─── Whitelist loader ─────────────────────────────────────────────────────────

// loadWhitelistDir scans dir, tries to parse each file as an ed25519 public
// key (OpenSSH or raw 32 bytes). Adds valid keys to wl.
// Returns (loaded filenames, skipped filenames).
func loadWhitelistDir(dir string, wl map[[32]byte]struct{}) (loaded, skipped []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		logErr("WARNING: cannot read whitelist dir %q: %v", dir, err)
		return
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		path := filepath.Join(dir, name)

		pub, err := tryLoadPubKey(path)
		if err != nil {
			skipped = append(skipped, name)
			continue
		}
		addKey(wl, pub)
		loaded = append(loaded, name)
	}
	return
}

// tryLoadPubKey attempts to load an ed25519 public key from path.
// Tries OpenSSH public key format first, then raw 32-byte format.
// Returns error if the file is not a valid ed25519 public key.
func tryLoadPubKey(path string) ([]byte, error) {
	// OpenSSH public key (authorized_keys line): "ssh-ed25519 AAAA… comment"
	pub, _, err := protocol.LoadEd25519FromOpenSSHFile(path)
	if err == nil && len(pub) == 32 {
		return pub, nil
	}

	// Raw 32-byte public key file.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 32 {
		return data, nil
	}

	return nil, fmt.Errorf("not a valid ed25519 public key")
}

// ─── Event loop ───────────────────────────────────────────────────────────────

func runEventLoop(c *sgtp.Client, ckReady chan<- struct{}, historyDone chan<- struct{}) {
	histTriggered  := false
	histDoneClosed := false

	closeHistDone := func() {
		if !histDoneClosed {
			histDoneClosed = true
			close(historyDone)
		}
	}

	for ev := range c.Events() {
		switch ev.Kind {
		case sgtp.EventPeerJoined:
			logErr("[+] peer joined: %s", hex.EncodeToString(ev.PeerUUID[:]))
			clearLine()
			fmt.Printf("[+] peer joined: %s…\n> ", hex.EncodeToString(ev.PeerUUID[:8]))

		case sgtp.EventPeerLeft:
			logErr("[-] peer left: %s", hex.EncodeToString(ev.PeerUUID[:]))
			clearLine()
			fmt.Printf("[-] peer left: %s…\n> ", hex.EncodeToString(ev.PeerUUID[:8]))

		case sgtp.EventPeerKicked:
			logErr("[!] peer kicked: %s", hex.EncodeToString(ev.PeerUUID[:]))
			clearLine()
			fmt.Printf("[!] peer kicked: %s…\n> ", hex.EncodeToString(ev.PeerUUID[:8]))

		case sgtp.EventChatKeyRotated:
			logErr("[*] Chat Key rotated")
			select {
			case ckReady <- struct{}{}:
			default:
			}
			if !histTriggered {
				histTriggered = true
				if len(c.KnownPeers()) == 0 {
					closeHistDone()
				} else {
					go func() {
						fetchAndDisplayHistory(c, true)
						closeHistDone()
					}()
				}
			}

		case sgtp.EventMessageFailed:
			logErr("[!] message %s rejected — resend after CK rotation",
				hex.EncodeToString(ev.MessageUUID[:8]))
			clearLine()
			fmt.Print("[!] your message was rejected — please resend\n> ")

		case sgtp.EventError:
			logErr("[ERR] %v", ev.Err)
		}
	}

	closeHistDone()
}

// ─── Message display ──────────────────────────────────────────────────────────

func runMessageLoop(c *sgtp.Client) {
	for msg := range c.Messages() {
		displayMessage(msg, false)
	}
}

func displayMessage(msg sgtp.InboundMessage, isHistory bool) {
	ts := msg.ReceivedAt.Format("15:04:05")
	sender := hex.EncodeToString(msg.SenderUUID[:4])
	prefix := ""
	if isHistory {
		prefix = "~"
	}
	clearLine()
	fmt.Printf("[%s%s] %s…> %s\n", prefix, ts, sender, msg.Data)
}

func fetchAndDisplayHistory(c *sgtp.Client, isAuto bool) {
	ch, err := c.RequestHistory()
	if err != nil {
		logErr("[ERR] RequestHistory: %v", err)
		return
	}

	var msgs []sgtp.InboundMessage
	for batch := range ch {
		if batch.IsLast {
			break
		}
		for _, raw := range batch.ExtractMessages() {
			msg, err := c.DecryptMessageFrame(raw)
			if err != nil {
				logErr("[history] skip frame: %v", err)
				continue
			}
			msgs = append(msgs, msg)
		}
	}

	if len(msgs) == 0 {
		if !isAuto {
			fmt.Println("  (no history)")
			fmt.Print("> ")
		}
		return
	}

	clearLine()
	fmt.Printf("─── history: %d message(s) ─────────────────────────────────────\n", len(msgs))
	for _, msg := range msgs {
		displayMessage(msg, true)
	}
	fmt.Printf("─── end of history ─────────────────────────────────────────────\n> ")
}

// ─── In-memory HistoryStore ───────────────────────────────────────────────────

type memStore struct {
	mu      sync.RWMutex
	records []sgtp.HistoryRecord
}

func newMemStore() *memStore { return &memStore{} }

func (s *memStore) Count() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return uint64(len(s.records))
}

func (s *memStore) Fetch(offset, limit uint64) []sgtp.HistoryRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := uint64(len(s.records))
	if offset >= total {
		return nil
	}
	end := total
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	result := make([]sgtp.HistoryRecord, end-offset)
	for i, r := range s.records[offset:end] {
		cp := sgtp.HistoryRecord{
			SenderUUID:  r.SenderUUID,
			MessageUUID: r.MessageUUID,
			Timestamp:   r.Timestamp,
			Nonce:       r.Nonce,
		}
		cp.Data = make([]byte, len(r.Data))
		copy(cp.Data, r.Data)
		result[i] = cp
	}
	return result
}

func (s *memStore) Append(r sgtp.HistoryRecord) {
	cp := sgtp.HistoryRecord{
		SenderUUID:  r.SenderUUID,
		MessageUUID: r.MessageUUID,
		Timestamp:   r.Timestamp,
		Nonce:       r.Nonce,
	}
	cp.Data = make([]byte, len(r.Data))
	copy(cp.Data, r.Data)
	s.mu.Lock()
	s.records = append(s.records, cp)
	s.mu.Unlock()
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func loadKeyPair(path string) (pub []byte, priv []byte, err error) {
	pub, priv, err = protocol.LoadEd25519FromOpenSSHFile(path)
	if err == nil && priv != nil {
		return
	}
	pub, priv, err = protocol.LoadEd25519FromFileRaw(path)
	return
}

func addKey(wl map[[32]byte]struct{}, pub []byte) {
	var arr [32]byte
	copy(arr[:], pub)
	wl[arr] = struct{}{}
}

func randomUUID() [16]byte {
	return uuidV7()
}

// uuidV7 generates a UUID version 7 (RFC 9562).
// The 48 high bits carry the current Unix timestamp in milliseconds,
// so lexicographic order matches time order.  This guarantees that a
// client joining later always gets a larger UUID and therefore never
// accidentally becomes master (master = smallest UUID).
func uuidV7() [16]byte {
	var u [16]byte
	f, err := os.Open("/dev/urandom")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	_, _ = f.Read(u[:])

	// Overwrite the top 48 bits with the current timestamp in ms.
	now := uint64(time.Now().UnixMilli())
	u[0] = byte(now >> 40)
	u[1] = byte(now >> 32)
	u[2] = byte(now >> 24)
	u[3] = byte(now >> 16)
	u[4] = byte(now >> 8)
	u[5] = byte(now)

	// Version 7, variant bits.
	u[6] = (u[6] & 0x0f) | 0x70
	u[8] = (u[8] & 0x3f) | 0x80
	return u
}

func clearLine() { fmt.Print("\r\033[2K") }
func logErr(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) }
func must(err error, msg string) {
	if err != nil {
		log.Fatalf("[FATAL] %s: %v", msg, err)
	}
}
