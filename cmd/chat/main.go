// Command chat is an interactive two-party SGTP console client.
//
// Run on two machines (or two terminals on localhost) to chat:
//
//	Terminal 1:  go run ./cmd/server          # start relay (once)
//	Terminal 2:  go run ./cmd/chat -server localhost:7777
//	Terminal 3:  go run ./cmd/chat -server localhost:7777
//
// Each client prints its UUID and public key on stdout. Copy those values into
// the other client when prompted. After the handshake completes the master
// (smallest UUID) issues a Chat Key automatically, and both sides can type
// messages.
//
// I/O convention:
//
//	stdout  — user prompts, received messages (pipe-friendly)
//	stderr  — all log / debug output
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	sgtp "github.com/SecureGroupTP/sgtp-go/client"
	"github.com/SecureGroupTP/sgtp-go/protocol"
	"golang.org/x/crypto/ssh"
)

func main() {
	serverAddr := flag.String("server", "localhost:7777", "relay server TCP address")
	infoDelay := flag.Duration("infodelay", 500*time.Millisecond, "discovery delay after first handshake")
	flag.Parse()

	// All structured logs → stderr.
	log.SetOutput(os.Stderr)
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	stdin := bufio.NewReader(os.Stdin)

	// ── 1. Generate identity ─────────────────────────────────────────────────
	printErr("=== SGTP Chat ===")
	printErr("Generating ed25519 identity …")

	pubKey, privKey, err := collectPeerKeyPair(stdin)
	must(err, "generate ed25519")

	myUUID := newUUID()
	roomID := newUUID()

	wlist, err := buildWhitelist([]string{
		"AAAAC3NzaC1lZDI1NTE5AAAAIHIfJYPmiTSuS/fvlV+s2BnUaulkTrRJUNz8D2WYhtnf",
		"AAAAC3NzaC1lZDI1NTE5AAAAIBEH5TJGcAv4W6tngWspw06jhD95iwSqRRO6vSW7gAMT",
		"AAAAC3NzaC1lZDI1NTE5AAAAICwn08JpI/ATboTg6HB7g0rU4sgI6OTne7t6+Tkk7RAh",
	})

	if err != nil {
		panic(fmt.Sprintf("error while to building whitelist: %s", err.Error()))
	}

	// Print to stdout so the user can copy-paste to the peer.
	fmt.Printf("─── Share with your peer ───────────────────────────────────────\n")
	fmt.Printf("UUID  : %s\n", hexStr(myUUID[:]))
	fmt.Printf("Room  : %s\n", hexStr(roomID[:]))
	fmt.Printf("PUBKEY: %s\n", hexStr(pubKey))
	fmt.Printf("────────────────────────────────────────────────────────────────\n\n")

	// ── 2. Collect peer identity ─────────────────────────────────────────────
	roomID = collectPeerIdentity(stdin)

	// ── 3. Derive room ID (commutative XOR of the two UUIDs) ─────────────────

	// ── 4. Build client ──────────────────────────────────────────────────────
	c, err := sgtp.New(sgtp.Config{
		ServerAddr: *serverAddr,
		RoomUUID:   roomID,
		UUID:       myUUID,
		PrivateKey: privKey,
		PublicKey:  pubKey,
		Whitelist:  wlist,
		InfoDelay:  *infoDelay,
	})
	must(err, "create client")

	// ── 5. Event loop ────────────────────────────────────────────────────────
	ckReady := make(chan struct{}, 1)
	go runEventLoop(c, ckReady, privKey)

	// ── 6. Message display ───────────────────────────────────────────────────
	go func() {
		for msg := range c.Messages() {
			ts := msg.ReceivedAt.Format("15:04:05")
			// \r clears any partial "> " prompt before printing.
			fmt.Printf("\r\033[2K[%s] peer> %s\n> ", ts, msg.Data)
		}
	}()

	// ── 7. Connect ───────────────────────────────────────────────────────────
	printErr("Connecting to %s …", *serverAddr)
	must(c.Connect(), "connect")
	printErr("Connected. Waiting for peer to join …")

	// ── 8. Wait for Chat Key ─────────────────────────────────────────────────
	printErr("(waiting for Chat Key — the master will issue it automatically)")
	select {
	case <-ckReady:
		fmt.Println("\n✓ Chat Key received. You can type now.")
	case <-time.After(60 * time.Second):
		log.Fatal("[FATAL] timeout waiting for Chat Key (60s)")
	}

	// ── 9. Handle Ctrl+C ─────────────────────────────────────────────────────
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		fmt.Println("\nDisconnecting …")
		_ = c.Disconnect()
		os.Exit(0)
	}()

	// ── 10. Message input loop ────────────────────────────────────────────────
	fmt.Println("Commands: /quit to exit, /peers to list peers")
	for {
		fmt.Print("> ")
		line, err := stdin.ReadString('\n')
		if err != nil {
			break // EOF (Ctrl+D)
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
				fmt.Printf("  • %s\n", hexStr(p.UUID[:]))
			}
			continue
		case "/master":
			fmt.Printf("  IsMaster: %v\n", c.IsMaster())
			continue
		}

		if _, err := c.SendMessage([]byte(line)); err != nil {
			fmt.Fprintf(os.Stderr, "[ERR] send: %v\n", err)
		}
	}

done:
	fmt.Fprintln(os.Stderr, "Disconnecting …")
	_ = c.Disconnect()
}

// ─── Event loop ───────────────────────────────────────────────────────────────

func runEventLoop(c *sgtp.Client, ckReady chan<- struct{}, _ ed25519.PrivateKey) {
	for ev := range c.Events() {
		switch ev.Kind {
		case sgtp.EventPeerJoined:
			printErr("[+] peer joined: %s", hexStr(ev.PeerUUID[:]))
			fmt.Printf("\r\033[2K[+] peer joined: %s\n> ", hexShort(ev.PeerUUID[:]))

			// If we are the master, issue a Chat Key to this peer.
			if c.IsMaster() {
				printErr("[master] we are master — issuing Chat Key")
				go func() {
					// Brief delay so the peer's PONG finishes processing.
					time.Sleep(100 * time.Millisecond)
					if err := c.IssueChatKeyToAll(); err != nil {
						printErr("[master] IssueChatKey error: %v", err)
					}
				}()
			}

		case sgtp.EventPeerLeft:
			printErr("[-] peer left: %s", hexShort(ev.PeerUUID[:]))
			fmt.Printf("\r\033[2K[-] peer left: %s\n> ", hexShort(ev.PeerUUID[:]))

		case sgtp.EventPeerKicked:
			printErr("[!] peer kicked: %s", hexShort(ev.PeerUUID[:]))
			fmt.Printf("\r\033[2K[!] peer kicked: %s\n> ", hexShort(ev.PeerUUID[:]))

		case sgtp.EventChatKeyRotated:
			printErr("[*] Chat Key active (epoch updated)")
			select {
			case ckReady <- struct{}{}:
			default:
			}

		case sgtp.EventMessageFailed:
			printErr("[!] message %s rejected — resend after CK rotation", hexShort(ev.MessageUUID[:]))
			fmt.Printf("\r\033[2K[!] your message was rejected — please resend\n> ")

		case sgtp.EventError:
			printErr("[ERR] %v", ev.Err)
		}
	}
}

// ─── Peer identity collection ─────────────────────────────────────────────────

func collectPeerIdentity(r *bufio.Reader) [16]byte {
	var peerUUID [16]byte

	for {
		fmt.Print("Enter room UUID   : ")
		uuidHex := strings.TrimSpace(readLine(r))
		uuidHex = strings.ReplaceAll(uuidHex, "-", "")
		b, err := hex.DecodeString(uuidHex)
		if err != nil || len(b) != 16 {
			fmt.Fprintln(os.Stderr, "  ✗ must be 32 hex characters (16 bytes). Try again.")
			continue
		}
		copy(peerUUID[:], b)
		break
	}

	return peerUUID
}

// ─── Utilities ───────────────────────────────────────────────────────────────

func readLine(r *bufio.Reader) string {
	line, _ := r.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

func hexStr(b []byte) string   { return hex.EncodeToString(b) }
func hexShort(b []byte) string { return hex.EncodeToString(b[:4]) + "…" }

func printErr(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func newUUID() [16]byte {
	var u [16]byte
	_, err := rand.Read(u[:])
	if err != nil {
		log.Fatalf("rand.Read: %v", err)
	}
	u[6] = (u[6] & 0x0f) | 0x40 // version 4
	u[8] = (u[8] & 0x3f) | 0x80 // variant RFC 4122
	return u
}

func must(err error, msg string) {
	if err != nil {
		log.Fatalf("[FATAL] %s: %v", msg, err)
	}
}

func buildWhitelist(keysSSH []string) (map[[32]byte]struct{}, error) {
	whitelist := make(map[[32]byte]struct{}, len(keysSSH))

	for i, keyStr := range keysSSH {
		// Убираем возможные префиксы типа "ssh-ed25519 " и комментарии
		parts := strings.Fields(keyStr)
		var keyBlob string
		if len(parts) >= 2 {
			keyBlob = parts[1] // берём base64-часть
		} else {
			keyBlob = keyStr
		}

		// Парсим как SSH public key
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte("ssh-ed25519 " + keyBlob))
		if err != nil {
			return nil, fmt.Errorf("invalid SSH key at index %d: %w", i, err)
		}

		// Извлекаем сырой ed25519.PublicKey
		rawKey, ok := pubKey.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key at index %d is not ed25519", i)
		}

		// Конвертируем []byte -> [32]byte
		if len(rawKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid key length at index %d", i)
		}
		var keyArray [32]byte
		copy(keyArray[:], rawKey)
		whitelist[keyArray] = struct{}{}
	}
	return whitelist, nil
}

func collectPeerPublicKey(r *bufio.Reader) (ed25519.PublicKey, error) {
	for {
		fmt.Print("Enter peer public key file: ")
		filename := strings.TrimSpace(readLine(r))

		if filename == "" {
			fmt.Fprintln(os.Stderr, "  ✗ filename cannot be empty. Try again.")
			continue
		}

		pubKey, _, err := protocol.LoadEd25519FromOpenSSHFile(filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ failed to load key from %s: %v. Try again.\n", filename, err)
			continue
		}

		if len(pubKey) != ed25519.PublicKeySize {
			fmt.Fprintln(os.Stderr, "  ✗ invalid public key size. Try again.")
			continue
		}

		return pubKey, nil
	}
}
func collectPeerKeyPair(r *bufio.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	for {
		fmt.Print("Enter peer key file: ")
		filename := strings.TrimSpace(readLine(r))

		if filename == "" {
			fmt.Fprintln(os.Stderr, "  ✗ filename cannot be empty. Try again.")
			continue
		}

		// Сначала пробуем raw-формат (твоя функция из protocol)
		pubKey, privKey, err := protocol.LoadEd25519FromFileRaw(filename)
		if err == nil {
			return pubKey, privKey, nil
		}

		// Потом пробуем OpenSSH-формат
		pubKey, privKey, err = protocol.LoadEd25519FromOpenSSHFile(filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ failed to load keys: %v. Try again.\n", err)
			continue
		}

		return pubKey, privKey, nil
	}
}
