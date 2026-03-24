package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	sgtp "github.com/SecureGroupTP/sgtp-go/client"
	"github.com/SecureGroupTP/sgtp-go/protocol"
	"github.com/SecureGroupTP/sgtp-go/server"
)

// makeUUID makes a time-ordered UUID where n acts as a sub-millisecond
// counter so uuid(1) < uuid(2), matching UUIDv7 ordering semantics.
func makeUUID(n byte) [16]byte {
	var u [16]byte
	now := uint64(time.Now().UnixMilli())
	u[0] = byte(now >> 40)
	u[1] = byte(now >> 32)
	u[2] = byte(now >> 24)
	u[3] = byte(now >> 16)
	u[4] = byte(now >> 8)
	u[5] = byte(now)
	u[6] = 0x70 // version 7
	u[7] = n    // sub-ms disambiguator: smaller n → smaller UUID → master
	u[8] = 0x80 // variant
	return u
}

func startTestServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	srv := server.New(addr, nil)
	go func() { _ = srv.ListenAndServe() }()
	time.Sleep(50 * time.Millisecond) // let listener start
	return addr
}

func makeClient(t *testing.T, addr string, roomID [16]byte, n byte,
	whitelist map[[32]byte]struct{}) *sgtp.Client {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	var pk32 [32]byte
	copy(pk32[:], pub)
	whitelist[pk32] = struct{}{}

	c, err := sgtp.New(sgtp.Config{
		ServerAddr: addr,
		RoomUUID:   roomID,
		UUID:       makeUUID(n),
		PrivateKey: priv,
		PublicKey:  pub,
		Whitelist:  whitelist,
		InfoDelay:  100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestHandshakeAndMessage verifies the full happy path:
// server → two clients handshake → master issues CK → both can exchange messages.
func TestHandshakeAndMessage(t *testing.T) {
	addr := startTestServer(t)
	roomID := makeUUID(0xff)
	wl := make(map[[32]byte]struct{})

	// Generate keys upfront so whitelist has both before connecting.
	pub1, priv1, _ := ed25519.GenerateKey(nil)
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	var arr1, arr2 [32]byte
	copy(arr1[:], pub1)
	copy(arr2[:], pub2)
	wl[arr1] = struct{}{}
	wl[arr2] = struct{}{}

	uuid1 := makeUUID(1) // smaller → master
	uuid2 := makeUUID(2)

	c1, _ := sgtp.New(sgtp.Config{ServerAddr: addr, RoomUUID: roomID, UUID: uuid1,
		PrivateKey: priv1, PublicKey: pub1, Whitelist: wl, InfoDelay: 100 * time.Millisecond})
	c2, _ := sgtp.New(sgtp.Config{ServerAddr: addr, RoomUUID: roomID, UUID: uuid2,
		PrivateKey: priv2, PublicKey: pub2, Whitelist: wl, InfoDelay: 100 * time.Millisecond})

	defer c1.Disconnect()
	defer c2.Disconnect()

	// Wait for both to have CK.
	ck1 := make(chan struct{}, 2)
	ck2 := make(chan struct{}, 2)
	go func() {
		for ev := range c1.Events() {
			if ev.Kind == sgtp.EventChatKeyRotated {
				ck1 <- struct{}{}
			}
		}
	}()
	go func() {
		for ev := range c2.Events() {
			if ev.Kind == sgtp.EventChatKeyRotated {
				ck2 <- struct{}{}
			}
		}
	}()

	if err := c1.Connect(); err != nil {
		t.Fatal("c1 connect:", err)
	}
	time.Sleep(50 * time.Millisecond) // stagger joins
	if err := c2.Connect(); err != nil {
		t.Fatal("c2 connect:", err)
	}

	timeout := time.After(10 * time.Second)
	select {
	case <-ck1:
	case <-timeout:
		t.Fatal("timeout waiting for c1 CK")
	}
	select {
	case <-ck2:
	case <-timeout:
		t.Fatal("timeout waiting for c2 CK")
	}

	// c2 sends a message; c1 should receive it.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case msg := <-c1.Messages():
			if string(msg.Data) != "hello from c2" {
				t.Errorf("unexpected message: %q", msg.Data)
			}
		case <-time.After(5 * time.Second):
			t.Error("timeout waiting for message on c1")
		}
	}()

	if _, err := c2.SendMessage([]byte("hello from c2")); err != nil {
		t.Fatal("send:", err)
	}
	wg.Wait()
}

// TestPacketMarshalUnmarshal verifies all packet round-trips.
func TestPacketMarshalUnmarshal(t *testing.T) {
	room := makeUUID(0xAA)
	sender := makeUUID(0x01)
	recv := makeUUID(0x02)
	ts := protocol.NowMillis()

	hdr := func(pt protocol.PacketType, plen uint32) *protocol.Header {
		return &protocol.Header{
			RoomUUID: room, ReceiverUUID: recv, SenderUUID: sender,
			Version: protocol.ProtocolVersion, PacketType: pt,
			PayloadLen: plen, Timestamp: ts,
		}
	}

	t.Run("Ping", func(t *testing.T) {
		var x, e [32]byte
		x[0], e[0] = 1, 2
		p := &protocol.Ping{PubKeyX25519: x, PubKeyEd25519: e, Body: []byte(protocol.ClientHello)}
		*p.GetHeader() = *hdr(protocol.TypePing, uint32(64+len(p.Body)))
		raw := p.Marshal()
		// reparse
		got, err := protocol.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		pg := got.(*protocol.Ping)
		if pg.PubKeyX25519 != x || pg.PubKeyEd25519 != e {
			t.Error("key mismatch after Ping round-trip")
		}
		if string(pg.Body) != protocol.ClientHello {
			t.Errorf("body mismatch: %q", pg.Body)
		}
	})

	t.Run("Pong", func(t *testing.T) {
		var x, e [32]byte
		x[0], e[0] = 3, 4
		p := &protocol.Pong{PubKeyX25519: x, PubKeyEd25519: e, Body: []byte(protocol.ClientHello)}
		*p.GetHeader() = *hdr(protocol.TypePong, uint32(64+len(p.Body)))
		raw := p.Marshal()
		got, err := protocol.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		pg := got.(*protocol.Pong)
		if pg.PubKeyX25519 != x || pg.PubKeyEd25519 != e {
			t.Error("key mismatch after Pong round-trip")
		}
	})

	t.Run("ChatKey_epoch_nonce", func(t *testing.T) {
		var ck [32]byte
		ck[0] = 0xAB
		epoch := uint64(42)

		// Encrypt key with epoch as nonce.
		var sharedSecret [32]byte
		sharedSecret[0] = 0xCC
		plain := ck[:]
		cipher, err := protocol.Encrypt(sharedSecret, epoch, plain)
		if err != nil {
			t.Fatal(err)
		}

		p := &protocol.ChatKey{Epoch: epoch, Ciphertext: cipher, Key: ck}
		*p.GetHeader() = *hdr(protocol.TypeChatKey, uint32(8+len(cipher)))
		raw := p.Marshal()

		// Verify epoch is plaintext at offset 64.
		gotEpoch := binary.BigEndian.Uint64(raw[64 : 64+8])
		if gotEpoch != epoch {
			t.Errorf("epoch not plaintext in wire: got %d want %d", gotEpoch, epoch)
		}

		got, err := protocol.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		ckpkt := got.(*protocol.ChatKey)
		if ckpkt.Epoch != epoch {
			t.Errorf("epoch mismatch: got %d want %d", ckpkt.Epoch, epoch)
		}

		// Decrypt with epoch as nonce.
		dec, err := protocol.Decrypt(sharedSecret, epoch, ckpkt.Ciphertext)
		if err != nil {
			t.Fatal("decrypt:", err)
		}
		if err := ckpkt.DecodePlaintext(dec); err != nil {
			t.Fatal(err)
		}
		if ckpkt.Key != ck {
			t.Error("chat key mismatch after round-trip")
		}
	})

	t.Run("Message", func(t *testing.T) {
		var msgUUID [16]byte
		msgUUID[0] = 0xFF
		cipher := []byte("encrypted-payload")
		p := &protocol.Message{MessageUUID: msgUUID, Nonce: 7, Ciphertext: cipher}
		*p.GetHeader() = *hdr(protocol.TypeMessage, uint32(16+8+len(cipher)))
		raw := p.Marshal()
		got, err := protocol.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		mp := got.(*protocol.Message)
		if mp.MessageUUID != msgUUID || mp.Nonce != 7 {
			t.Error("Message round-trip mismatch")
		}
	})

	t.Run("HSRA_endofstream", func(t *testing.T) {
		p := &protocol.HSRA{BatchNumber: 99, MessageCount: 0}
		*p.GetHeader() = *hdr(protocol.TypeHSRA, 16)
		raw := p.Marshal()
		got, err := protocol.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		hp := got.(*protocol.HSRA)
		if !hp.IsEndOfStream() {
			t.Error("expected IsEndOfStream")
		}
		if hp.BatchNumber != 99 {
			t.Errorf("batch_number: got %d want 99", hp.BatchNumber)
		}
	})

	t.Run("TimestampWindow", func(t *testing.T) {
		h := hdr(protocol.TypeHSIR, 0)
		h.Timestamp = uint64(time.Now().Add(-31 * time.Second).UnixMilli())
		if err := protocol.ValidateTimestamp(h); err == nil {
			t.Error("expected timestamp rejection for 31s old frame")
		}
		h.Timestamp = protocol.NowMillis()
		if err := protocol.ValidateTimestamp(h); err != nil {
			t.Errorf("unexpected timestamp rejection: %v", err)
		}
	})

	t.Run("MaxPayload", func(t *testing.T) {
		h := hdr(protocol.TypeMessage, protocol.MaxPayloadLength+1)
		raw := protocol.MarshalHeader(h)
		raw = append(raw, make([]byte, 64)...) // fake sig
		_, err := protocol.Parse(raw)
		if err == nil {
			t.Error("expected rejection of oversized payload")
		}
	})

	t.Run("UUIDBroadcast", func(t *testing.T) {
		h := hdr(protocol.TypeFIN, 0)
		h.ReceiverUUID = protocol.BroadcastUUID
		if !h.IsBroadcast() {
			t.Error("expected IsBroadcast == true")
		}
		h.ReceiverUUID = makeUUID(5)
		if h.IsBroadcast() {
			t.Error("expected IsBroadcast == false")
		}
	})

	_ = fmt.Sprintf // suppress import
}

func TestUUIDLess(t *testing.T) {
	a := makeUUID(1)
	b := makeUUID(2)
	if !protocol.UUIDLess(a, b) {
		t.Error("expected a < b")
	}
	if protocol.UUIDLess(b, a) {
		t.Error("expected !(b < a)")
	}
	if protocol.UUIDLess(a, a) {
		t.Error("expected !(a < a)")
	}
}
