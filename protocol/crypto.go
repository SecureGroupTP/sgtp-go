// Package protocol/crypto collects all SGTP cryptographic primitives into one
// place so no other layer needs to import x/crypto directly.
package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

// ─── Key generation ──────────────────────────────────────────────────────────

// GenerateEd25519 creates a new long-term ed25519 identity key pair.
func GenerateEd25519() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func LoadEd25519FromFileRaw(filename string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("github.com/SecureGroupTP/sgtp-go/client: read key file: %w", err)
	}

	// Попытка распарсить как PEM (RFC 8410)
	if block, _ := pem.Decode(data); block != nil {
		switch block.Type {
		case "ED25519 PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("github.com/SecureGroupTP/sgtp-go/client: parse PKCS#8: %w", err)
			}
			priv, ok := key.(ed25519.PrivateKey)
			if !ok {
				return nil, nil, fmt.Errorf("github.com/SecureGroupTP/sgtp-go/client: key is not ed25519")
			}
			return priv.Public().(ed25519.PublicKey), priv, nil

		case "PRIVATE KEY": // untyped PKCS#8
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("github.com/SecureGroupTP/sgtp-go/client: parse PKCS#8: %w", err)
			}
			priv, ok := key.(ed25519.PrivateKey)
			if !ok {
				return nil, nil, fmt.Errorf("github.com/SecureGroupTP/sgtp-go/client: key is not ed25519")
			}
			return priv.Public().(ed25519.PublicKey), priv, nil
		}
	}

	// Fallback: сырые байты
	switch len(data) {
	case ed25519.PrivateKeySize: // 64 байта: приватный + публичный
		priv := ed25519.PrivateKey(data)
		return priv.Public().(ed25519.PublicKey), priv, nil

	case ed25519.SeedSize: // 32 байта: только сид, выведем пару
		seed := make([]byte, ed25519.SeedSize)
		copy(seed, data)
		priv := ed25519.NewKeyFromSeed(seed)
		return priv.Public().(ed25519.PublicKey), priv, nil

	default:
		return nil, nil, fmt.Errorf(
			"github.com/SecureGroupTP/sgtp-go/client: invalid key size %d; expected %d (seed) or %d (full private)",
			len(data), ed25519.SeedSize, ed25519.PrivateKeySize,
		)
	}
}

func LoadEd25519FromOpenSSHFile(filename string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("read file: %w", err)
	}

	// 1. Пробуем как приватный ключ через ParseRawPrivateKey
	rawKey, err := ssh.ParseRawPrivateKey(data)
	if err == nil {
		var edPriv ed25519.PrivateKey

		switch v := rawKey.(type) {
		case ed25519.PrivateKey:
			edPriv = v
		case *ed25519.PrivateKey:
			edPriv = *v
		default:
			return nil, nil, fmt.Errorf("key is not Ed25519, got %T", rawKey)
		}

		edPub := edPriv.Public().(ed25519.PublicKey)
		return edPub, edPriv, nil
	}

	// 2. Пробуем как публичный ключ в формате authorized_keys
	sshPub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err == nil && sshPub.Type() == ssh.KeyAlgoED25519 {
		cryptoPub := sshPub.(ssh.CryptoPublicKey).CryptoPublicKey()
		edPub, ok := cryptoPub.(ed25519.PublicKey)
		if !ok {
			return nil, nil, fmt.Errorf("failed to convert to ed25519.PublicKey")
		}
		return edPub, nil, nil
	}

	return nil, nil, fmt.Errorf("unrecognized Ed25519 key format: %w", err)
}

// GenerateX25519 creates a new ephemeral x25519 key pair.
// Returns (publicKey[32], privateKey[32], error).
func GenerateX25519() ([32]byte, [32]byte, error) {
	var priv, pub [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return pub, priv, fmt.Errorf("github.com/SecureGroupTP/sgtp-go/crypto: x25519 key gen: %w", err)
	}
	// clamp per RFC 7748
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pubSlice, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return pub, priv, fmt.Errorf("github.com/SecureGroupTP/sgtp-go/crypto: x25519 public key: %w", err)
	}
	copy(pub[:], pubSlice)
	return pub, priv, nil
}

// X25519SharedSecret computes the Diffie-Hellman shared secret.
func X25519SharedSecret(privKey, peerPubKey [32]byte) ([32]byte, error) {
	var shared [32]byte
	out, err := curve25519.X25519(privKey[:], peerPubKey[:])
	if err != nil {
		return shared, fmt.Errorf("github.com/SecureGroupTP/sgtp-go/crypto: x25519 DH: %w", err)
	}
	copy(shared[:], out)
	return shared, nil
}

// ─── Signing / verification ───────────────────────────────────────────────────

// Sign produces a 64-byte ed25519 signature over msg.
// msg should be the full frame bytes EXCLUDING the trailing 64-byte signature.
func Sign(priv ed25519.PrivateKey, msg []byte) [SignatureSize]byte {
	var sig [SignatureSize]byte
	copy(sig[:], ed25519.Sign(priv, msg))
	return sig
}

// Verify checks an ed25519 signature.
// frameWithoutSig must be the frame bytes without the trailing 64-byte signature.
func Verify(pub ed25519.PublicKey, frameWithoutSig, sig []byte) bool {
	return ed25519.Verify(pub, frameWithoutSig, sig)
}

// ─── Symmetric encryption (ChaCha20-Poly1305) ────────────────────────────────

// chachaKeyFromShared derives a 32-byte ChaCha20-Poly1305 key from a raw
// x25519 shared secret by using it directly (the shared secret is already
// 32 random-looking bytes).
func chachaKeyFromShared(shared [32]byte) []byte {
	k := make([]byte, 32)
	copy(k, shared[:])
	return k
}

// nonceFromCounter converts a uint64 monotonic counter into the 12-byte nonce
// required by ChaCha20-Poly1305.  The counter occupies the last 8 bytes;
// the first 4 bytes are zero.
func nonceFromCounter(counter uint64) []byte {
	n := make([]byte, chacha20poly1305.NonceSize) // 12 bytes
	binary.BigEndian.PutUint64(n[4:], counter)
	return n
}

// Encrypt encrypts plaintext using ChaCha20-Poly1305 with the given key and
// nonce counter.  Returns the ciphertext (with 16-byte auth tag appended).
func Encrypt(key [32]byte, nonceCounter uint64, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(chachaKeyFromShared(key))
	if err != nil {
		return nil, fmt.Errorf("github.com/SecureGroupTP/sgtp-go/crypto: chacha20 init: %w", err)
	}
	nonce := nonceFromCounter(nonceCounter)
	return aead.Seal(nil, nonce, plaintext, nil), nil
}

// Decrypt decrypts ciphertext using ChaCha20-Poly1305.
func Decrypt(key [32]byte, nonceCounter uint64, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(chachaKeyFromShared(key))
	if err != nil {
		return nil, fmt.Errorf("github.com/SecureGroupTP/sgtp-go/crypto: chacha20 init: %w", err)
	}
	nonce := nonceFromCounter(nonceCounter)
	plain, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("github.com/SecureGroupTP/sgtp-go/crypto: decrypt: %w", err)
	}
	return plain, nil
}

// NewChatKey generates a cryptographically random 32-byte Chat Key.
func NewChatKey() ([32]byte, error) {
	var ck [32]byte
	if _, err := rand.Read(ck[:]); err != nil {
		return ck, fmt.Errorf("github.com/SecureGroupTP/sgtp-go/crypto: chat key gen: %w", err)
	}
	return ck, nil
}
