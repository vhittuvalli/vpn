// Package protocol implements the VPN's wire protocol: hybrid post-quantum
// identities, a two-message handshake modeled on Noise IK, DoS cookies,
// handshake fragmentation, and encrypted data sessions.
package protocol

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Key is a 32-byte X25519 private or public key.
type Key [32]byte

// generateX25519 returns a new random X25519 private key.
func generateX25519() (Key, error) {
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Key{}, err
	}
	var k Key
	copy(k[:], sk.Bytes())
	return k, nil
}

// Public returns the X25519 public key for private key k.
func (k Key) Public() Key {
	sk, err := ecdh.X25519().NewPrivateKey(k[:])
	if err != nil {
		panic(err) // X25519 accepts any 32 bytes.
	}
	var pub Key
	copy(pub[:], sk.PublicKey().Bytes())
	return pub
}

// dh computes the X25519 shared secret. It fails if the peer's public key is
// a low-order point, which would make the shared secret all zeros.
func dh(priv, pub Key) ([]byte, error) {
	sk, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		return nil, err
	}
	pk, err := ecdh.X25519().NewPublicKey(pub[:])
	if err != nil {
		return nil, err
	}
	return sk.ECDH(pk)
}

// A peer's identity is two key pairs: X25519 for the Noise key exchange and
// ML-DSA-44 (FIPS 204) for post-quantum signatures. Both are derived from one
// 32-byte secret, so a private key is still a single short string.
//
// The public key is the X25519 public key followed by a SHA-256 hash of the
// ML-DSA public key. The full 1,312-byte ML-DSA key travels (encrypted) in the
// handshake and is checked against the hash, which keeps configs short.

const (
	dsaPublicKeySize = mldsa.MLDSA44PublicKeySize // 1312
	dsaSignatureSize = mldsa.MLDSA44SignatureSize // 2420
)

// PrivateKey is the 32-byte secret seed of an identity.
type PrivateKey [32]byte

// PublicKey is an X25519 public key followed by SHA-256(ML-DSA public key).
type PublicKey [64]byte

// GeneratePrivateKey returns a new random identity seed.
func GeneratePrivateKey() (PrivateKey, error) {
	var k PrivateKey
	_, err := rand.Read(k[:])
	return k, err
}

func (k PrivateKey) String() string { return base64.StdEncoding.EncodeToString(k[:]) }
func (k PublicKey) String() string  { return base64.StdEncoding.EncodeToString(k[:]) }

// Public returns the public key for k.
func (k PrivateKey) Public() PublicKey { return NewIdentity(k).Public }

func (k PublicKey) x25519() Key {
	var x Key
	copy(x[:], k[:32])
	return x
}

// matchesDSA reports whether dsaPub is the ML-DSA key this public key commits to.
func (k PublicKey) matchesDSA(dsaPub []byte) bool {
	h := sha256.Sum256(dsaPub)
	return bytes.Equal(h[:], k[32:])
}

func ParsePrivateKey(s string) (PrivateKey, error) {
	var k PrivateKey
	return k, parseBase64(s, k[:])
}

func ParsePublicKey(s string) (PublicKey, error) {
	var k PublicKey
	return k, parseBase64(s, k[:])
}

func parseBase64(s string, out []byte) error {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("invalid key: %w", err)
	}
	if len(b) != len(out) {
		return fmt.Errorf("invalid key: got %d bytes, want %d", len(b), len(out))
	}
	copy(out, b)
	return nil
}

// Identity holds the expanded key material for a PrivateKey.
type Identity struct {
	Public PublicKey
	x25519 Key
	dsa    *mldsa.PrivateKey
	dsaPub []byte
}

func NewIdentity(k PrivateKey) *Identity {
	derive := func(label string) []byte {
		b, err := hkdf.Key(sha256.New, k[:], nil, label, 32)
		if err != nil {
			panic(err)
		}
		return b
	}
	id := &Identity{}
	copy(id.x25519[:], derive("vpn-from-scratch x25519"))
	dsa, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), derive("vpn-from-scratch ml-dsa-44"))
	if err != nil {
		panic(err) // any 32-byte seed is valid
	}
	id.dsa = dsa
	id.dsaPub = dsa.PublicKey().Bytes()

	xPub := id.x25519.Public()
	dsaHash := sha256.Sum256(id.dsaPub)
	copy(id.Public[:32], xPub[:])
	copy(id.Public[32:], dsaHash[:])
	return id
}

func (id *Identity) sign(context string, msg []byte) ([]byte, error) {
	return id.dsa.Sign(nil, msg, &mldsa.Options{Context: context})
}

func verify(dsaPub []byte, context string, msg, sig []byte) error {
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA44(), dsaPub)
	if err != nil {
		return err
	}
	return mldsa.Verify(pk, msg, sig, &mldsa.Options{Context: context})
}

// Hash is SHA-256 over the concatenation of parts.
func Hash(parts ...[]byte) [32]byte { return hash(parts...) }
