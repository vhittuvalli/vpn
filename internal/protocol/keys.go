// Package protocol implements the VPN's wire protocol: X25519 keys, a
// two-message handshake modeled on Noise IK, and encrypted data sessions.
package protocol

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// Key is a 32-byte X25519 private or public key.
type Key [32]byte

// GeneratePrivateKey returns a new random private key.
func GeneratePrivateKey() (Key, error) {
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Key{}, err
	}
	var k Key
	copy(k[:], sk.Bytes())
	return k, nil
}

// Public returns the public key for private key k.
func (k Key) Public() Key {
	sk, err := ecdh.X25519().NewPrivateKey(k[:])
	if err != nil {
		panic(err) // X25519 accepts any 32 bytes.
	}
	var pub Key
	copy(pub[:], sk.PublicKey().Bytes())
	return pub
}

func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

func (k Key) IsZero() bool { return k == Key{} }

// ParseKey decodes a base64 key as printed by Key.String.
func ParseKey(s string) (Key, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Key{}, fmt.Errorf("invalid key: %w", err)
	}
	if len(b) != len(Key{}) {
		return Key{}, fmt.Errorf("invalid key: got %d bytes, want 32", len(b))
	}
	var k Key
	copy(k[:], b)
	return k, nil
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
