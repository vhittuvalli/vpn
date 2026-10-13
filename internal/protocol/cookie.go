package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Handshakes are expensive (ML-KEM, ML-DSA, three X25519 operations), so the
// server guards them with two MACs, following WireGuard:
//
//   - mac1 is keyed by the server's public key. Checking it costs one HMAC,
//     and it proves the sender knows the public key, so random internet
//     scanners never trigger the expensive work.
//   - mac2 is keyed by a "cookie" the server hands out only when it is under
//     load. The cookie is a MAC of the client's address under a secret that
//     changes every two minutes, so getting one proves the client really
//     receives traffic at that address. Floods from spoofed addresses then
//     can't get through, and real addresses can be rate-limited.

const (
	CookieReplySize = 8 + chacha20poly1305.NonceSizeX + macSize + tagSize // 64
	cookieLifetime  = 2 * time.Minute
)

var ErrCookie = errors.New("invalid cookie reply")

func mac(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)[:macSize]
}

func mac1Key(receiver PublicKey) []byte {
	k := hash([]byte("mac1----"), receiver[:])
	return k[:]
}

func cookieKey(receiver PublicKey) []byte {
	k := hash([]byte("cookie--"), receiver[:])
	return k[:]
}

// AddMACs fills in a handshake message's mac1 (keyed by the receiver's public
// key) and, if cookie is non-nil, mac2.
func AddMACs(msg []byte, receiver PublicKey, cookie []byte) {
	n := len(msg)
	copy(msg[n-2*macSize:], mac(mac1Key(receiver), msg[:n-2*macSize]))
	if cookie == nil {
		clear(msg[n-macSize:])
		return
	}
	copy(msg[n-macSize:], mac(cookie, msg[:n-macSize]))
}

// CheckMAC1 reports whether msg's mac1 is valid for receiver.
func CheckMAC1(msg []byte, receiver PublicKey) bool {
	n := len(msg)
	if n < 2*macSize {
		return false
	}
	return hmac.Equal(msg[n-2*macSize:n-macSize], mac(mac1Key(receiver), msg[:n-2*macSize]))
}

// CookieChecker is the server's side of the cookie mechanism.
type CookieChecker struct {
	self PublicKey

	mu         sync.Mutex
	secret     [32]byte
	secretTime time.Time
}

func NewCookieChecker(self PublicKey) *CookieChecker {
	return &CookieChecker{self: self}
}

func (c *CookieChecker) CheckMAC1(msg []byte) bool { return CheckMAC1(msg, c.self) }

// cookie returns the cookie for a source address, rotating the secret when
// it gets old.
func (c *CookieChecker) cookie(source string) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.secretTime) > cookieLifetime {
		rand.Read(c.secret[:])
		c.secretTime = time.Now()
	}
	return mac(c.secret[:], []byte(source))
}

// CheckMAC2 reports whether msg carries a valid cookie MAC for source.
func (c *CookieChecker) CheckMAC2(msg []byte, source string) bool {
	n := len(msg)
	if n < 2*macSize {
		return false
	}
	return hmac.Equal(msg[n-macSize:], mac(c.cookie(source), msg[:n-macSize]))
}

// CreateReply builds a cookie reply for the handshake message msg. The cookie
// is encrypted under a key derived from the server's public key, with msg's
// mac1 as associated data, so only the real sender can use it.
func (c *CookieChecker) CreateReply(msg []byte, source string) ([]byte, error) {
	if len(msg) < 8+2*macSize {
		return nil, ErrMalformed
	}
	aead, _ := chacha20poly1305.NewX(cookieKey(c.self))
	reply := make([]byte, 8+chacha20poly1305.NonceSizeX, CookieReplySize)
	reply[0] = TypeCookieReply
	copy(reply[4:8], msg[4:8]) // the sender index of the handshake message
	nonce := reply[8:]
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	n := len(msg)
	return aead.Seal(reply, nonce, c.cookie(source), msg[n-2*macSize:n-macSize]), nil
}

// ConsumeCookieReply decrypts a cookie reply to the handshake message sent,
// which was addressed to server.
func ConsumeCookieReply(reply, sent []byte, server PublicKey) ([]byte, error) {
	if len(reply) != CookieReplySize || reply[0] != TypeCookieReply || len(sent) < 8+2*macSize {
		return nil, ErrCookie
	}
	if binary.LittleEndian.Uint32(reply[4:8]) != binary.LittleEndian.Uint32(sent[4:8]) {
		return nil, ErrCookie
	}
	aead, _ := chacha20poly1305.NewX(cookieKey(server))
	n := len(sent)
	nonce := reply[8 : 8+chacha20poly1305.NonceSizeX]
	cookie, err := aead.Open(nil, nonce, reply[8+chacha20poly1305.NonceSizeX:], sent[n-2*macSize:n-macSize])
	if err != nil {
		return nil, ErrCookie
	}
	return cookie, nil
}

// CookieLifetime is how long a client may keep using a cookie. It is a bit
// shorter than the server's secret rotation so cookies don't go stale in use.
const CookieLifetime = cookieLifetime - 10*time.Second
