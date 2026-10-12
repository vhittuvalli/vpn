package protocol

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Message types (first byte of every packet).
const (
	TypeInitiation = 1
	TypeResponse   = 2
	TypeData       = 3
)

// Message sizes.
//
//	initiation: type(1) reserved(3) sender(4) ephemeral(32) static(32+16) timestamp(12+16)
//	response:   type(1) reserved(3) sender(4) receiver(4) ephemeral(32) empty(0+16)
//	data:       type(1) reserved(3) receiver(4) counter(8) ciphertext(n+16)
const (
	InitiationSize = 116
	ResponseSize   = 60
	DataHeaderSize = 16
	TimestampSize  = 12
	tagSize        = chacha20poly1305.Overhead
)

var construction = []byte("vpn-from-scratch v1: X25519, ChaCha20-Poly1305, SHA-256")

var (
	ErrMalformed = errors.New("malformed message")
	ErrDecrypt   = errors.New("decryption failed")
)

// Timestamp is a big-endian (seconds, nanoseconds) pair. The server only
// accepts an initiation whose timestamp is newer than the last one it saw
// from that peer, so recorded initiations cannot be replayed.
type Timestamp [TimestampSize]byte

func NewTimestamp(t time.Time) Timestamp {
	var ts Timestamp
	binary.BigEndian.PutUint64(ts[:8], uint64(t.Unix()))
	binary.BigEndian.PutUint32(ts[8:], uint32(t.Nanosecond()))
	return ts
}

// After reports whether ts is strictly later than other.
func (ts Timestamp) After(other Timestamp) bool {
	for i := range ts {
		if ts[i] != other[i] {
			return ts[i] > other[i]
		}
	}
	return false
}

// The handshake keeps two running values, as in Noise:
//   - h, a hash of the transcript so far, used as AEAD associated data so
//     any tampering with earlier fields breaks later decryption;
//   - ck, a chaining key into which every Diffie-Hellman result is mixed.

func hash(parts ...[]byte) [32]byte {
	d := sha256.New()
	for _, p := range parts {
		d.Write(p)
	}
	var out [32]byte
	d.Sum(out[:0])
	return out
}

// kdf derives n 32-byte keys from the chaining key and new input.
func kdf(ck [32]byte, input []byte, n int) [][32]byte {
	b, err := hkdf.Key(sha256.New, input, ck[:], "", 32*n)
	if err != nil {
		panic(err)
	}
	out := make([][32]byte, n)
	for i := range out {
		copy(out[i][:], b[32*i:])
	}
	return out
}

// Each handshake key is used for exactly one message, so a zero nonce is safe.
var zeroNonce [chacha20poly1305.NonceSize]byte

func seal(key [32]byte, plaintext, ad []byte) []byte {
	a, _ := chacha20poly1305.New(key[:])
	return a.Seal(nil, zeroNonce[:], plaintext, ad)
}

func open(key [32]byte, ciphertext, ad []byte) ([]byte, error) {
	a, _ := chacha20poly1305.New(key[:])
	pt, err := a.Open(nil, zeroNonce[:], ciphertext, ad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

func initialState(responderPublic Key) (ck, h [32]byte) {
	ck = hash(construction)
	h = hash(ck[:], responderPublic[:])
	return ck, h
}

// InitiatorHandshake is the client's state between sending an initiation and
// receiving the response.
type InitiatorHandshake struct {
	LocalIndex uint32
	static     Key
	ephemeral  Key
	ck, h      [32]byte
}

// CreateInitiation builds the first handshake message. It proves the client
// holds `static` and encrypts the client's identity so only the server can
// read it.
func CreateInitiation(static, serverPublic Key, localIndex uint32, now time.Time) (*InitiatorHandshake, []byte, error) {
	e, err := GeneratePrivateKey()
	if err != nil {
		return nil, nil, err
	}
	ePub := e.Public()
	ck, h := initialState(serverPublic)
	h = hash(h[:], ePub[:])

	ss, err := dh(e, serverPublic)
	if err != nil {
		return nil, nil, err
	}
	k := kdf(ck, ss, 2)
	ck = k[0]
	sPub := static.Public()
	encStatic := seal(k[1], sPub[:], h[:])
	h = hash(h[:], encStatic)

	ss, err = dh(static, serverPublic)
	if err != nil {
		return nil, nil, err
	}
	k = kdf(ck, ss, 2)
	ck = k[0]
	ts := NewTimestamp(now)
	encTS := seal(k[1], ts[:], h[:])
	h = hash(h[:], encTS)

	msg := make([]byte, InitiationSize)
	msg[0] = TypeInitiation
	binary.LittleEndian.PutUint32(msg[4:8], localIndex)
	copy(msg[8:40], ePub[:])
	copy(msg[40:88], encStatic)
	copy(msg[88:116], encTS)

	return &InitiatorHandshake{LocalIndex: localIndex, static: static, ephemeral: e, ck: ck, h: h}, msg, nil
}

// ConsumeResponse verifies the server's response and returns the new session.
func (ih *InitiatorHandshake) ConsumeResponse(msg []byte) (*Session, error) {
	if len(msg) != ResponseSize || msg[0] != TypeResponse {
		return nil, ErrMalformed
	}
	if binary.LittleEndian.Uint32(msg[8:12]) != ih.LocalIndex {
		return nil, ErrMalformed
	}
	remoteIndex := binary.LittleEndian.Uint32(msg[4:8])
	var ePub Key
	copy(ePub[:], msg[12:44])

	h := hash(ih.h[:], ePub[:])
	ss, err := dh(ih.ephemeral, ePub)
	if err != nil {
		return nil, err
	}
	ck := kdf(ih.ck, ss, 1)[0]
	ss, err = dh(ih.static, ePub)
	if err != nil {
		return nil, err
	}
	ck = kdf(ck, ss, 1)[0]
	k := kdf(ck, nil, 2)
	ck = k[0]
	if _, err := open(k[1], msg[44:60], h[:]); err != nil {
		return nil, err
	}

	t := kdf(ck, nil, 2)
	return newSession(ih.LocalIndex, remoteIndex, t[0], t[1]), nil
}

// ReceivedInitiation is a verified initiation, held by the server while it
// decides whether to answer.
type ReceivedInitiation struct {
	PeerStatic    Key
	Timestamp     Timestamp
	remoteIndex   uint32
	peerEphemeral Key
	ck, h         [32]byte
}

// ConsumeInitiation decrypts and authenticates a client's initiation. The
// caller must still check that PeerStatic is an allowed peer and that
// Timestamp is newer than the last one seen from it.
func ConsumeInitiation(static Key, msg []byte) (*ReceivedInitiation, error) {
	if len(msg) != InitiationSize || msg[0] != TypeInitiation {
		return nil, ErrMalformed
	}
	r := &ReceivedInitiation{remoteIndex: binary.LittleEndian.Uint32(msg[4:8])}
	copy(r.peerEphemeral[:], msg[8:40])

	ck, h := initialState(static.Public())
	h = hash(h[:], r.peerEphemeral[:])

	ss, err := dh(static, r.peerEphemeral)
	if err != nil {
		return nil, err
	}
	k := kdf(ck, ss, 2)
	ck = k[0]
	sPub, err := open(k[1], msg[40:88], h[:])
	if err != nil {
		return nil, err
	}
	copy(r.PeerStatic[:], sPub)
	h = hash(h[:], msg[40:88])

	ss, err = dh(static, r.PeerStatic)
	if err != nil {
		return nil, err
	}
	k = kdf(ck, ss, 2)
	ck = k[0]
	ts, err := open(k[1], msg[88:116], h[:])
	if err != nil {
		return nil, err
	}
	copy(r.Timestamp[:], ts)
	h = hash(h[:], msg[88:116])

	r.ck, r.h = ck, h
	return r, nil
}

// CreateResponse completes the handshake on the server side. Fresh ephemeral
// keys on both sides give forward secrecy: stealing a static key later does
// not decrypt recorded traffic.
func (r *ReceivedInitiation) CreateResponse(localIndex uint32) (*Session, []byte, error) {
	e, err := GeneratePrivateKey()
	if err != nil {
		return nil, nil, err
	}
	ePub := e.Public()
	h := hash(r.h[:], ePub[:])

	ss, err := dh(e, r.peerEphemeral)
	if err != nil {
		return nil, nil, err
	}
	ck := kdf(r.ck, ss, 1)[0]
	ss, err = dh(e, r.PeerStatic)
	if err != nil {
		return nil, nil, err
	}
	ck = kdf(ck, ss, 1)[0]
	k := kdf(ck, nil, 2)
	ck = k[0]
	encEmpty := seal(k[1], nil, h[:])

	msg := make([]byte, ResponseSize)
	msg[0] = TypeResponse
	binary.LittleEndian.PutUint32(msg[4:8], localIndex)
	binary.LittleEndian.PutUint32(msg[8:12], r.remoteIndex)
	copy(msg[12:44], ePub[:])
	copy(msg[44:60], encEmpty)

	t := kdf(ck, nil, 2)
	return newSession(localIndex, r.remoteIndex, t[1], t[0]), msg, nil
}

// ReceiverIndex returns the index a response or data message is addressed to.
func ReceiverIndex(msg []byte) (uint32, bool) {
	switch {
	case len(msg) == ResponseSize && msg[0] == TypeResponse:
		return binary.LittleEndian.Uint32(msg[8:12]), true
	case len(msg) >= DataHeaderSize+tagSize && msg[0] == TypeData:
		return binary.LittleEndian.Uint32(msg[4:8]), true
	}
	return 0, false
}
