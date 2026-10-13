package protocol

import (
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Message types (first byte of every packet).
const (
	TypeInitiation  = 1
	TypeResponse    = 2
	TypeData        = 3
	TypeCookieReply = 4
	TypeFragment    = 5
)

const (
	tagSize       = chacha20poly1305.Overhead
	TimestampSize = 12
	kemKeySize    = mlkem.EncapsulationKeySize768 // 1184
	kemCTSize     = mlkem.CiphertextSize768       // 1088
	macSize       = 16
)

// Message layouts. Each encrypted field is followed by a 16-byte tag.
//
//	initiation: type(1) reserved(3) sender(4) ephemeral(32) kem-key(1184)
//	            enc{x25519-static(32) ml-dsa-key(1312)} enc{timestamp(12) signature(2420)}
//	            mac1(16) mac2(16)
//	response:   type(1) reserved(3) sender(4) receiver(4) ephemeral(32) kem-ciphertext(1088)
//	            enc{ml-dsa-key(1312) signature(2420)} mac1(16) mac2(16)
//	data:       type(1) reserved(3) receiver(4) counter(8) ciphertext(n+16)
//
// Handshake messages are larger than one packet, so they are sent as
// fragments (see fragment.go). The response is smaller than the
// initiation, so the server can't be used to amplify a flood.
const (
	initEph        = 8
	initKEM        = initEph + 32
	initStatic     = initKEM + kemKeySize
	initPayload    = initStatic + 32 + dsaPublicKeySize + tagSize
	initMACs       = initPayload + TimestampSize + dsaSignatureSize + tagSize
	InitiationSize = initMACs + 2*macSize // 5064

	respEph      = 12
	respKEM      = respEph + 32
	respPayload  = respKEM + kemCTSize
	respMACs     = respPayload + dsaPublicKeySize + dsaSignatureSize + tagSize
	ResponseSize = respMACs + 2*macSize // 4912

	DataHeaderSize = 16
)

var construction = []byte("vpn-from-scratch v3: X25519+ML-KEM-768, ML-DSA-44, ChaCha20-Poly1305, SHA-256")

const (
	initSigContext = "vpn-from-scratch v3 initiation"
	respSigContext = "vpn-from-scratch v3 response"
)

var (
	ErrMalformed   = errors.New("malformed message")
	ErrDecrypt     = errors.New("decryption failed")
	ErrUnknownPeer = errors.New("unknown peer")
	ErrSignature   = errors.New("bad signature")
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

// The handshake is post-quantum in two ways:
//
//   - Confidentiality: alongside the X25519 exchanges, the client sends a
//     fresh ML-KEM-768 public key and the server encapsulates a secret to it.
//     That secret is mixed into the session keys, so recorded traffic stays
//     private unless an attacker breaks BOTH X25519 and ML-KEM ("harvest now,
//     decrypt later" protection).
//   - Authentication: each side signs the handshake transcript with its
//     ML-DSA-44 key, so even an attacker who can break X25519 cannot
//     impersonate a client or the server.
//
// The handshake keeps two running values, as in Noise:
//   - h, a hash of the transcript so far, used as AEAD associated data and as
//     the signed message, so tampering with any earlier field is detected;
//   - ck, a chaining key into which every shared secret is mixed.

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

func initialState(responder PublicKey) (ck, h [32]byte) {
	ck = hash(construction)
	h = hash(ck[:], responder[:])
	return ck, h
}

// InitiatorHandshake is the client's state between sending an initiation and
// receiving the response.
type InitiatorHandshake struct {
	LocalIndex uint32
	Message    []byte // the initiation, kept so it can be resent with a cookie
	id         *Identity
	server     PublicKey
	ephemeral  Key
	kem        *mlkem.DecapsulationKey768
	ck, h      [32]byte
}

// CreateInitiation builds the first handshake message. The client's identity
// is encrypted so only the server can read it. The caller must still add
// MACs with AddMACs before sending.
func CreateInitiation(id *Identity, server PublicKey, localIndex uint32, now time.Time) (*InitiatorHandshake, error) {
	e, err := generateX25519()
	if err != nil {
		return nil, err
	}
	ePub := e.Public()
	kem, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	kemKey := kem.EncapsulationKey().Bytes()
	ck, h := initialState(server)
	h = hash(h[:], ePub[:], kemKey)

	ss, err := dh(e, server.x25519())
	if err != nil {
		return nil, err
	}
	k := kdf(ck, ss, 2)
	ck = k[0]
	xPub := id.x25519.Public()
	encStatic := seal(k[1], append(xPub[:], id.dsaPub...), h[:])
	h = hash(h[:], encStatic)

	ss, err = dh(id.x25519, server.x25519())
	if err != nil {
		return nil, err
	}
	k = kdf(ck, ss, 2)
	ck = k[0]
	sig, err := id.sign(initSigContext, h[:])
	if err != nil {
		return nil, err
	}
	ts := NewTimestamp(now)
	encPayload := seal(k[1], append(ts[:], sig...), h[:])
	h = hash(h[:], encPayload)

	msg := make([]byte, InitiationSize)
	msg[0] = TypeInitiation
	binary.LittleEndian.PutUint32(msg[4:8], localIndex)
	copy(msg[initEph:], ePub[:])
	copy(msg[initKEM:], kemKey)
	copy(msg[initStatic:], encStatic)
	copy(msg[initPayload:], encPayload)

	return &InitiatorHandshake{
		LocalIndex: localIndex, Message: msg,
		id: id, server: server, ephemeral: e, kem: kem, ck: ck, h: h,
	}, nil
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
	copy(ePub[:], msg[respEph:respKEM])
	kemCT := msg[respKEM:respPayload]

	h := hash(ih.h[:], ePub[:], kemCT)
	ss, err := dh(ih.ephemeral, ePub)
	if err != nil {
		return nil, err
	}
	ck := kdf(ih.ck, ss, 1)[0]
	ss, err = dh(ih.id.x25519, ePub)
	if err != nil {
		return nil, err
	}
	ck = kdf(ck, ss, 1)[0]
	pq, err := ih.kem.Decapsulate(kemCT)
	if err != nil {
		return nil, ErrMalformed
	}
	ck = kdf(ck, pq, 1)[0]
	k := kdf(ck, nil, 2)
	ck = k[0]
	payload, err := open(k[1], msg[respPayload:respMACs], h[:])
	if err != nil {
		return nil, err
	}
	dsaPub, sig := payload[:dsaPublicKeySize], payload[dsaPublicKeySize:]
	if !ih.server.matchesDSA(dsaPub) {
		return nil, ErrSignature
	}
	if err := verify(dsaPub, respSigContext, h[:], sig); err != nil {
		return nil, ErrSignature
	}

	t := kdf(ck, nil, 2)
	return newSession(ih.LocalIndex, remoteIndex, t[0], t[1]), nil
}

// ReceivedInitiation is a verified initiation, held by the server while it
// decides whether to answer.
type ReceivedInitiation struct {
	Peer          PublicKey
	Timestamp     Timestamp
	remoteIndex   uint32
	peerEphemeral Key
	peerX25519    Key
	peerKEM       *mlkem.EncapsulationKey768
	ck, h         [32]byte
}

// ConsumeInitiation decrypts and authenticates a client's initiation.
// allowed is called with the client's public key before the (comparatively
// expensive) signature check. The caller must still check that Timestamp is
// newer than the last one seen from that peer.
func ConsumeInitiation(id *Identity, msg []byte, allowed func(PublicKey) bool) (*ReceivedInitiation, error) {
	if len(msg) != InitiationSize || msg[0] != TypeInitiation {
		return nil, ErrMalformed
	}
	r := &ReceivedInitiation{remoteIndex: binary.LittleEndian.Uint32(msg[4:8])}
	copy(r.peerEphemeral[:], msg[initEph:initKEM])
	kemKey := msg[initKEM:initStatic]
	var err error
	if r.peerKEM, err = mlkem.NewEncapsulationKey768(kemKey); err != nil {
		return nil, ErrMalformed
	}

	ck, h := initialState(id.Public)
	h = hash(h[:], r.peerEphemeral[:], kemKey)

	ss, err := dh(id.x25519, r.peerEphemeral)
	if err != nil {
		return nil, err
	}
	k := kdf(ck, ss, 2)
	ck = k[0]
	static, err := open(k[1], msg[initStatic:initPayload], h[:])
	if err != nil {
		return nil, err
	}
	copy(r.peerX25519[:], static[:32])
	dsaPub := static[32:]
	dsaHash := sha256.Sum256(dsaPub)
	copy(r.Peer[:32], static[:32])
	copy(r.Peer[32:], dsaHash[:])
	h = hash(h[:], msg[initStatic:initPayload])
	if !allowed(r.Peer) {
		return nil, ErrUnknownPeer
	}

	ss, err = dh(id.x25519, r.peerX25519)
	if err != nil {
		return nil, err
	}
	k = kdf(ck, ss, 2)
	ck = k[0]
	payload, err := open(k[1], msg[initPayload:initMACs], h[:])
	if err != nil {
		return nil, err
	}
	if err := verify(dsaPub, initSigContext, h[:], payload[TimestampSize:]); err != nil {
		return nil, ErrSignature
	}
	copy(r.Timestamp[:], payload[:TimestampSize])
	h = hash(h[:], msg[initPayload:initMACs])

	r.ck, r.h = ck, h
	return r, nil
}

// CreateResponse completes the handshake on the server side. Fresh ephemeral
// keys on both sides give forward secrecy: stealing a long-term key later
// does not decrypt recorded traffic. The caller must add MACs before sending.
func (r *ReceivedInitiation) CreateResponse(id *Identity, localIndex uint32) (*Session, []byte, error) {
	e, err := generateX25519()
	if err != nil {
		return nil, nil, err
	}
	ePub := e.Public()
	pq, kemCT := r.peerKEM.Encapsulate()
	h := hash(r.h[:], ePub[:], kemCT)

	ss, err := dh(e, r.peerEphemeral)
	if err != nil {
		return nil, nil, err
	}
	ck := kdf(r.ck, ss, 1)[0]
	ss, err = dh(e, r.peerX25519)
	if err != nil {
		return nil, nil, err
	}
	ck = kdf(ck, ss, 1)[0]
	ck = kdf(ck, pq, 1)[0]
	k := kdf(ck, nil, 2)
	ck = k[0]
	sig, err := id.sign(respSigContext, h[:])
	if err != nil {
		return nil, nil, err
	}
	encPayload := seal(k[1], append(append([]byte{}, id.dsaPub...), sig...), h[:])

	msg := make([]byte, ResponseSize)
	msg[0] = TypeResponse
	binary.LittleEndian.PutUint32(msg[4:8], localIndex)
	binary.LittleEndian.PutUint32(msg[8:12], r.remoteIndex)
	copy(msg[respEph:], ePub[:])
	copy(msg[respKEM:], kemCT)
	copy(msg[respPayload:], encPayload)

	t := kdf(ck, nil, 2)
	return newSession(localIndex, r.remoteIndex, t[1], t[0]), msg, nil
}

// ReceiverIndex returns the index a response, cookie reply or data message
// is addressed to.
func ReceiverIndex(msg []byte) (uint32, bool) {
	switch {
	case len(msg) == ResponseSize && msg[0] == TypeResponse:
		return binary.LittleEndian.Uint32(msg[8:12]), true
	case len(msg) == CookieReplySize && msg[0] == TypeCookieReply:
		return binary.LittleEndian.Uint32(msg[4:8]), true
	case len(msg) >= DataHeaderSize+tagSize && msg[0] == TypeData:
		return binary.LittleEndian.Uint32(msg[4:8]), true
	}
	return 0, false
}
