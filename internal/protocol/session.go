package protocol

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Timers, following WireGuard's choices.
const (
	RekeyAfterTime    = 2 * time.Minute // client starts a new handshake
	RejectAfterTime   = 3 * time.Minute // session is no longer used at all
	KeepaliveInterval = 15 * time.Second
	HandshakeRetry    = 5 * time.Second

	rejectAfterMessages = 1 << 60
)

var (
	ErrReplay  = errors.New("replayed or too-old packet")
	ErrExpired = errors.New("session expired")
)

// Session holds the keys for one direction-pair of encrypted traffic.
type Session struct {
	LocalIndex  uint32 // peers address packets to us by this index
	RemoteIndex uint32 // we address packets to the peer by this index
	Created     time.Time

	send, recv  cipher.AEAD
	sendCounter atomic.Uint64
	replay      replayWindow
}

func newSession(localIndex, remoteIndex uint32, sendKey, recvKey [32]byte) *Session {
	send, _ := chacha20poly1305.New(sendKey[:])
	recv, _ := chacha20poly1305.New(recvKey[:])
	return &Session{
		LocalIndex:  localIndex,
		RemoteIndex: remoteIndex,
		Created:     time.Now(),
		send:        send,
		recv:        recv,
	}
}

func (s *Session) Expired() bool { return time.Since(s.Created) > RejectAfterTime }

// Seal encrypts an IP packet (or nil for a keepalive) into a data message.
// The counter doubles as the nonce, so a nonce is never reused under a key.
func (s *Session) Seal(packet []byte) ([]byte, error) {
	if s.Expired() {
		return nil, ErrExpired
	}
	n := s.sendCounter.Add(1) - 1
	if n >= rejectAfterMessages {
		return nil, ErrExpired
	}
	var header [DataHeaderSize]byte
	header[0] = TypeData
	binary.LittleEndian.PutUint32(header[4:8], s.RemoteIndex)
	binary.LittleEndian.PutUint64(header[8:16], n)

	out := make([]byte, DataHeaderSize, DataHeaderSize+len(packet)+tagSize)
	copy(out, header[:])
	return s.send.Seal(out, nonce(n), packet, header[:]), nil
}

// Open authenticates and decrypts a data message, rejecting replays.
func (s *Session) Open(msg []byte) ([]byte, error) {
	if len(msg) < DataHeaderSize+tagSize || msg[0] != TypeData {
		return nil, ErrMalformed
	}
	if s.Expired() {
		return nil, ErrExpired
	}
	n := binary.LittleEndian.Uint64(msg[8:16])
	if n >= rejectAfterMessages || !s.replay.check(n, false) {
		return nil, ErrReplay
	}
	pt, err := s.recv.Open(nil, nonce(n), msg[DataHeaderSize:], msg[:DataHeaderSize])
	if err != nil {
		return nil, ErrDecrypt
	}
	// Only mark the counter as seen once the packet proved authentic, so
	// forged packets cannot push the window forward.
	if !s.replay.check(n, true) {
		return nil, ErrReplay
	}
	return pt, nil
}

func nonce(n uint64) []byte {
	var b [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(b[4:], n)
	return b[:]
}

// replayWindow tracks which of the most recent windowSize counters have been
// seen. UDP can reorder packets, so anything inside the window is accepted
// once; anything older is dropped.
const windowSize = 2048

type replayWindow struct {
	mu      sync.Mutex
	started bool
	highest uint64
	bits    [windowSize / 64]uint64
}

func (w *replayWindow) check(n uint64, commit bool) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.started || n > w.highest {
		if commit {
			if !w.started || n-w.highest >= windowSize {
				w.bits = [windowSize / 64]uint64{}
			} else {
				for i := w.highest + 1; i < n; i++ {
					w.clear(i)
				}
			}
			w.started, w.highest = true, n
			w.set(n)
		}
		return true
	}
	if w.highest-n >= windowSize || w.isSet(n) {
		return false
	}
	if commit {
		w.set(n)
	}
	return true
}

func (w *replayWindow) set(n uint64)        { w.bits[(n/64)%(windowSize/64)] |= 1 << (n % 64) }
func (w *replayWindow) clear(n uint64)      { w.bits[(n/64)%(windowSize/64)] &^= 1 << (n % 64) }
func (w *replayWindow) isSet(n uint64) bool { return w.bits[(n/64)%(windowSize/64)]&(1<<(n%64)) != 0 }

// RandomIndex returns a random nonzero session index.
func RandomIndex() uint32 {
	var b [4]byte
	for {
		rand.Read(b[:])
		if i := binary.LittleEndian.Uint32(b[:]); i != 0 {
			return i
		}
	}
}
