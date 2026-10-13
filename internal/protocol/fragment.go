package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"
)

// Post-quantum keys and signatures make handshake messages about 5 KB, more
// than fits in one packet. Instead of relying on IP fragmentation, which
// many networks drop, the protocol splits them itself:
//
//	fragment: type(1) index(1) count(1) reserved(1) message-id(4) payload(<= FragmentPayload)
//
// Data messages are never fragmented; the tunnel MTU keeps them small.

const (
	FragmentPayload    = 1000 // fits in a QUIC datagram as well as a UDP packet
	fragmentHeaderSize = 8
	maxFragments       = 8
	reassemblyTimeout  = 5 * time.Second
	maxReassemblies    = 1024
)

// Fragment splits msg into fragment packets.
func Fragment(msg []byte) [][]byte {
	var idb [4]byte
	rand.Read(idb[:])
	count := (len(msg) + FragmentPayload - 1) / FragmentPayload
	frags := make([][]byte, 0, count)
	for i := range count {
		chunk := msg[i*FragmentPayload : min((i+1)*FragmentPayload, len(msg))]
		f := make([]byte, fragmentHeaderSize, fragmentHeaderSize+len(chunk))
		f[0] = TypeFragment
		f[1] = byte(i)
		f[2] = byte(count)
		copy(f[4:8], idb[:])
		frags = append(frags, append(f, chunk...))
	}
	return frags
}

// Reassembler collects fragments from many sources. It holds a bounded
// number of partial messages and evicts the oldest, so a flood of bogus
// fragments can use only a fixed amount of memory.
type Reassembler[S comparable] struct {
	mu      sync.Mutex
	partial map[reassemblyKey[S]]*partialMessage
}

type reassemblyKey[S comparable] struct {
	source S
	id     uint32
}

type partialMessage struct {
	created  time.Time
	pieces   [][]byte
	received int
}

func NewReassembler[S comparable]() *Reassembler[S] {
	return &Reassembler[S]{partial: map[reassemblyKey[S]]*partialMessage{}}
}

// Add stores one fragment and returns the whole message once every fragment
// has arrived.
func (r *Reassembler[S]) Add(source S, frag []byte) ([]byte, bool) {
	if len(frag) <= fragmentHeaderSize || len(frag) > fragmentHeaderSize+FragmentPayload || frag[0] != TypeFragment {
		return nil, false
	}
	index, count := int(frag[1]), int(frag[2])
	if count == 0 || count > maxFragments || index >= count {
		return nil, false
	}
	key := reassemblyKey[S]{source, binary.LittleEndian.Uint32(frag[4:8])}

	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.partial[key]
	if p == nil {
		r.makeRoom()
		p = &partialMessage{created: time.Now(), pieces: make([][]byte, count)}
		r.partial[key] = p
	}
	if len(p.pieces) != count || p.pieces[index] != nil {
		return nil, false // inconsistent or duplicate
	}
	p.pieces[index] = append([]byte(nil), frag[fragmentHeaderSize:]...)
	p.received++
	if p.received < count {
		return nil, false
	}
	delete(r.partial, key)
	var msg []byte
	for _, piece := range p.pieces {
		msg = append(msg, piece...)
	}
	return msg, true
}

func (r *Reassembler[S]) makeRoom() {
	if len(r.partial) < maxReassemblies {
		return
	}
	var oldestKey reassemblyKey[S]
	var oldest *partialMessage
	for k, p := range r.partial {
		if time.Since(p.created) > reassemblyTimeout {
			delete(r.partial, k)
			continue
		}
		if oldest == nil || p.created.Before(oldest.created) {
			oldestKey, oldest = k, p
		}
	}
	if len(r.partial) >= maxReassemblies && oldest != nil {
		delete(r.partial, oldestKey)
	}
}
