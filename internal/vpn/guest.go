package vpn

import (
	"log"
	"sync"
	"time"

	"github.com/vhittuvalli/vpn/internal/config"
)

// Guest limits are enforced on every packet, so a guest can't keep going
// past its expiry or quota until the next sweep removes it from the config.

// guestLimits is fixed for a peer's lifetime.
type guestLimits struct {
	expiresAt time.Time
	quota     uint64       // bytes both ways; 0 means unlimited
	bucket    *tokenBucket // nil means no bandwidth cap
}

// usedBytes is everything the peer sent and received, across restarts.
func (p *serverPeer) usedBytes() uint64 {
	p.mu.Lock()
	carried := p.carried.RxBytes + p.carried.TxBytes
	p.mu.Unlock()
	return carried + p.rxBytes.Load() + p.txBytes.Load()
}

// guestCutOff reports whether a guest has used up its time or data. Once
// true it stays true.
func (p *serverPeer) guestCutOff(now time.Time) bool {
	if p.guest == nil {
		return false
	}
	if p.cutOff.Load() {
		return true
	}
	why := ""
	switch {
	case !now.Before(p.guest.expiresAt):
		why = "its time ran out"
	case p.guest.quota > 0 && p.usedBytes() >= p.guest.quota:
		why = "it used its data allowance"
	default:
		return false
	}
	if p.cutOff.CompareAndSwap(false, true) {
		log.Printf("guest %s cut off: %s", p.name, why)
	}
	return true
}

// guestAllow applies the guest's bandwidth cap to a packet of n bytes.
func (p *serverPeer) guestAllow(n int) bool {
	return p.guest == nil || p.guest.bucket == nil || p.guest.bucket.allow(n, time.Now())
}

// GuestsOverLimit names the guests that have run out of time or data, for
// the sweep that removes them from the config.
func (s *Server) GuestsOverLimit(now time.Time) []string {
	var names []string
	for _, p := range s.allPeers() {
		if p.guestCutOff(now) {
			names = append(names, p.name)
		}
	}
	return names
}

// SetGuestRate sets the bandwidth cap for guests added from now on, in
// megabits per second; 0 means none.
func (s *Server) SetGuestRate(mbps float64) {
	s.peersMu.Lock()
	s.guestRate = mbps
	s.peersMu.Unlock()
}

func newGuestLimits(p config.Peer, mbps float64) *guestLimits {
	if !p.Guest {
		return nil
	}
	g := &guestLimits{expiresAt: p.ExpiresAt, quota: p.QuotaBytes}
	if mbps > 0 {
		g.bucket = newTokenBucket(mbps * 1e6 / 8)
	}
	return g
}

// tokenBucket limits a rate in bytes per second, allowing bursts of up to
// half a second's worth. Packets over the limit are dropped, which TCP
// treats as congestion and slows down for.
type tokenBucket struct {
	mu     sync.Mutex
	rate   float64 // bytes per second
	burst  float64
	tokens float64
	last   time.Time
}

func newTokenBucket(bytesPerSecond float64) *tokenBucket {
	burst := max(bytesPerSecond/2, 64*1024)
	return &tokenBucket{rate: bytesPerSecond, burst: burst, tokens: burst}
}

func (b *tokenBucket) allow(n int, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.last.IsZero() {
		b.tokens = min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	}
	b.last = now
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}
