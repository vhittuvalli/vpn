package vpn

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vhittuvalli/vpn/internal/config"
)

func TestGuestQuota(t *testing.T) {
	tn := startPeer(t, "udp", DefaultLoadThreshold, config.Peer{
		Guest: true, ExpiresAt: time.Now().Add(time.Hour), QuotaBytes: 250,
	})
	up := ipv4Packet("10.8.0.2", "10.8.0.1", strings.Repeat("u", 80)) // 100 bytes
	down := ipv4Packet("10.8.0.1", "10.8.0.2", strings.Repeat("d", 80))

	// Under the 250-byte quota, traffic flows both ways.
	tn.client.fromOS <- up
	tn.server.expect(t, up)
	tn.server.fromOS <- down
	tn.client.expect(t, down)
	if over := tn.serverVPN.GuestsOverLimit(time.Now()); len(over) != 0 {
		t.Fatalf("cut off too early: %v", over)
	}
	// A packet that starts under the quota still goes through, so a guest
	// can overshoot by at most one packet.
	tn.client.fromOS <- up
	tn.server.expect(t, up)

	// Past the quota, nothing more flows either way.
	tn.client.fromOS <- up
	tn.server.expectNothing(t)
	tn.server.fromOS <- down
	tn.client.expectNothing(t)
	if over := tn.serverVPN.GuestsOverLimit(time.Now()); !slices.Equal(over, []string{"laptop"}) {
		t.Fatalf("GuestsOverLimit = %v", over)
	}
}

func TestGuestExpiry(t *testing.T) {
	expires := time.Now().Add(1500 * time.Millisecond)
	tn := startPeer(t, "udp", DefaultLoadThreshold, config.Peer{Guest: true, ExpiresAt: expires})
	up := ipv4Packet("10.8.0.2", "10.8.0.1", "before")
	tn.client.fromOS <- up
	tn.server.expect(t, up)

	time.Sleep(time.Until(expires) + 50*time.Millisecond)
	tn.client.fromOS <- ipv4Packet("10.8.0.2", "10.8.0.1", "after")
	tn.server.expectNothing(t)
	tn.server.fromOS <- ipv4Packet("10.8.0.1", "10.8.0.2", "after")
	tn.client.expectNothing(t)
	if over := tn.serverVPN.GuestsOverLimit(time.Now()); len(over) != 1 {
		t.Fatalf("GuestsOverLimit = %v", over)
	}
}

// Regular devices have no limits even with the same traffic.
func TestRegularDeviceUnlimited(t *testing.T) {
	tn := start(t, "udp", DefaultLoadThreshold)
	if over := tn.serverVPN.GuestsOverLimit(time.Now().Add(1000 * time.Hour)); len(over) != 0 {
		t.Fatalf("regular device listed as over a guest limit: %v", over)
	}
}

func TestTokenBucket(t *testing.T) {
	start := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	b := newTokenBucket(1_000_000) // 1 MB/s, so a 500 KB burst
	if !b.allow(500_000, start) {
		t.Fatal("the initial burst should pass")
	}
	if b.allow(1500, start) {
		t.Fatal("bucket empty, packet should be dropped")
	}
	// 10 ms later, 10 KB has refilled.
	if !b.allow(10_000, start.Add(10*time.Millisecond)) {
		t.Fatal("refill not applied")
	}
	if b.allow(1500, start.Add(10*time.Millisecond)) {
		t.Fatal("refill over-counted")
	}
	// It never banks more than the burst, however long it idles.
	if b.allow(600_000, start.Add(time.Hour)) {
		t.Fatal("bucket grew past its burst")
	}

	// Over a simulated 10 seconds of 1500-byte packets, about rate*10
	// (plus the burst) gets through.
	b = newTokenBucket(625_000) // 5 Mbit/s
	sent := 0
	for ms := range 10_000 {
		for range 3 {
			if b.allow(1500, start.Add(time.Duration(ms)*time.Millisecond)) {
				sent += 1500
			}
		}
	}
	want := 625_000*10 + 312_500
	if sent < want*95/100 || sent > want*105/100 {
		t.Fatalf("sent %d bytes in 10 s at 5 Mbit/s, want about %d", sent, want)
	}
}
