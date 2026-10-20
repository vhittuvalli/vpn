package vpn

import "testing"

// Packets from the TUN device and the tunnel are parsed for addresses; no
// input may panic, and only IPv4 headers may yield one.
func FuzzIPv4Addrs(f *testing.F) {
	f.Add(ipv4Packet("10.8.0.2", "1.1.1.1", "x"))
	f.Add([]byte{0x60, 0, 0, 0}) // IPv6
	f.Fuzz(func(t *testing.T, p []byte) {
		src, ok1 := ipv4Src(p)
		dst, ok2 := ipv4Dst(p)
		if ok1 != ok2 {
			t.Fatal("source and destination parsing disagree")
		}
		if ok1 && (len(p) < 20 || p[0]>>4 != 4 || !src.Is4() || !dst.Is4()) {
			t.Fatalf("accepted a non-IPv4 packet: %x", p)
		}
	})
}
