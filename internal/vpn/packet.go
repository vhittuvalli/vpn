// Package vpn runs the server and client: it moves packets between the TUN
// device and the encrypted UDP tunnel.
package vpn

import "net/netip"

// Only IPv4 is carried through the tunnel.

func ipv4Src(p []byte) (netip.Addr, bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(p[12:16])), true
}

func ipv4Dst(p []byte) (netip.Addr, bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(p[16:20])), true
}

// firstError runs each loop in its own goroutine and returns the first error.
func firstError(loops ...func() error) error {
	errc := make(chan error, len(loops))
	for _, loop := range loops {
		go func() { errc <- loop() }()
	}
	return <-errc
}
