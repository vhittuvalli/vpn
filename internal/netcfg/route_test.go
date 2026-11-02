package netcfg

import (
	"net/netip"
	"testing"
)

func TestBestDefaultRoute(t *testing.T) {
	def := netip.MustParsePrefix("0.0.0.0/0")
	routes := []Route{
		{Interface: 7, Prefix: netip.MustParsePrefix("192.168.1.0/24"), Metric: 1},           // not a default route
		{Interface: 9, Prefix: def, NextHop: netip.MustParseAddr("10.0.0.1"), Metric: 50},    // Ethernet
		{Interface: 4, Prefix: def, NextHop: netip.MustParseAddr("192.168.1.1"), Metric: 35}, // Wi-Fi, preferred
		{Interface: 3, Prefix: def, Metric: 5},                                               // the tunnel itself
		{Interface: 5, Prefix: netip.MustParsePrefix("::/0"), Metric: 1},                     // IPv6
	}
	r, ok := BestDefaultRoute(routes, 3)
	if !ok || r.Interface != 4 || r.NextHop != netip.MustParseAddr("192.168.1.1") {
		t.Fatalf("got %+v, %v; want the Wi-Fi route", r, ok)
	}
	if _, ok := BestDefaultRoute(routes[:1], 3); ok {
		t.Fatal("found a default route where there is none")
	}
}
