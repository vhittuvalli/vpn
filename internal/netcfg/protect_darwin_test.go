package netcfg

import (
	"net/netip"
	"strings"
	"testing"
)

func TestPFRules(t *testing.T) {
	server := netip.MustParseAddr("203.0.113.10")
	strict := pfRules("utun4", server, false, true)
	if !strings.Contains(strict, "pass out quick inet from any to 203.0.113.10\n") {
		t.Errorf("server not allowed:\n%s", strict)
	}
	if strings.Contains(strict, "192.168.0.0/16") {
		t.Errorf("local network allowed without allowLAN:\n%s", strict)
	}
	lan := pfRules("utun4", server, true, true)
	for _, want := range []string{"192.168.0.0/16", "224.0.0.0/4", "fe80::/10"} {
		if !strings.Contains(lan, want) {
			t.Errorf("missing %s:\n%s", want, lan)
		}
	}
	if !strings.HasSuffix(lan, "block drop out quick all\n") {
		t.Errorf("block rule must come last:\n%s", lan)
	}

	// Without the kill switch, IPv4 flows freely but IPv6 is still blocked.
	v6only := pfRules("utun4", server, true, false)
	if strings.Contains(v6only, "block drop out quick all") || strings.Contains(v6only, "inet from any to 203.0.113.10") {
		t.Errorf("IPv4 blocked without the kill switch:\n%s", v6only)
	}
	if !strings.HasSuffix(v6only, "block drop out quick inet6 all\n") || !strings.Contains(v6only, "fe80::/10") {
		t.Errorf("IPv6 not blocked (or link-local not allowed):\n%s", v6only)
	}
}
