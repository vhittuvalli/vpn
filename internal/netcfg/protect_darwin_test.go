package netcfg

import (
	"net/netip"
	"strings"
	"testing"
)

func TestPFRules(t *testing.T) {
	server := netip.MustParseAddr("203.0.113.10")
	strict := pfRules("utun4", server, false)
	if !strings.Contains(strict, "pass out quick inet from any to 203.0.113.10\n") {
		t.Errorf("server not allowed:\n%s", strict)
	}
	if strings.Contains(strict, "192.168.0.0/16") {
		t.Errorf("local network allowed without allowLAN:\n%s", strict)
	}
	lan := pfRules("utun4", server, true)
	for _, want := range []string{"192.168.0.0/16", "224.0.0.0/4", "fe80::/10"} {
		if !strings.Contains(lan, want) {
			t.Errorf("missing %s:\n%s", want, lan)
		}
	}
	if !strings.HasSuffix(lan, "block drop out quick all\n") {
		t.Errorf("block rule must come last:\n%s", lan)
	}
}
