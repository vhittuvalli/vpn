package netcfg

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestKillSwitchCommands(t *testing.T) {
	server := netip.MustParseAddr("203.0.113.10")
	has := func(cmds [][]string, want string) bool {
		return slices.ContainsFunc(cmds, func(c []string) bool { return strings.Join(c, " ") == want })
	}

	strict := killSwitchCommands("tun0", server, false, true)
	// All traffic to the server is allowed, not just the tunnel port, so
	// SSH to it keeps working.
	if !has(strict, "iptables -A VPN_KILLSWITCH -d 203.0.113.10 -j ACCEPT") {
		t.Error("server not allowed")
	}
	if has(strict, "iptables -A VPN_KILLSWITCH -d 192.168.0.0/16 -j ACCEPT") {
		t.Error("local network allowed without allowLAN")
	}

	lan := killSwitchCommands("tun0", server, true, true)
	for _, want := range []string{
		"iptables -A VPN_KILLSWITCH -d 192.168.0.0/16 -j ACCEPT",
		"iptables -A VPN_KILLSWITCH -d 224.0.0.0/4 -j ACCEPT",
		"ip6tables -A VPN_KILLSWITCH -d fe80::/10 -j ACCEPT",
	} {
		if !has(lan, want) {
			t.Errorf("missing %q", want)
		}
	}
	// Without the kill switch, only IPv6 is filtered.
	v6only := killSwitchCommands("tun0", server, true, false)
	for _, c := range v6only {
		if c[0] == "iptables" {
			t.Errorf("IPv4 rule without the kill switch: %v", c)
		}
	}
	if !has(v6only, "ip6tables -A VPN_KILLSWITCH -j REJECT") || !has(v6only, "ip6tables -A VPN_KILLSWITCH -d fe80::/10 -j ACCEPT") {
		t.Error("IPv6 not blocked (or link-local not allowed) without the kill switch")
	}

	// Every ACCEPT comes before the final REJECT in each chain.
	for _, ipt := range []string{"iptables", "ip6tables"} {
		reject := slices.IndexFunc(lan, func(c []string) bool { return c[0] == ipt && slices.Contains(c, "REJECT") })
		for i, c := range lan {
			if c[0] == ipt && slices.Contains(c, "ACCEPT") && i > reject {
				t.Errorf("%s: %v comes after REJECT", ipt, c)
			}
		}
	}
}
