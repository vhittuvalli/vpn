package netcfg

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestNATRules(t *testing.T) {
	rules := natRules("tun0", "eth0", netip.MustParsePrefix("10.8.0.1/24"))
	// Inserted at the top in order, so the chain reads in reverse.
	var chain []string
	for _, r := range slices.Backward(rules) {
		if r[2] == "FORWARD" {
			chain = append(chain, strings.Join(r[3:], " "))
		}
	}
	pos := func(rule string) int {
		i := slices.Index(chain, rule)
		if i < 0 {
			t.Fatalf("missing FORWARD rule %q in %q", rule, chain)
		}
		return i
	}
	accept := pos("-i tun0 -j ACCEPT")
	for _, blocked := range []string{
		"-i tun0 -o tun0 -j DROP", // device to device
		"-i tun0 ! -o tun0 -d 169.254.0.0/16 -j DROP",
		"-i tun0 ! -o tun0 -d 10.0.0.0/8 -j DROP",
	} {
		if pos(blocked) > accept {
			t.Errorf("%q comes after the ACCEPT, so it never applies", blocked)
		}
	}
	if !slices.ContainsFunc(rules, func(r []string) bool {
		return strings.Join(r, " ") == "-t nat POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE"
	}) {
		t.Error("missing MASQUERADE")
	}
}
