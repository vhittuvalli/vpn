package main

import "testing"

func TestParseDialogResult(t *testing.T) {
	for _, c := range []struct{ out, button, text string }{
		{"Connect\nvpn://abc\n", "Connect", "vpn://abc"},
		{"Get a Free Key\n\n", "Get a Free Key", ""},
		{"Connect\n  vpn://abc  \n", "Connect", "vpn://abc"},
		{"Connect\n", "Connect", ""},
	} {
		b, txt := parseDialogResult(c.out)
		if b != c.button || txt != c.text {
			t.Errorf("parseDialogResult(%q) = %q, %q; want %q, %q", c.out, b, txt, c.button, c.text)
		}
	}
}
