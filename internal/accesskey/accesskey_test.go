package accesskey

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/vhittuvalli/vpn/internal/protocol"
)

func testKey(t *testing.T) *Key {
	t.Helper()
	server, err := protocol.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	device, err := protocol.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return &Key{
		Name: "laptop", Host: "203.0.113.10", UDPPort: 51820, HTTPSPort: 443,
		ServerPublicKey: server.Public(), PrivateKey: device,
		Address: netip.MustParsePrefix("10.8.0.2/24"),
	}
}

func TestRoundTrip(t *testing.T) {
	k := testKey(t)
	s := k.String()
	if !strings.HasPrefix(s, "vpn://") {
		t.Fatalf("missing scheme: %s", s)
	}
	// Pasted keys often pick up line breaks and spaces.
	got, err := Parse("  " + s[:40] + "\n" + s[40:] + " \n")
	if err != nil {
		t.Fatal(err)
	}
	if *got != *k {
		t.Fatalf("round trip changed the key:\n got %+v\nwant %+v", got, k)
	}
}

func TestClient(t *testing.T) {
	k := testKey(t)
	udp, err := k.Client(false, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if udp.Server != "203.0.113.10:51820" || udp.Transport != "udp" || !udp.KillSwitch || !udp.AllowLAN || !udp.RouteAllTraffic {
		t.Fatalf("udp config: %+v", udp)
	}
	https, err := k.Client(true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if https.Server != "203.0.113.10:443" || https.Transport != "https" || https.ServerName != "203.0.113.10" || https.KillSwitch {
		t.Fatalf("https config: %+v", https)
	}
	k.HTTPSPort = 0
	if _, err := k.Client(true, false, false); err == nil {
		t.Fatal("expected an error for https without an HTTPS port")
	}
}

func TestParseRejects(t *testing.T) {
	good := testKey(t).String()
	for name, s := range map[string]string{
		"empty":     "",
		"no scheme": strings.TrimPrefix(good, "vpn://"),
		"truncated": good[:len(good)/2],
		"garbage":   "vpn://!!!",
		"not json":  "vpn://aGVsbG8",
	} {
		if _, err := Parse(s); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
