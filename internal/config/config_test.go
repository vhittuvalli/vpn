package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vhittuvalli/vpn/internal/protocol"
)

func writeFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func keys(t *testing.T) (server, peer string) {
	t.Helper()
	s, _ := protocol.GeneratePrivateKey()
	p, _ := protocol.GeneratePrivateKey()
	return s.String(), p.Public().String()
}

// A server.json written before guest access existed loads unchanged, with
// guests off and the defaults filled in.
func TestOldServerFileStillLoads(t *testing.T) {
	sk, pk := keys(t)
	path := writeFile(t, `{
  "private_key": "`+sk+`",
  "endpoint": "139.59.79.156",
  "listen_port": 51820,
  "https_port": 443,
  "address": "10.8.0.1/24",
  "nat_interface": "eth0",
  "peers": [
    {"name": "macbook", "public_key": "`+pk+`", "address": "10.8.0.2"}
  ]
}`)
	s, err := LoadServer(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Peers) != 1 || s.Peers[0].Guest || !s.Peers[0].ExpiresAt.IsZero() {
		t.Fatalf("peer: %+v", s.Peers)
	}
	g := s.Guests
	if g.Enabled || g.TTL != time.Hour || g.QuotaBytes != 500_000_000 || g.MaxActive != 20 || g.PerIPPerDay != 3 {
		t.Fatalf("guest defaults: %+v", g)
	}
	if g.Hostname != "139.59.79.156.sslip.io" || g.Pool != netip.MustParsePrefix("10.8.0.128/25") {
		t.Fatalf("derived guest settings: %+v", g)
	}

	// Reading and writing it back (as `vpn invite` does) adds no new fields.
	f, err := ReadServerFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Write(path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	for _, field := range []string{"guests", "guest", "expires_at", "quota_bytes"} {
		if strings.Contains(string(data), `"`+field+`"`) {
			t.Errorf("round trip added %q:\n%s", field, data)
		}
	}
}

func TestGuestPeersAndSettings(t *testing.T) {
	sk, pk := keys(t)
	path := writeFile(t, `{
  "private_key": "`+sk+`",
  "endpoint": "203.0.113.10",
  "address": "10.8.0.1/24",
  "guests": {"enabled": true, "ttl": "30m", "quota_bytes": 1000, "max_active_guests": 2, "allowed_origins": ["https://example.com"]},
  "peers": [
    {"name": "guest-abc123", "public_key": "`+pk+`", "address": "10.8.0.130",
     "guest": true, "expires_at": "2026-11-02T15:00:00Z", "quota_bytes": 1000}
  ]
}`)
	s, err := LoadServer(path)
	if err != nil {
		t.Fatal(err)
	}
	p := s.Peers[0]
	if !p.Guest || p.QuotaBytes != 1000 || !p.ExpiresAt.Equal(time.Date(2026, 11, 2, 15, 0, 0, 0, time.UTC)) {
		t.Fatalf("guest peer: %+v", p)
	}
	g := s.Guests
	if !g.Enabled || g.TTL != 30*time.Minute || g.QuotaBytes != 1000 || g.MaxActive != 2 || g.PerIPPerDay != 3 || g.AllowedOrigins[0] != "https://example.com" {
		t.Fatalf("guest settings: %+v", g)
	}
}

func TestGuestSettingsErrors(t *testing.T) {
	sk, pk := keys(t)
	for name, c := range map[string]struct{ guests, peer, want string }{
		"bad ttl":      {`{"enabled": true, "ttl": "soon"}`, "", "guests.ttl"},
		"no hostname":  {`{"enabled": true}`, "", "guest_hostname"},
		"bad expiry":   {`{}`, `, "guest": true, "expires_at": "tomorrow"`, "expires_at"},
		"negative cap": {`{"max_active_guests": -1}`, "", "negative"},
	} {
		t.Run(name, func(t *testing.T) {
			endpoint := "203.0.113.10"
			if name == "no hostname" {
				endpoint = "vpn.example.com" // not an IP, so no sslip.io default
			}
			path := writeFile(t, `{"private_key": "`+sk+`", "endpoint": "`+endpoint+`", "address": "10.8.0.1/24", "guests": `+c.guests+`,
  "peers": [{"name": "p", "public_key": "`+pk+`", "address": "10.8.0.2"`+c.peer+`}]}`)
			if _, err := LoadServer(path); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error mentioning %q, got %v", c.want, err)
			}
		})
	}
}

func TestGuestPool(t *testing.T) {
	for subnet, want := range map[string]string{
		"10.8.0.1/24":    "10.8.0.128/25",
		"10.8.0.1/16":    "10.8.128.0/17",
		"192.168.5.9/28": "192.168.5.8/29",
	} {
		got, ok := GuestPool(netip.MustParsePrefix(subnet))
		if !ok || got.String() != want {
			t.Errorf("GuestPool(%s) = %v, %v; want %s", subnet, got, ok, want)
		}
	}
	if _, ok := GuestPool(netip.MustParsePrefix("10.8.0.1/30")); ok {
		t.Error("a /30 has no room for a guest pool")
	}
}
