package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vhittuvalli/vpn/internal/budget"
	"github.com/vhittuvalli/vpn/internal/config"
	"github.com/vhittuvalli/vpn/internal/guestapi"
	"github.com/vhittuvalli/vpn/internal/protocol"
	"github.com/vhittuvalli/vpn/internal/registry"
	"github.com/vhittuvalli/vpn/internal/vpn"
)

func TestGuestLimitsColumn(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	used := vpn.PeerStats{RxBytes: 20_500_000, TxBytes: 100_000_000}
	for _, c := range []struct {
		peer config.PeerFile
		want string
	}{
		{config.PeerFile{Name: "laptop"}, "-"},
		{config.PeerFile{Guest: true, ExpiresAt: "2026-11-02T12:42:00Z", QuotaBytes: 500_000_000}, "42m left · 120.5 MB of 500.0 MB"},
		{config.PeerFile{Guest: true, ExpiresAt: "2026-11-02T11:00:00Z", QuotaBytes: 500_000_000}, "expired · 120.5 MB of 500.0 MB"},
		{config.PeerFile{Guest: true, ExpiresAt: "2026-11-02T13:00:00Z"}, "1h 0m left · 120.5 MB used"},
	} {
		if got := guestLimits(c.peer, used, now); got != c.want {
			t.Errorf("guestLimits(%+v) = %q, want %q", c.peer, got, c.want)
		}
	}
}

func TestGuestStatusOutput(t *testing.T) {
	dir := t.TempDir()
	reg := registry.Registry{Path: filepath.Join(dir, "server.json")}
	sk, _ := protocol.GeneratePrivateKey()
	f := &config.ServerFile{PrivateKey: sk.String(), Endpoint: "203.0.113.10", Address: "10.8.0.1/24",
		Guests: &config.GuestFile{Enabled: true}, Peers: []config.PeerFile{}}
	if err := f.Write(reg.Path); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := reg.AddGuest(now); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(usagePath(reg.Path), []byte(`{"month":"`+budget.Month(now)+`","sent_bytes":12400000000,"last_counter":1}`), 0o600)
	line, _ := json.Marshal(guestapi.IssueRecord{Time: now, Name: "guest-x", IP: "198.51.100.7"})
	os.WriteFile(guestLogPath(reg.Path), append(line, '\n'), 0o600)

	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w
	err := guestStatus(reg)
	w.Close()
	os.Stdout = stdout
	out, _ := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("\n%s", out)
	for _, want := range []string{
		"Guest access is on. 1 of 3 guest slots in use.",
		"11.5 GiB of the 450 GiB cap (3%)",
		"Guest keys handed out: 1 this month, 1 today.",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("output lacks %q", want)
		}
	}
}
