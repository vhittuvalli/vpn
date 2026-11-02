package registry

import (
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vhittuvalli/vpn/internal/config"
	"github.com/vhittuvalli/vpn/internal/protocol"
)

var now = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

func newRegistry(t *testing.T, guests *config.GuestFile) Registry {
	t.Helper()
	sk, _ := protocol.GeneratePrivateKey()
	r := Registry{Path: filepath.Join(t.TempDir(), "server.json")}
	f := &config.ServerFile{
		PrivateKey: sk.String(), Endpoint: "203.0.113.10", Address: "10.8.0.1/24",
		Guests: guests, Peers: []config.PeerFile{},
	}
	if err := f.Write(r.Path); err != nil {
		t.Fatal(err)
	}
	return r
}

// The file must always stay loadable by the server.
func mustLoad(t *testing.T, r Registry) *config.Server {
	t.Helper()
	s, err := config.LoadServer(r.Path)
	if err != nil {
		t.Fatalf("server.json no longer loads: %v", err)
	}
	return s
}

func TestAddAndRevokeDevice(t *testing.T) {
	r := newRegistry(t, nil)
	a, err := r.AddDevice("laptop")
	if err != nil {
		t.Fatal(err)
	}
	if a.Peer.Address != "10.8.0.2" || a.Peer.Guest || a.Key.Name != "laptop" || a.Key.Host != "203.0.113.10" {
		t.Fatalf("added: %+v", a.Peer)
	}
	if a.Key.Address != netip.MustParsePrefix("10.8.0.2/24") || a.Key.UDPPort != config.DefaultUDPPort {
		t.Fatalf("key: %+v", a.Key)
	}
	if _, err := r.AddDevice("laptop"); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("duplicate name: %v", err)
	}
	if _, err := r.AddDevice("not a name!"); err == nil {
		t.Fatal("accepted a bad name")
	}
	r.AddDevice("phone")
	if s := mustLoad(t, r); len(s.Peers) != 2 {
		t.Fatalf("%d peers", len(s.Peers))
	}

	removed, err := r.Remove("laptop", "nobody")
	if err != nil || len(removed) != 1 || removed[0] != "laptop" {
		t.Fatalf("removed %v, %v", removed, err)
	}
	if s := mustLoad(t, r); len(s.Peers) != 1 || s.Peers[0].Name != "phone" {
		t.Fatalf("after revoke: %+v", s.Peers)
	}
}

func TestRegularDevicesStayOutOfGuestPool(t *testing.T) {
	r := newRegistry(t, nil)
	for i := range 126 { // 10.8.0.2 – 10.8.0.127
		if _, err := r.AddDevice("d" + string(rune('a'+i/26)) + string(rune('a'+i%26))); err != nil {
			t.Fatalf("device %d: %v", i, err)
		}
	}
	if _, err := r.AddDevice("onemore"); !errors.Is(err, ErrNoAddress) {
		t.Fatalf("expected the lower half to be full, got %v", err)
	}
}

func TestAddGuest(t *testing.T) {
	r := newRegistry(t, &config.GuestFile{Enabled: true, TTL: "1h", QuotaBytes: 1234})
	a, err := r.AddGuest(now)
	if err != nil {
		t.Fatal(err)
	}
	p := a.Peer
	if !p.Guest || !strings.HasPrefix(p.Name, "guest-") || len(p.Name) != len("guest-")+6 {
		t.Fatalf("guest: %+v", p)
	}
	if p.Address != "10.8.0.128" || p.QuotaBytes != 1234 || p.ExpiresAt != "2026-11-02T13:00:00Z" {
		t.Fatalf("guest address, quota or expiry: %+v", p)
	}
	s := mustLoad(t, r)
	if !s.Peers[0].Guest || !s.Peers[0].ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("loaded guest: %+v", s.Peers[0])
	}
}

func TestGuestsDisabled(t *testing.T) {
	r := newRegistry(t, nil)
	if _, err := r.AddGuest(now); !errors.Is(err, ErrGuestsDisabled) {
		t.Fatalf("got %v", err)
	}
	if err := r.SetGuestsEnabled(true); err != nil {
		t.Fatal(err)
	}
	if _, err := r.AddGuest(now); err != nil {
		t.Fatal(err)
	}
	r.SetGuestsEnabled(false)
	if !strings.Contains(mustLoadRaw(t, r), `"enabled": false`) {
		t.Fatal("guests not turned off in the file")
	}
}

func mustLoadRaw(t *testing.T, r Registry) string {
	t.Helper()
	f, err := config.ReadServerFile(r.Path)
	if err != nil {
		t.Fatal(err)
	}
	if f.Guests == nil {
		return ""
	}
	if f.Guests.Enabled {
		return `"enabled": true`
	}
	return `"enabled": false`
}

func TestMaxActiveGuests(t *testing.T) {
	r := newRegistry(t, &config.GuestFile{Enabled: true, MaxActiveGuests: 2})
	r.AddGuest(now)
	r.AddGuest(now)
	if _, err := r.AddGuest(now); !errors.Is(err, ErrGuestsFull) {
		t.Fatalf("third guest: %v", err)
	}
	// Once the first two expire, their slots free up even before the sweep
	// removes them.
	if _, err := r.AddGuest(now.Add(2 * time.Hour)); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}

// Simultaneous requests can't overshoot the limit or corrupt the file.
func TestConcurrentGuests(t *testing.T) {
	r := newRegistry(t, &config.GuestFile{Enabled: true, MaxActiveGuests: 5})
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, full := 0, 0
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.AddGuest(now)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrGuestsFull):
				full++
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if ok != 5 || full != 15 {
		t.Fatalf("%d added, %d refused; want 5 and 15", ok, full)
	}
	if s := mustLoad(t, r); len(s.Peers) != 5 {
		t.Fatalf("%d peers in the file", len(s.Peers))
	}
}

func TestRemoveExpiredGuests(t *testing.T) {
	r := newRegistry(t, &config.GuestFile{Enabled: true, TTL: "1h"})
	r.AddDevice("laptop")
	old, _ := r.AddGuest(now)
	fresh, _ := r.AddGuest(now.Add(50 * time.Minute))

	removed, err := r.RemoveExpiredGuests(now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != old.Peer.Name {
		t.Fatalf("removed %v, want only %s", removed, old.Peer.Name)
	}
	names := map[string]bool{}
	for _, p := range mustLoad(t, r).Peers {
		names[p.Name] = true
	}
	if !names["laptop"] || !names[fresh.Peer.Name] || names[old.Peer.Name] {
		t.Fatalf("left: %v", names)
	}
}

func TestPurgeGuests(t *testing.T) {
	r := newRegistry(t, &config.GuestFile{Enabled: true})
	r.AddDevice("laptop")
	r.AddGuest(now)
	r.AddGuest(now)
	removed, err := r.RemoveIf(func(p config.PeerFile) bool { return p.Guest })
	if err != nil || len(removed) != 2 {
		t.Fatalf("purged %v, %v", removed, err)
	}
	if s := mustLoad(t, r); len(s.Peers) != 1 || s.Peers[0].Name != "laptop" {
		t.Fatalf("left: %+v", s.Peers)
	}
}
