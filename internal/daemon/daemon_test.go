package daemon

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/vhittuvalli/vpn/internal/accesskey"
	"github.com/vhittuvalli/vpn/internal/config"
	"github.com/vhittuvalli/vpn/internal/netid"
	"github.com/vhittuvalli/vpn/internal/protocol"
	"github.com/vhittuvalli/vpn/internal/tunnel"
	"github.com/vhittuvalli/vpn/internal/vpn"
)

var (
	home    = netid.Network{ID: "wifi|Home|a0:bc:6f:76:b5:02", Name: "Home"}
	fake    = netid.Network{ID: "wifi|Home|de:ad:be:ef:00:01", Name: "Home"} // same name, other router
	airport = netid.Network{ID: "wifi|Airport|11:22:33:44:55:66", Name: "Airport"}
)

// testDaemon has a fake tunnel that connects instantly and a network that
// the test changes by hand.
type testDaemon struct {
	*Daemon
	mu      sync.Mutex
	network netid.Network
	running int // tunnels currently up
}

func newTestDaemon(t *testing.T, dir string) *testDaemon {
	t.Helper()
	td := &testDaemon{Daemon: newDaemon(dir, "test", 0), network: home}
	td.currentNetwork = func() (netid.Network, error) {
		td.mu.Lock()
		defer td.mu.Unlock()
		return td.network, nil
	}
	td.runTunnel = func(ctx context.Context, _ *config.Client, onState func(tunnel.State, *vpn.Client)) error {
		td.mu.Lock()
		td.running++
		td.mu.Unlock()
		onState(tunnel.Connected, nil)
		<-ctx.Done()
		td.mu.Lock()
		td.running--
		td.mu.Unlock()
		return nil
	}
	td.load()
	td.checkNetwork()
	return td
}

func (td *testDaemon) moveTo(n netid.Network) {
	td.mu.Lock()
	td.network = n
	td.mu.Unlock()
	td.checkNetwork()
}

// expect waits briefly for the tunnel goroutine to come up or go down.
func (td *testDaemon) expect(t *testing.T, state string, tunnels int) {
	t.Helper()
	var s Status
	var running int
	for range 100 {
		s = td.handle(Request{Cmd: CmdStatus})
		td.mu.Lock()
		running = td.running
		td.mu.Unlock()
		if s.State == state && running == tunnels {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("state %q with %d tunnel(s), want %q with %d (status %+v)", s.State, running, state, tunnels, s)
}

func testKey(t *testing.T) string {
	t.Helper()
	server, _ := protocol.GeneratePrivateKey()
	device, _ := protocol.GeneratePrivateKey()
	return (&accesskey.Key{
		Name: "laptop", Host: "203.0.113.10", UDPPort: 51820,
		ServerPublicKey: server.Public(), PrivateKey: device,
		Address: netip.MustParsePrefix("10.8.0.2/24"),
	}).String()
}

func TestTrustedNetworks(t *testing.T) {
	dir := t.TempDir()
	td := newTestDaemon(t, dir)
	yes, no := true, false

	td.handle(Request{Cmd: CmdSetKey, Key: testKey(t)})
	td.handle(Request{Cmd: CmdOn})
	td.expect(t, StateOn, 1)

	// Trusting home pauses the VPN there.
	if s := td.handle(Request{Cmd: CmdTrust, Trust: &yes}); !s.NetworkTrusted || s.Network != "Home" {
		t.Fatalf("after trusting: %+v", s)
	}
	td.expect(t, StatePaused, 0)

	// Leaving home reconnects; coming back pauses again.
	td.moveTo(airport)
	td.expect(t, StateOn, 1)
	td.moveTo(home)
	td.expect(t, StatePaused, 0)

	// A hotspot with the same name but another router isn't trusted.
	td.moveTo(fake)
	td.expect(t, StateOn, 1)
	td.moveTo(home)
	td.expect(t, StatePaused, 0)

	// Turning it on by hand at home connects anyway, until the network
	// changes.
	td.handle(Request{Cmd: CmdOn})
	td.expect(t, StateOn, 1)
	td.moveTo(airport)
	td.moveTo(home)
	td.expect(t, StatePaused, 0)

	// Off means off everywhere.
	td.handle(Request{Cmd: CmdOff})
	td.expect(t, StateOff, 0)
	td.moveTo(airport)
	td.expect(t, StateOff, 0)

	// Trusted networks are remembered across restarts.
	td.moveTo(home)
	td.handle(Request{Cmd: CmdOn})
	td.handle(Request{Cmd: CmdOff})
	restarted := newTestDaemon(t, dir)
	if s := restarted.handle(Request{Cmd: CmdStatus}); !s.NetworkTrusted {
		t.Fatalf("home not trusted after restart: %+v", s)
	}

	// Untrusting home connects again.
	td.handle(Request{Cmd: CmdOn})
	td.handle(Request{Cmd: CmdOn}) // a second On on a trusted network still connects
	td.handle(Request{Cmd: CmdTrust, Trust: &no})
	td.expect(t, StateOn, 1)
	td.handle(Request{Cmd: CmdOff})
}

func TestTrustUnknownNetwork(t *testing.T) {
	td := newTestDaemon(t, t.TempDir())
	td.Daemon.network = netid.Network{}
	td.currentNetwork = func() (netid.Network, error) { return netid.Network{}, netid.ErrUnknown }
	yes := true
	if s := td.handle(Request{Cmd: CmdTrust, Trust: &yes}); s.Error == "" {
		t.Fatal("trusting an unidentified network should fail")
	}
}
