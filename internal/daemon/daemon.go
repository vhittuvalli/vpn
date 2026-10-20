// Package daemon is the background service behind the Mac app. Changing
// routes, DNS and the firewall needs root, so a small root process owns the
// tunnel and the app (running as the user) tells it what to do over a Unix
// socket. Only root and the user who installed the service may send
// commands; the kernel reports who is on the other end of the socket.
//
// Each connection carries one JSON Request and gets one JSON Status back.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/vhittuvalli/vpn/internal/accesskey"
	"github.com/vhittuvalli/vpn/internal/config"
	"github.com/vhittuvalli/vpn/internal/netcfg"
	"github.com/vhittuvalli/vpn/internal/netid"
	"github.com/vhittuvalli/vpn/internal/tunnel"
	"github.com/vhittuvalli/vpn/internal/vpn"
)

const SocketPath = "/var/run/vpn.sock"

// Commands.
const (
	CmdStatus   = "status"
	CmdOn       = "on"
	CmdOff      = "off"
	CmdSetKey   = "set-key"
	CmdSettings = "settings"
	CmdTrust    = "trust" // trust or stop trusting the current network
)

type Request struct {
	Cmd        string `json:"cmd"`
	Key        string `json:"key,omitempty"`         // CmdSetKey
	KillSwitch *bool  `json:"kill_switch,omitempty"` // CmdSettings
	HTTPS      *bool  `json:"https,omitempty"`       // CmdSettings
	AllowLAN   *bool  `json:"allow_lan,omitempty"`   // CmdSettings
	Trust      *bool  `json:"trust,omitempty"`       // CmdTrust
}

// Connection states.
const (
	StateOff        = "off"
	StateConnecting = "connecting"
	StateOn         = "on"
	StatePaused     = "paused" // on, but this is a trusted network
)

type Status struct {
	Version string `json:"version"`
	State   string `json:"state"`
	Error   string `json:"error,omitempty"` // why the last command or connection failed
	HasKey  bool   `json:"has_key"`
	Name    string `json:"name,omitempty"`   // this device's name on the server
	Server  string `json:"server,omitempty"` // server host

	// While connected: since when, traffic so far and the latest round trip.
	ConnectedSince int64  `json:"connected_since,omitempty"` // unix seconds
	RxBytes        uint64 `json:"rx_bytes,omitempty"`
	TxBytes        uint64 `json:"tx_bytes,omitempty"`
	RTTMillis      int64  `json:"rtt_ms,omitempty"`
	KillSwitch     bool   `json:"kill_switch"`
	HTTPS          bool   `json:"https"`
	AllowLAN       bool   `json:"allow_lan"`

	// The network this machine is on, if it could be identified.
	Network        string `json:"network,omitempty"`
	NetworkTrusted bool   `json:"network_trusted"`
}

// settings survive restarts, so the VPN comes back after a reboot if it
// was on.
type settings struct {
	On         bool             `json:"on"`
	KillSwitch bool             `json:"kill_switch"`
	HTTPS      bool             `json:"https"`
	AllowLAN   bool             `json:"allow_lan"`
	Trusted    []TrustedNetwork `json:"trusted,omitempty"`
}

// TrustedNetwork is a network the VPN pauses on.
type TrustedNetwork struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Daemon struct {
	version string
	owner   int // uid allowed to send commands, besides root
	dir     string

	// op runs commands that change state one at a time, so a new tunnel
	// never starts while the old one is still being torn down. Status
	// requests skip it and stay instant.
	op sync.Mutex

	mu       sync.Mutex
	key      *accesskey.Key
	settings settings
	state    string
	lastErr  string
	client   *vpn.Client // the current connection, for statistics
	cancel   context.CancelFunc
	done     chan struct{}
	network  netid.Network // zero if unknown
	override bool          // turned on by hand while on a trusted network

	// Replaced in tests.
	runTunnel      func(context.Context, *config.Client, func(tunnel.State, *vpn.Client)) error
	currentNetwork func() (netid.Network, error)
}

// networkCheckInterval is how often the service looks for a network change.
const networkCheckInterval = 5 * time.Second

func newDaemon(dir, version string, owner int) *Daemon {
	return &Daemon{
		version: version, owner: owner, dir: dir, state: StateOff,
		settings:       settings{KillSwitch: true, AllowLAN: true},
		runTunnel:      tunnel.Run,
		currentNetwork: netid.Current,
	}
}

// Run serves commands until ctx is canceled, then disconnects.
func Run(ctx context.Context, version string, owner int) error {
	d := newDaemon(stateDir, version, owner)
	if err := os.MkdirAll(d.dir, 0o700); err != nil {
		return err
	}
	d.load()

	// Undo anything a crashed earlier run left behind (kill switch, DNS).
	if err := netcfg.Reset(); err != nil {
		log.Printf("reset: %v", err)
	}

	os.Remove(SocketPath)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: SocketPath, Net: "unix"})
	if err != nil {
		return err
	}
	// Anyone may connect; serve() checks who they are.
	if err := os.Chmod(SocketPath, 0o666); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	log.Printf("vpn service %s listening on %s (owner uid %d)", version, SocketPath, owner)

	d.checkNetwork()
	d.mu.Lock()
	d.applyLocked(false)
	d.mu.Unlock()
	go func() {
		t := time.NewTicker(networkCheckInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				d.checkNetwork()
			}
		}
	}()

	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			break
		}
		go d.serve(conn)
	}
	d.mu.Lock()
	d.stopLocked()
	d.mu.Unlock()
	os.Remove(SocketPath)
	return nil
}

func (d *Daemon) serve(conn *net.UnixConn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	uid, err := peerUID(conn)
	if err != nil || (uid != 0 && uid != d.owner) {
		json.NewEncoder(conn).Encode(Status{Version: d.version, Error: "not allowed: the VPN service belongs to another user"})
		return
	}
	var req Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}
	json.NewEncoder(conn).Encode(d.handle(req))
}

func (d *Daemon) handle(req Request) Status {
	if req.Cmd != CmdStatus {
		d.op.Lock()
		defer d.op.Unlock()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	switch req.Cmd {
	case CmdStatus:
	case CmdOn:
		if d.key == nil {
			d.lastErr = "add an access key first"
			break
		}
		d.settings.On = true
		// Turning it on by hand on a trusted network connects anyway, until
		// the network changes.
		d.override = d.trustedLocked()
		d.save()
		d.applyLocked(true)
	case CmdOff:
		d.settings.On, d.override = false, false
		d.save()
		d.applyLocked(false)
		d.lastErr = ""
	case CmdSetKey:
		k, err := accesskey.Parse(req.Key)
		if err != nil {
			d.lastErr = err.Error()
			break
		}
		if err := os.WriteFile(filepath.Join(d.dir, "key"), []byte(k.String()+"\n"), 0o600); err != nil {
			d.lastErr = fmt.Sprintf("saving the key: %v", err)
			break
		}
		d.key, d.lastErr = k, ""
		d.applyLocked(true)
	case CmdSettings:
		if req.KillSwitch != nil {
			d.settings.KillSwitch = *req.KillSwitch
		}
		if req.HTTPS != nil {
			d.settings.HTTPS = *req.HTTPS
		}
		if req.AllowLAN != nil {
			d.settings.AllowLAN = *req.AllowLAN
		}
		d.save()
		d.applyLocked(true)
	case CmdTrust:
		if d.network.ID == "" {
			d.lastErr = "can't tell which network this is yet; try again in a few seconds"
			break
		}
		trusted := d.settings.Trusted[:0:0]
		for _, n := range d.settings.Trusted {
			if n.ID != d.network.ID {
				trusted = append(trusted, n)
			}
		}
		if req.Trust != nil && *req.Trust {
			trusted = append(trusted, TrustedNetwork{ID: d.network.ID, Name: d.network.Name})
		}
		d.settings.Trusted, d.override, d.lastErr = trusted, false, ""
		d.save()
		d.applyLocked(false)
	default:
		d.lastErr = "unknown command " + req.Cmd
	}
	return d.statusLocked()
}

func (d *Daemon) statusLocked() Status {
	s := Status{
		Version: d.version, State: d.state, Error: d.lastErr, HasKey: d.key != nil,
		KillSwitch: d.settings.KillSwitch, HTTPS: d.settings.HTTPS, AllowLAN: d.settings.AllowLAN,
	}
	if d.key != nil {
		s.Name, s.Server = d.key.Name, d.key.Host
	}
	s.Network, s.NetworkTrusted = d.network.Name, d.trustedLocked()
	if d.state == StateOn && d.client != nil {
		st := d.client.Stats()
		if !st.ConnectedAt.IsZero() {
			s.ConnectedSince = st.ConnectedAt.Unix()
		}
		s.RxBytes, s.TxBytes, s.RTTMillis = st.RxBytes, st.TxBytes, st.RTT.Milliseconds()
	}
	return s
}

// trustedLocked reports whether the current network is trusted.
func (d *Daemon) trustedLocked() bool {
	for _, n := range d.settings.Trusted {
		if d.network.ID != "" && n.ID == d.network.ID {
			return true
		}
	}
	return false
}

// applyLocked brings the tunnel in line with the settings: connected while
// the VPN is on, except on a trusted network (unless turned on by hand
// there). With restart, a running tunnel is restarted to pick up changed
// settings. d.mu must be held.
func (d *Daemon) applyLocked(restart bool) {
	on := d.settings.On && d.key != nil
	want := on && (d.override || !d.trustedLocked())
	if restart || !want {
		d.stopLocked()
	}
	if want && d.cancel == nil {
		d.startLocked()
	}
	if !want {
		if on {
			d.state = StatePaused
		} else {
			d.state = StateOff
		}
	}
}

// checkNetwork looks at which network this machine is on and, when it has
// changed, pauses or resumes the VPN for trusted networks.
func (d *Daemon) checkNetwork() {
	n, err := d.currentNetwork()
	if err != nil {
		return // unknown for now (e.g. between networks); keep things as they are
	}
	d.op.Lock()
	defer d.op.Unlock()
	d.mu.Lock()
	defer d.mu.Unlock()
	if n.ID == d.network.ID {
		return
	}
	log.Printf("network is now %s", n.Name)
	d.network, d.override = n, false
	d.applyLocked(false)
}

// startLocked connects in the background, retrying if the tunnel fails
// until the VPN is turned off. d.mu must be held.
func (d *Daemon) startLocked() {
	cfg, err := d.key.Client(d.settings.HTTPS, d.settings.KillSwitch, d.settings.AllowLAN)
	if err != nil {
		d.lastErr = err.Error()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	d.cancel, d.done, d.state, d.lastErr = cancel, done, StateConnecting, ""
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			err := d.runTunnel(ctx, cfg, func(s tunnel.State, c *vpn.Client) {
				d.mu.Lock()
				defer d.mu.Unlock()
				if ctx.Err() != nil {
					return
				}
				d.client = c
				if s == tunnel.Connected {
					d.state, d.lastErr = StateOn, ""
				} else {
					d.state = StateConnecting
				}
			})
			if ctx.Err() != nil {
				return
			}
			if err == nil {
				err = errors.New("connection closed")
			}
			log.Printf("tunnel: %v (retrying in 5s)", err)
			d.mu.Lock()
			d.state, d.lastErr = StateConnecting, err.Error()
			d.mu.Unlock()
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
			}
		}
	}()
}

// stopLocked disconnects and waits until the system is back to normal.
// d.mu must be held; it is released while waiting.
func (d *Daemon) stopLocked() {
	if d.cancel == nil {
		return
	}
	cancel, done := d.cancel, d.done
	d.cancel, d.done = nil, nil
	cancel()
	d.mu.Unlock()
	<-done
	d.mu.Lock()
	d.state, d.client = StateOff, nil
}

func (d *Daemon) load() {
	if data, err := os.ReadFile(filepath.Join(d.dir, "key")); err == nil {
		if k, err := accesskey.Parse(string(data)); err == nil {
			d.key = k
		} else {
			log.Printf("saved access key: %v", err)
		}
	}
	if data, err := os.ReadFile(filepath.Join(d.dir, "settings.json")); err == nil {
		json.Unmarshal(data, &d.settings)
	}
}

func (d *Daemon) save() {
	data, _ := json.Marshal(d.settings)
	if err := os.WriteFile(filepath.Join(d.dir, "settings.json"), data, 0o600); err != nil {
		log.Printf("saving settings: %v", err)
	}
}

// Call sends one request to the running service.
func Call(req Request) (*Status, error) {
	conn, err := net.DialTimeout("unix", SocketPath, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// Turning off waits for routes and DNS to be restored, which can take
	// a few seconds.
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}
	var s Status
	if err := json.NewDecoder(conn).Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
}
