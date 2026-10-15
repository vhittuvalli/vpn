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
	"github.com/vhittuvalli/vpn/internal/netcfg"
	"github.com/vhittuvalli/vpn/internal/tunnel"
)

const SocketPath = "/var/run/vpn.sock"

// Commands.
const (
	CmdStatus   = "status"
	CmdOn       = "on"
	CmdOff      = "off"
	CmdSetKey   = "set-key"
	CmdSettings = "settings"
)

type Request struct {
	Cmd        string `json:"cmd"`
	Key        string `json:"key,omitempty"`         // CmdSetKey
	KillSwitch *bool  `json:"kill_switch,omitempty"` // CmdSettings
	HTTPS      *bool  `json:"https,omitempty"`       // CmdSettings
}

// Connection states.
const (
	StateOff        = "off"
	StateConnecting = "connecting"
	StateOn         = "on"
)

type Status struct {
	Version    string `json:"version"`
	State      string `json:"state"`
	Error      string `json:"error,omitempty"` // why the last command or connection failed
	HasKey     bool   `json:"has_key"`
	Name       string `json:"name,omitempty"`   // this device's name on the server
	Server     string `json:"server,omitempty"` // server host
	KillSwitch bool   `json:"kill_switch"`
	HTTPS      bool   `json:"https"`
}

// settings survive restarts, so the VPN comes back after a reboot if it
// was on.
type settings struct {
	On         bool `json:"on"`
	KillSwitch bool `json:"kill_switch"`
	HTTPS      bool `json:"https"`
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
	cancel   context.CancelFunc
	done     chan struct{}
}

// Run serves commands until ctx is canceled, then disconnects.
func Run(ctx context.Context, version string, owner int) error {
	d := &Daemon{version: version, owner: owner, dir: stateDir, state: StateOff,
		settings: settings{KillSwitch: true}}
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

	d.mu.Lock()
	if d.settings.On && d.key != nil {
		d.startLocked()
	}
	d.mu.Unlock()

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
		d.save()
		d.stopLocked()
		d.startLocked()
	case CmdOff:
		d.settings.On = false
		d.save()
		d.stopLocked()
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
		if d.settings.On {
			d.stopLocked()
			d.startLocked()
		}
	case CmdSettings:
		if req.KillSwitch != nil {
			d.settings.KillSwitch = *req.KillSwitch
		}
		if req.HTTPS != nil {
			d.settings.HTTPS = *req.HTTPS
		}
		d.save()
		if d.settings.On {
			d.stopLocked()
			d.startLocked()
		}
	default:
		d.lastErr = "unknown command " + req.Cmd
	}
	return d.statusLocked()
}

func (d *Daemon) statusLocked() Status {
	s := Status{
		Version: d.version, State: d.state, Error: d.lastErr, HasKey: d.key != nil,
		KillSwitch: d.settings.KillSwitch, HTTPS: d.settings.HTTPS,
	}
	if d.key != nil {
		s.Name, s.Server = d.key.Name, d.key.Host
	}
	return s
}

// startLocked connects in the background, retrying if the tunnel fails
// until the VPN is turned off. d.mu must be held.
func (d *Daemon) startLocked() {
	cfg, err := d.key.Client(d.settings.HTTPS, d.settings.KillSwitch)
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
			err := tunnel.Run(ctx, cfg, func(s tunnel.State) {
				d.mu.Lock()
				defer d.mu.Unlock()
				if ctx.Err() != nil {
					return
				}
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
	d.state = StateOff
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
