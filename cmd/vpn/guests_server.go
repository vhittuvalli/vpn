package main

import (
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/vhittuvalli/vpn/internal/config"
	"github.com/vhittuvalli/vpn/internal/guestapi"
	"github.com/vhittuvalli/vpn/internal/registry"
	"github.com/vhittuvalli/vpn/internal/vpn"
)

// guestSweepInterval is how often expired and over-quota guests are removed
// from server.json. Between sweeps the server already drops their packets.
const guestSweepInterval = time.Minute

// serverState keeps the running server, its guest key endpoint and
// server.json in step. Reloads come from SIGHUP (`vpn invite`, `vpn revoke`,
// `vpn guests`), from newly issued guest keys and from the sweep.
type serverState struct {
	path string
	srv  *vpn.Server
	reg  registry.Registry

	mu       sync.Mutex
	guests   config.Guests
	endpoint *guestapi.Listener
	handler  *guestapi.Handler
}

func newServerState(path string, srv *vpn.Server, cfg *config.Server) *serverState {
	st := &serverState{path: path, srv: srv, reg: registry.Registry{Path: path}}
	st.handler = &guestapi.Handler{
		Registry: st.reg,
		Settings: st.guestSettings,
		OnIssue:  func() { st.reload("new guest") },
		LogPath:  filepath.Join(filepath.Dir(path), "guest-keys.log"),
	}
	st.applyGuests(cfg.Guests)
	return st
}

func (st *serverState) guestSettings() config.Guests {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.guests
}

// reload re-reads server.json and applies it without dropping anyone else.
func (st *serverState) reload(why string) {
	next, err := config.LoadServer(st.path)
	if err != nil {
		log.Printf("reload (%s): %v (keeping the current devices)", why, err)
		return
	}
	st.srv.SetGuestRate(next.Guests.RateLimitMbps)
	added, removed := st.srv.SetPeers(next.Peers)
	log.Printf("reloaded devices (%s): %d total, %d added, %d removed", why, len(next.Peers), added, removed)
	st.applyGuests(next.Guests)
}

// applyGuests starts or stops the key endpoint to match the settings.
func (st *serverState) applyGuests(g config.Guests) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.guests = g
	if st.endpoint != nil && (!g.Enabled || st.endpoint.Hostname != g.Hostname) {
		st.endpoint.Close() // frees TCP 443 right away
		st.endpoint = nil
		log.Print("guest key endpoint stopped")
	}
	if g.Enabled && st.endpoint == nil {
		l, err := guestapi.Listen(":443", g.Hostname, filepath.Join(filepath.Dir(st.path), "autocert"), st.handler)
		if err != nil {
			log.Printf("guest key endpoint: %v", err)
			return
		}
		st.endpoint = l
	}
}

// sweep removes guests whose time or data has run out.
func (st *serverState) sweep(now time.Time) {
	removed, err := st.reg.SweepGuests(now, st.srv.GuestsOverLimit(now))
	if err != nil {
		log.Printf("guest sweep: %v", err)
		return
	}
	if len(removed) > 0 {
		log.Printf("guest sweep removed %v", removed)
		st.reload("guest sweep")
	}
}

func (st *serverState) close() {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.endpoint != nil {
		st.endpoint.Close()
		st.endpoint = nil
	}
}
