// Package registry adds and removes devices in server.json. `vpn invite`,
// `vpn revoke`, `vpn guests` and the running server's guest key endpoint
// and expiry sweep all go through it, so they apply the same rules and never
// overwrite each other's changes.
package registry

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sync"
	"time"

	"github.com/vhittuvalli/vpn/internal/accesskey"
	"github.com/vhittuvalli/vpn/internal/config"
	"github.com/vhittuvalli/vpn/internal/protocol"
)

var (
	ErrNameTaken      = errors.New("a device with that name already exists")
	ErrNoAddress      = errors.New("no free tunnel addresses left")
	ErrGuestsDisabled = errors.New("guest access is turned off")
	ErrGuestsFull     = errors.New("all guest slots are in use")
)

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)

// Registry edits one server.json.
type Registry struct {
	Path string
}

// One writer at a time within this process; the file lock covers other
// processes.
var mu sync.Mutex

// update reads server.json, lets fn change it, and writes it back
// atomically, all under the lock. Nothing is written if fn fails.
func (r Registry) update(fn func(f *config.ServerFile) error) error {
	mu.Lock()
	defer mu.Unlock()
	unlock, err := lockFile(r.Path + ".lock")
	if err != nil {
		return fmt.Errorf("locking %s: %w", r.Path, err)
	}
	defer unlock()
	f, err := config.ReadServerFile(r.Path)
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		return err
	}
	return f.Write(r.Path)
}

// Added is a newly created device.
type Added struct {
	Peer config.PeerFile
	Key  *accesskey.Key
}

// AddDevice adds a regular device with a fresh key.
func (r Registry) AddDevice(name string) (*Added, error) {
	if !nameRE.MatchString(name) {
		return nil, fmt.Errorf("%q isn't a usable name: use up to 32 letters, digits, dots, dashes or underscores", name)
	}
	var added *Added
	err := r.update(func(f *config.ServerFile) error {
		for _, p := range f.Peers {
			if p.Name == name {
				return fmt.Errorf("%w: %q (remove it first with: sudo vpn revoke %s)", ErrNameTaken, name, name)
			}
		}
		g, err := f.GuestSettings()
		if err != nil {
			return err
		}
		var a error
		added, a = addPeer(f, config.PeerFile{Name: name}, g.Pool, false)
		return a
	})
	return added, err
}

// AddGuest adds a guest that expires after the configured TTL and may use
// the configured quota. It refuses when guests are off or all slots are
// taken; expired guests waiting for the sweep don't count.
func (r Registry) AddGuest(now time.Time) (*Added, error) {
	var added *Added
	err := r.update(func(f *config.ServerFile) error {
		g, err := f.GuestSettings()
		if err != nil {
			return err
		}
		if !g.Enabled {
			return ErrGuestsDisabled
		}
		if ActiveGuests(f, now) >= g.MaxActive {
			return ErrGuestsFull
		}
		name, err := guestName(f)
		if err != nil {
			return err
		}
		p := config.PeerFile{
			Name: name, Guest: true, QuotaBytes: g.QuotaBytes,
			ExpiresAt: now.Add(g.TTL).UTC().Format(time.RFC3339),
		}
		added, err = addPeer(f, p, g.Pool, true)
		return err
	})
	return added, err
}

// Remove deletes the named devices and reports which existed.
func (r Registry) Remove(names ...string) ([]string, error) {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	return r.RemoveIf(func(p config.PeerFile) bool { return want[p.Name] })
}

// RemoveIf deletes every device match accepts and returns their names.
func (r Registry) RemoveIf(match func(config.PeerFile) bool) ([]string, error) {
	var removed []string
	err := r.update(func(f *config.ServerFile) error {
		kept := f.Peers[:0]
		for _, p := range f.Peers {
			if match(p) {
				removed = append(removed, p.Name)
			} else {
				kept = append(kept, p)
			}
		}
		f.Peers = kept
		return nil
	})
	return removed, err
}

// RemoveExpiredGuests deletes guests whose time is up.
func (r Registry) RemoveExpiredGuests(now time.Time) ([]string, error) {
	return r.RemoveIf(func(p config.PeerFile) bool { return p.Guest && guestExpired(p, now) })
}

// SweepGuests deletes guests that have expired, plus the named ones (guests
// the running server has cut off for using up their data).
func (r Registry) SweepGuests(now time.Time, overLimit []string) ([]string, error) {
	over := map[string]bool{}
	for _, n := range overLimit {
		over[n] = true
	}
	return r.RemoveIf(func(p config.PeerFile) bool { return p.Guest && (guestExpired(p, now) || over[p.Name]) })
}

// GuestCount reports whether guest access is on, how many guests are active
// and how many may be.
func (r Registry) GuestCount(now time.Time) (enabled bool, active, max int, err error) {
	f, err := config.ReadServerFile(r.Path)
	if err != nil {
		return false, 0, 0, err
	}
	g, err := f.GuestSettings()
	if err != nil {
		return false, 0, 0, err
	}
	return g.Enabled, ActiveGuests(f, now), g.MaxActive, nil
}

// SetGuestsEnabled turns guest key issuing on or off.
func (r Registry) SetGuestsEnabled(on bool) error {
	return r.update(func(f *config.ServerFile) error {
		if f.Guests == nil {
			f.Guests = &config.GuestFile{}
		}
		f.Guests.Enabled = on
		_, err := f.GuestSettings()
		return err
	})
}

// ActiveGuests counts guests that haven't expired.
func ActiveGuests(f *config.ServerFile, now time.Time) int {
	n := 0
	for _, p := range f.Peers {
		if p.Guest && !guestExpired(p, now) {
			n++
		}
	}
	return n
}

func guestExpired(p config.PeerFile, now time.Time) bool {
	t, err := time.Parse(time.RFC3339, p.ExpiresAt)
	return err != nil || !now.Before(t)
}

// addPeer gives p a fresh key and a free address and appends it to f.
// Guests get addresses from the guest pool; regular devices stay out of it.
func addPeer(f *config.ServerFile, p config.PeerFile, pool netip.Prefix, guest bool) (*Added, error) {
	if f.Endpoint == "" {
		return nil, errors.New(`server.json has no "endpoint": add "endpoint": "<this server's public IP>" to it`)
	}
	serverKey, err := protocol.ParsePrivateKey(f.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("server.json: private_key: %w", err)
	}
	subnet, err := netip.ParsePrefix(f.Address)
	if err != nil {
		return nil, fmt.Errorf("server.json: address: %w", err)
	}
	used := map[netip.Addr]bool{subnet.Addr(): true}
	for _, existing := range f.Peers {
		if a, err := netip.ParseAddr(existing.Address); err == nil {
			used[a] = true
		}
	}
	addr := netip.Addr{}
	for a := subnet.Masked().Addr().Next(); subnet.Contains(a.Next()); a = a.Next() { // skip network and broadcast
		inPool := pool.IsValid() && pool.Contains(a)
		if !used[a] && inPool == guest {
			addr = a
			break
		}
	}
	if !addr.IsValid() {
		if guest {
			return nil, fmt.Errorf("%w in the guest range %s", ErrNoAddress, pool)
		}
		return nil, fmt.Errorf("%w in %s", ErrNoAddress, subnet.Masked())
	}

	device, err := protocol.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	p.PublicKey, p.Address = device.Public().String(), addr.String()
	f.Peers = append(f.Peers, p)

	udp := f.ListenPort
	if udp == 0 {
		udp = config.DefaultUDPPort
	}
	return &Added{Peer: p, Key: &accesskey.Key{
		Name: p.Name, Host: f.Endpoint, UDPPort: udp, HTTPSPort: f.HTTPSPort,
		ServerPublicKey: serverKey.Public(), PrivateKey: device,
		Address: netip.PrefixFrom(addr, subnet.Bits()),
	}}, nil
}

// guestName picks an unused "guest-" plus 6 random letters and digits.
func guestName(f *config.ServerFile) (string, error) {
	const alphabet = "abcdefghijkmnpqrstuvwxyz23456789" // no look-alikes
	taken := map[string]bool{}
	for _, p := range f.Peers {
		taken[p.Name] = true
	}
	for range 100 {
		b := make([]byte, 6)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		for i := range b {
			b[i] = alphabet[int(b[i])%len(alphabet)]
		}
		if name := "guest-" + string(b); !taken[name] {
			return name, nil
		}
	}
	return "", errors.New("couldn't pick a unique guest name")
}
