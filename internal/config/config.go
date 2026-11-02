// Package config loads and validates the server and client JSON configs.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/vhittuvalli/vpn/internal/protocol"
)

const (
	DefaultUDPPort = 51820
	DefaultMTU     = 1420 // 1500 minus IPv4 (20), UDP (8), our header (16) and tag (16), rounded down
	HTTPSMTU       = 1150 // QUIC and HTTP/3 framing take more room
)

type Server struct {
	PrivateKey   protocol.PrivateKey
	ListenPort   int    // UDP transport
	HTTPSPort    int    // HTTP/3 transport; 0 disables it
	ServerName   string // name in the self-signed certificate
	TLSCert      string // optional real certificate (PEM files)
	TLSKey       string
	Address      netip.Prefix // server's tunnel address, e.g. 10.8.0.1/24
	MTU          int
	NATInterface string // if set, share this interface's internet connection with clients
	Endpoint     string // public IP or hostname clients connect to; goes into access keys
	Peers        []Peer
	Guests       Guests
}

type Peer struct {
	Name      string
	PublicKey protocol.PublicKey
	Address   netip.Addr // the one tunnel address this peer may use

	// Guests are temporary peers handed out by the guest key endpoint. They
	// stop working at ExpiresAt or once they have used QuotaBytes (0: no
	// quota), whichever comes first.
	Guest      bool
	ExpiresAt  time.Time
	QuotaBytes uint64
}

// Guests configures self-serve guest access. It is off unless enabled.
type Guests struct {
	Enabled        bool
	TTL            time.Duration // how long a guest key works
	QuotaBytes     uint64        // data allowance per guest, both directions together
	MaxActive      int           // guests that may exist at once
	PerIPPerDay    int           // keys one client IP may get in 24 hours
	RateLimitMbps  float64       // per-guest bandwidth cap; 0 means none
	Hostname       string        // public name of the key endpoint, for its TLS certificate
	AllowedOrigins []string      // web pages allowed to call the endpoint (CORS)
	Pool           netip.Prefix  // tunnel addresses reserved for guests
}

// Guest access defaults.
const (
	DefaultGuestTTL         = time.Hour
	DefaultGuestQuota       = 500_000_000 // 500 MB
	DefaultGuestMaxActive   = 20
	DefaultGuestPerIPPerDay = 3
	DefaultGuestRateMbps    = 5
)

var DefaultGuestOrigins = []string{"https://vhittuvalli.github.io"}

// GuestPool is the upper half of the tunnel subnet, which guests get their
// addresses from (10.8.0.128/25 for 10.8.0.1/24). Keeping guests in one range
// lets the server firewall them with a single rule. ok is false when the
// subnet is too small to split.
func GuestPool(subnet netip.Prefix) (pool netip.Prefix, ok bool) {
	if !subnet.Addr().Is4() || subnet.Bits() > 29 {
		return netip.Prefix{}, false
	}
	b := subnet.Masked().Addr().As4()
	start := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	start += uint32(1) << (32 - subnet.Bits() - 1)
	upper := netip.AddrFrom4([4]byte{byte(start >> 24), byte(start >> 16), byte(start >> 8), byte(start)})
	return netip.PrefixFrom(upper, subnet.Bits()+1), true
}

type Client struct {
	PrivateKey      protocol.PrivateKey
	Address         netip.Prefix // client's tunnel address, e.g. 10.8.0.2/24
	Server          string       // host:port
	ServerPublicKey protocol.PublicKey
	Transport       string // "udp" or "https"
	ServerName      string // TLS server name for the https transport
	MTU             int
	RouteAllTraffic bool
	KillSwitch      bool
	AllowLAN        bool // with the kill switch, still allow the local network
	DNS             []netip.Addr
}

// ServerFile is server.json as stored on disk. `vpn invite` and `vpn revoke`
// edit it and write it back; everything else uses the validated Server.
type ServerFile struct {
	PrivateKey   string     `json:"private_key"`
	Endpoint     string     `json:"endpoint,omitempty"`
	ListenPort   int        `json:"listen_port,omitempty"`
	HTTPSPort    int        `json:"https_port,omitempty"`
	ServerName   string     `json:"server_name,omitempty"`
	TLSCert      string     `json:"tls_cert,omitempty"`
	TLSKey       string     `json:"tls_key,omitempty"`
	Address      string     `json:"address"`
	MTU          int        `json:"mtu,omitempty"`
	NATInterface string     `json:"nat_interface,omitempty"`
	Guests       *GuestFile `json:"guests,omitempty"`
	Peers        []PeerFile `json:"peers"`
}

type PeerFile struct {
	Name       string `json:"name"`
	PublicKey  string `json:"public_key"`
	Address    string `json:"address"`
	Guest      bool   `json:"guest,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"` // RFC 3339
	QuotaBytes uint64 `json:"quota_bytes,omitempty"`
}

// GuestFile is the "guests" section of server.json. Missing fields take the
// defaults above.
type GuestFile struct {
	Enabled         bool     `json:"enabled"`
	TTL             string   `json:"ttl,omitempty"` // e.g. "1h", "30m"
	QuotaBytes      uint64   `json:"quota_bytes,omitempty"`
	MaxActiveGuests int      `json:"max_active_guests,omitempty"`
	PerIPPerDay     int      `json:"per_ip_per_day,omitempty"`
	RateLimitMbps   float64  `json:"rate_limit_mbps,omitempty"`
	GuestHostname   string   `json:"guest_hostname,omitempty"`
	AllowedOrigins  []string `json:"allowed_origins,omitempty"`
}

// ReadServerFile reads server.json without validating it.
func ReadServerFile(path string) (*ServerFile, error) {
	var f ServerFile
	if err := decode(path, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

// Write saves f to path atomically, readable only by its owner (it holds the
// server's private key).
func (f *ServerFile) Write(path string) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type clientFile struct {
	PrivateKey      string   `json:"private_key"`
	Address         string   `json:"address"`
	Server          string   `json:"server"`
	ServerPublicKey string   `json:"server_public_key"`
	Transport       string   `json:"transport"`
	ServerName      string   `json:"server_name"`
	MTU             int      `json:"mtu"`
	RouteAllTraffic bool     `json:"route_all_traffic"`
	KillSwitch      bool     `json:"kill_switch"`
	AllowLAN        bool     `json:"allow_lan,omitempty"`
	DNS             []string `json:"dns"`
}

func decode(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func LoadServer(path string) (*Server, error) {
	var f ServerFile
	if err := decode(path, &f); err != nil {
		return nil, err
	}
	var errs []error
	s := &Server{
		ListenPort: f.ListenPort, HTTPSPort: f.HTTPSPort, ServerName: f.ServerName,
		TLSCert: f.TLSCert, TLSKey: f.TLSKey, MTU: f.MTU, NATInterface: f.NATInterface,
		Endpoint: f.Endpoint,
	}
	if s.ListenPort == 0 {
		s.ListenPort = DefaultUDPPort
	}
	if s.ServerName == "" {
		s.ServerName = "localhost"
	}
	if s.MTU == 0 {
		s.MTU = DefaultMTU
	}
	if (s.TLSCert == "") != (s.TLSKey == "") {
		errs = append(errs, errors.New("tls_cert and tls_key must be set together"))
	}
	var err error
	if s.PrivateKey, err = protocol.ParsePrivateKey(f.PrivateKey); err != nil {
		errs = append(errs, fmt.Errorf("private_key: %w", err))
	}
	if s.Address, err = parseIPv4Prefix(f.Address); err != nil {
		errs = append(errs, fmt.Errorf("address: %w", err))
	}
	seenKey := map[protocol.PublicKey]bool{}
	seenAddr := map[netip.Addr]bool{s.Address.Addr(): true}
	for i, fp := range f.Peers {
		p := Peer{Name: fp.Name}
		if p.Name == "" {
			p.Name = fmt.Sprintf("peer%d", i+1)
		}
		if p.PublicKey, err = protocol.ParsePublicKey(fp.PublicKey); err != nil {
			errs = append(errs, fmt.Errorf("peer %s: public_key: %w (run 'vpn pubkey' on the peer)", p.Name, err))
		} else if seenKey[p.PublicKey] {
			errs = append(errs, fmt.Errorf("peer %s: duplicate public_key", p.Name))
		}
		if p.Address, err = netip.ParseAddr(fp.Address); err != nil || !p.Address.Is4() {
			errs = append(errs, fmt.Errorf("peer %s: address must be an IPv4 address like 10.8.0.2", p.Name))
		} else if !s.Address.Contains(p.Address) {
			errs = append(errs, fmt.Errorf("peer %s: address %s is outside %s", p.Name, p.Address, s.Address.Masked()))
		} else if seenAddr[p.Address] {
			errs = append(errs, fmt.Errorf("peer %s: address %s is already in use", p.Name, p.Address))
		}
		seenKey[p.PublicKey], seenAddr[p.Address] = true, true
		if fp.Guest {
			p.Guest, p.QuotaBytes = true, fp.QuotaBytes
			if p.ExpiresAt, err = time.Parse(time.RFC3339, fp.ExpiresAt); err != nil {
				errs = append(errs, fmt.Errorf("peer %s: expires_at must be an RFC 3339 time like 2026-11-02T15:04:05Z", p.Name))
			}
		}
		s.Peers = append(s.Peers, p)
	}
	var gerrs []error
	s.Guests, gerrs = loadGuests(f.Guests, s.Address, s.Endpoint)
	errs = append(errs, gerrs...)
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// loadGuests fills in guest settings, with defaults for anything unset.
func loadGuests(f *GuestFile, subnet netip.Prefix, endpoint string) (Guests, []error) {
	g := Guests{
		TTL: DefaultGuestTTL, QuotaBytes: DefaultGuestQuota, MaxActive: DefaultGuestMaxActive,
		PerIPPerDay: DefaultGuestPerIPPerDay, RateLimitMbps: DefaultGuestRateMbps,
		AllowedOrigins: DefaultGuestOrigins,
	}
	// By default the endpoint's TLS name is <ip>.sslip.io, which resolves to
	// the server without any DNS setup.
	if ip, err := netip.ParseAddr(endpoint); err == nil && ip.Is4() {
		g.Hostname = ip.String() + ".sslip.io"
	}
	if pool, ok := GuestPool(subnet); ok {
		g.Pool = pool
	}
	if f == nil {
		return g, nil
	}
	var errs []error
	g.Enabled = f.Enabled
	if f.TTL != "" {
		d, err := time.ParseDuration(f.TTL)
		if err != nil || d <= 0 {
			errs = append(errs, fmt.Errorf("guests.ttl: want a duration like \"1h\" or \"30m\", got %q", f.TTL))
		}
		g.TTL = d
	}
	if f.QuotaBytes != 0 {
		g.QuotaBytes = f.QuotaBytes
	}
	if f.MaxActiveGuests != 0 {
		g.MaxActive = f.MaxActiveGuests
	}
	if f.PerIPPerDay != 0 {
		g.PerIPPerDay = f.PerIPPerDay
	}
	if f.RateLimitMbps != 0 {
		g.RateLimitMbps = f.RateLimitMbps
	}
	if f.GuestHostname != "" {
		g.Hostname = f.GuestHostname
	}
	if len(f.AllowedOrigins) > 0 {
		g.AllowedOrigins = f.AllowedOrigins
	}
	if g.MaxActive < 0 || g.PerIPPerDay < 0 || g.RateLimitMbps < 0 {
		errs = append(errs, errors.New("guests: limits can't be negative"))
	}
	if g.Enabled {
		if g.Hostname == "" {
			errs = append(errs, errors.New("guests.guest_hostname: required when guests are enabled (the endpoint's public name, for its certificate)"))
		}
		if !g.Pool.IsValid() {
			errs = append(errs, fmt.Errorf("guests: the tunnel subnet %s is too small to set aside addresses for guests", subnet.Masked()))
		}
	}
	return g, errs
}

func LoadClient(path string) (*Client, error) {
	var f clientFile
	if err := decode(path, &f); err != nil {
		return nil, err
	}
	var errs []error
	c := &Client{
		Server: f.Server, Transport: f.Transport, ServerName: f.ServerName, MTU: f.MTU,
		RouteAllTraffic: f.RouteAllTraffic, KillSwitch: f.KillSwitch, AllowLAN: f.AllowLAN,
	}
	switch c.Transport {
	case "", "udp":
		c.Transport = "udp"
		if c.MTU == 0 {
			c.MTU = DefaultMTU
		}
	case "https":
		if c.MTU == 0 {
			c.MTU = HTTPSMTU
		}
		if c.MTU > HTTPSMTU {
			errs = append(errs, fmt.Errorf("mtu: at most %d with the https transport", HTTPSMTU))
		}
		if c.ServerName == "" {
			if host, _, err := net.SplitHostPort(c.Server); err == nil {
				c.ServerName = host
			}
		}
	default:
		errs = append(errs, fmt.Errorf("transport: want \"udp\" or \"https\", got %q", c.Transport))
	}
	var err error
	if c.PrivateKey, err = protocol.ParsePrivateKey(f.PrivateKey); err != nil {
		errs = append(errs, fmt.Errorf("private_key: %w", err))
	}
	if c.ServerPublicKey, err = protocol.ParsePublicKey(f.ServerPublicKey); err != nil {
		errs = append(errs, fmt.Errorf("server_public_key: %w (run 'vpn pubkey' on the server)", err))
	}
	if c.Address, err = parseIPv4Prefix(f.Address); err != nil {
		errs = append(errs, fmt.Errorf("address: %w", err))
	}
	if c.Server == "" {
		errs = append(errs, errors.New("server: required, e.g. \"203.0.113.10:51820\""))
	}
	if c.KillSwitch && !c.RouteAllTraffic {
		errs = append(errs, errors.New("kill_switch needs route_all_traffic: otherwise it would block all non-VPN traffic"))
	}
	for _, d := range f.DNS {
		a, err := netip.ParseAddr(d)
		if err != nil || !a.Is4() {
			errs = append(errs, fmt.Errorf("dns: %q is not an IPv4 address", d))
			continue
		}
		c.DNS = append(c.DNS, a)
	}
	if len(c.DNS) > 0 && !c.RouteAllTraffic {
		errs = append(errs, errors.New("dns needs route_all_traffic, so lookups go through the tunnel"))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

func parseIPv4Prefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("want an IPv4 address with prefix length, like 10.8.0.1/24, got %q", s)
	}
	return p, nil
}
