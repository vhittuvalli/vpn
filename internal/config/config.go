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
	Peers        []Peer
}

type Peer struct {
	Name      string
	PublicKey protocol.PublicKey
	Address   netip.Addr // the one tunnel address this peer may use
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
	DNS             []netip.Addr
}

type serverFile struct {
	PrivateKey   string `json:"private_key"`
	ListenPort   int    `json:"listen_port"`
	HTTPSPort    int    `json:"https_port"`
	ServerName   string `json:"server_name"`
	TLSCert      string `json:"tls_cert"`
	TLSKey       string `json:"tls_key"`
	Address      string `json:"address"`
	MTU          int    `json:"mtu"`
	NATInterface string `json:"nat_interface"`
	Peers        []struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
		Address   string `json:"address"`
	} `json:"peers"`
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
	var f serverFile
	if err := decode(path, &f); err != nil {
		return nil, err
	}
	var errs []error
	s := &Server{
		ListenPort: f.ListenPort, HTTPSPort: f.HTTPSPort, ServerName: f.ServerName,
		TLSCert: f.TLSCert, TLSKey: f.TLSKey, MTU: f.MTU, NATInterface: f.NATInterface,
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
	if len(f.Peers) == 0 {
		errs = append(errs, errors.New("peers: at least one peer is required"))
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
		s.Peers = append(s.Peers, p)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

func LoadClient(path string) (*Client, error) {
	var f clientFile
	if err := decode(path, &f); err != nil {
		return nil, err
	}
	var errs []error
	c := &Client{
		Server: f.Server, Transport: f.Transport, ServerName: f.ServerName, MTU: f.MTU,
		RouteAllTraffic: f.RouteAllTraffic, KillSwitch: f.KillSwitch,
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
