// Package config loads and validates the server and client JSON configs.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"

	"github.com/vhittuvalli/vpn/internal/protocol"
)

const DefaultMTU = 1420 // 1500 minus IPv4 (20), UDP (8), our header (16) and tag (16), rounded down

type Server struct {
	PrivateKey   protocol.Key
	ListenPort   int
	Address      netip.Prefix // server's tunnel address, e.g. 10.8.0.1/24
	MTU          int
	NATInterface string // if set, share this interface's internet connection with clients
	Peers        []Peer
}

type Peer struct {
	Name      string
	PublicKey protocol.Key
	Address   netip.Addr // the one tunnel address this peer may use
}

type Client struct {
	PrivateKey      protocol.Key
	Address         netip.Prefix // client's tunnel address, e.g. 10.8.0.2/24
	Server          string       // host:port
	ServerPublicKey protocol.Key
	MTU             int
	RouteAllTraffic bool
}

type serverFile struct {
	PrivateKey   string `json:"private_key"`
	ListenPort   int    `json:"listen_port"`
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
	PrivateKey      string `json:"private_key"`
	Address         string `json:"address"`
	Server          string `json:"server"`
	ServerPublicKey string `json:"server_public_key"`
	MTU             int    `json:"mtu"`
	RouteAllTraffic bool   `json:"route_all_traffic"`
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
	s := &Server{ListenPort: f.ListenPort, MTU: f.MTU, NATInterface: f.NATInterface}
	if s.ListenPort == 0 {
		s.ListenPort = 51820
	}
	if s.MTU == 0 {
		s.MTU = DefaultMTU
	}
	var err error
	if s.PrivateKey, err = protocol.ParseKey(f.PrivateKey); err != nil {
		errs = append(errs, fmt.Errorf("private_key: %w", err))
	}
	if s.Address, err = parseIPv4Prefix(f.Address); err != nil {
		errs = append(errs, fmt.Errorf("address: %w", err))
	}
	if len(f.Peers) == 0 {
		errs = append(errs, errors.New("peers: at least one peer is required"))
	}
	seenKey := map[protocol.Key]bool{}
	seenAddr := map[netip.Addr]bool{s.Address.Addr(): true}
	for i, fp := range f.Peers {
		p := Peer{Name: fp.Name}
		if p.Name == "" {
			p.Name = fmt.Sprintf("peer%d", i+1)
		}
		if p.PublicKey, err = protocol.ParseKey(fp.PublicKey); err != nil {
			errs = append(errs, fmt.Errorf("peer %s: public_key: %w", p.Name, err))
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
	c := &Client{Server: f.Server, MTU: f.MTU, RouteAllTraffic: f.RouteAllTraffic}
	if c.MTU == 0 {
		c.MTU = DefaultMTU
	}
	var err error
	if c.PrivateKey, err = protocol.ParseKey(f.PrivateKey); err != nil {
		errs = append(errs, fmt.Errorf("private_key: %w", err))
	}
	if c.ServerPublicKey, err = protocol.ParseKey(f.ServerPublicKey); err != nil {
		errs = append(errs, fmt.Errorf("server_public_key: %w", err))
	}
	if c.Address, err = parseIPv4Prefix(f.Address); err != nil {
		errs = append(errs, fmt.Errorf("address: %w", err))
	}
	if c.Server == "" {
		errs = append(errs, errors.New("server: required, e.g. \"203.0.113.10:51820\""))
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
