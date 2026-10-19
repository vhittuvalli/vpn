// Package accesskey encodes everything a device needs to connect into one
// string that can be pasted or scanned:
//
//	vpn://<base64url JSON>
//
// `vpn invite` on the server makes one for each device. The key contains the
// device's private key, so it is a secret: anyone holding it can connect as
// that device until it is revoked with `vpn revoke`.
package accesskey

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/vhittuvalli/vpn/internal/config"
	"github.com/vhittuvalli/vpn/internal/protocol"
)

const scheme = "vpn://"

// Key is a decoded access key.
type Key struct {
	Name            string              // the device's name on the server, for display
	Host            string              // server IP or hostname
	UDPPort         int                 // 0 if the server has no UDP transport
	HTTPSPort       int                 // 0 if the server has no HTTPS transport
	ServerPublicKey protocol.PublicKey  //
	PrivateKey      protocol.PrivateKey // this device's key
	Address         netip.Prefix        // this device's tunnel address, e.g. 10.8.0.2/24
}

type wire struct {
	V int    `json:"v"`
	N string `json:"n,omitempty"`
	H string `json:"h"`
	U int    `json:"u,omitempty"`
	T int    `json:"t,omitempty"`
	S string `json:"s"`
	K string `json:"k"`
	A string `json:"a"`
}

// String encodes k as a vpn:// access key.
func (k *Key) String() string {
	data, _ := json.Marshal(wire{
		V: 1, N: k.Name, H: k.Host, U: k.UDPPort, T: k.HTTPSPort,
		S: k.ServerPublicKey.String(), K: k.PrivateKey.String(), A: k.Address.String(),
	})
	return scheme + base64.RawURLEncoding.EncodeToString(data)
}

// Parse decodes an access key. Surrounding whitespace and line breaks (from
// copying out of a terminal or chat) are ignored.
func Parse(s string) (*Key, error) {
	s = strings.Join(strings.Fields(s), "")
	body, ok := strings.CutPrefix(s, scheme)
	if !ok {
		return nil, errors.New("an access key starts with vpn://")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(body, "="))
	if err != nil {
		return nil, errors.New("this access key is damaged; copy it again in full")
	}
	var w wire
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, errors.New("this access key is damaged; copy it again in full")
	}
	if w.V != 1 {
		return nil, fmt.Errorf("this access key is for a newer version of vpn (format %d); update the app", w.V)
	}
	k := &Key{Name: w.N, Host: w.H, UDPPort: w.U, HTTPSPort: w.T}
	if k.Host == "" || (k.UDPPort == 0 && k.HTTPSPort == 0) {
		return nil, errors.New("this access key has no server address")
	}
	if k.ServerPublicKey, err = protocol.ParsePublicKey(w.S); err != nil {
		return nil, errors.New("this access key has an invalid server key")
	}
	if k.PrivateKey, err = protocol.ParsePrivateKey(w.K); err != nil {
		return nil, errors.New("this access key has an invalid device key")
	}
	if k.Address, err = netip.ParsePrefix(w.A); err != nil || !k.Address.Addr().Is4() {
		return nil, errors.New("this access key has an invalid tunnel address")
	}
	return k, nil
}

// Client builds a client config from the key. With https, the tunnel runs
// over HTTP/3 on the server's HTTPS port; otherwise over UDP. Both send all
// traffic and DNS through the VPN. allowLAN keeps the local network
// reachable through the kill switch.
func (k *Key) Client(https, killSwitch, allowLAN bool) (*config.Client, error) {
	c := &config.Client{
		PrivateKey:      k.PrivateKey,
		Address:         k.Address,
		ServerPublicKey: k.ServerPublicKey,
		RouteAllTraffic: true,
		KillSwitch:      killSwitch,
		AllowLAN:        allowLAN,
		DNS:             []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("9.9.9.9")},
	}
	switch {
	case https && k.HTTPSPort != 0:
		c.Transport, c.MTU, c.ServerName = "https", config.HTTPSMTU, k.Host
		c.Server = net.JoinHostPort(k.Host, strconv.Itoa(k.HTTPSPort))
	case !https && k.UDPPort != 0:
		c.Transport, c.MTU = "udp", config.DefaultMTU
		c.Server = net.JoinHostPort(k.Host, strconv.Itoa(k.UDPPort))
	case https:
		return nil, errors.New("this server doesn't offer the HTTPS disguise")
	default:
		return nil, errors.New("this server only accepts the HTTPS transport")
	}
	return c, nil
}
