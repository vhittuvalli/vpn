// Package netcfg configures addresses, routes, DNS, the kill switch and NAT:
// by running the OS's own networking commands on macOS (ifconfig, route,
// pf) and Linux (ip, iptables), and through the IP Helper API and Windows
// Filtering Platform on Windows.
package netcfg

import (
	"fmt"
	"log"
	"net/netip"
	"os/exec"
	"strings"
)

// Cleanup undoes a configuration change. It is safe to call once.
type Cleanup func()

func run(name string, args ...string) (string, error) {
	return runInput("", name, args...)
}

func runInput(stdin, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// runAll runs each command in order and returns a Cleanup running undo in
// reverse. If a command fails, the steps already applied are undone.
// LocalNetworks are the destinations "allow local network" lets through the
// kill switch: private ranges, link-local and multicast (printers, AirDrop,
// Chromecast, the router's admin page). The tunnel routes only the default
// route, so the more specific local subnet routes still win.
var (
	LocalNetworks4 = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"}
	LocalNetworks6 = []string{"fe80::/10", "ff00::/8"}
)

func runAll(do, undo [][]string) (Cleanup, error) {
	cleanup := func(n int) {
		for i := n - 1; i >= 0; i-- {
			if undo[i] == nil {
				continue
			}
			if _, err := run(undo[i][0], undo[i][1:]...); err != nil {
				log.Printf("cleanup: %v", err)
			}
		}
	}
	for i, cmd := range do {
		if _, err := run(cmd[0], cmd[1:]...); err != nil {
			cleanup(i)
			return nil, err
		}
	}
	return func() { cleanup(len(do)) }, nil
}

// Route is a routing table entry, reduced to what choosing a path needs.
type Route struct {
	Interface uint64 // OS-specific interface identifier
	Prefix    netip.Prefix
	NextHop   netip.Addr
	Metric    uint32 // route metric plus interface metric
}

// BestDefaultRoute picks the IPv4 default route with the lowest metric,
// ignoring the tunnel's own interface: the path traffic to the VPN server
// must keep using once everything else goes through the tunnel.
func BestDefaultRoute(routes []Route, tunnel uint64) (Route, bool) {
	var best Route
	found := false
	for _, r := range routes {
		if r.Interface == tunnel || r.Prefix.Bits() != 0 || !r.Prefix.Addr().Is4() {
			continue
		}
		if !found || r.Metric < best.Metric {
			best, found = r, true
		}
	}
	return best, found
}
