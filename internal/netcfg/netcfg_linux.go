package netcfg

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ConfigureInterface assigns addr to the interface and brings it up. The
// kernel adds the route for addr's subnet automatically.
func ConfigureInterface(name string, addr netip.Prefix, mtu int) error {
	if _, err := run("ip", "addr", "add", addr.String(), "dev", name); err != nil {
		return err
	}
	_, err := run("ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu), "up")
	return err
}

// RouteAllTraffic sends all IPv4 traffic through the tunnel, except traffic
// to the VPN server itself, which keeps using the current route.
func RouteAllTraffic(tunName string, server netip.Addr) (Cleanup, error) {
	out, err := run("ip", "route", "get", server.String())
	if err != nil {
		return nil, err
	}
	// e.g. "203.0.113.10 via 192.168.1.1 dev eth0 src 192.168.1.20 uid 0"
	fields := strings.Fields(strings.SplitN(out, "\n", 2)[0])
	route := []string{"ip", "route", "add", server.String() + "/32"}
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "via" || fields[i] == "dev" {
			route = append(route, fields[i], fields[i+1])
		}
	}
	return runAll(
		[][]string{
			route,
			{"ip", "route", "add", "0.0.0.0/1", "dev", tunName},
			{"ip", "route", "add", "128.0.0.0/1", "dev", tunName},
		},
		[][]string{
			{"ip", "route", "del", server.String() + "/32"},
			nil, // removed with the interface
			nil,
		},
	)
}

// EnableNAT lets clients reach the internet through the server: the kernel
// forwards their packets and rewrites the source address to the server's.
func EnableNAT(tunName, outInterface string, subnet netip.Prefix) (Cleanup, error) {
	if _, err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return nil, err
	}
	rules := [][]string{
		{"-t", "nat", "POSTROUTING", "-s", subnet.Masked().String(), "-o", outInterface, "-j", "MASQUERADE"},
		{"-t", "filter", "FORWARD", "-i", tunName, "-j", "ACCEPT"},
		{"-t", "filter", "FORWARD", "-o", tunName, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}
	var do, undo [][]string
	for _, r := range rules {
		table, chain, spec := r[:2], r[2], r[3:]
		do = append(do, append(append([]string{"iptables"}, table...), append([]string{"-I", chain}, spec...)...))
		undo = append(undo, append(append([]string{"iptables"}, table...), append([]string{"-D", chain}, spec...)...))
	}
	cleanup, err := runAll(do, undo)
	if err != nil {
		return nil, fmt.Errorf("enabling NAT: %w", err)
	}
	return cleanup, nil
}
