package netcfg

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ConfigureInterface assigns addr to the interface, brings it up, and routes
// addr's subnet through it.
func ConfigureInterface(name string, addr netip.Prefix, mtu int) error {
	ip := addr.Addr().String()
	if _, err := run("ifconfig", name, "inet", ip, ip, "mtu", strconv.Itoa(mtu), "up"); err != nil {
		return err
	}
	_, err := run("route", "-q", "-n", "add", "-net", addr.Masked().String(), "-interface", name)
	return err
}

// RouteAllTraffic sends all IPv4 traffic through the tunnel, except traffic
// to the VPN server itself, which must keep using the real network.
// 0.0.0.0/1 + 128.0.0.0/1 cover everything and win over the default route
// because they are more specific, so the default route is left untouched.
func RouteAllTraffic(tunName string, server netip.Addr) (Cleanup, error) {
	out, err := run("route", "-n", "get", "default")
	if err != nil {
		return nil, err
	}
	gateway := ""
	for _, line := range strings.Split(out, "\n") {
		if g, ok := strings.CutPrefix(strings.TrimSpace(line), "gateway:"); ok {
			gateway = strings.TrimSpace(g)
		}
	}
	if gateway == "" {
		return nil, errors.New("could not find the default gateway")
	}
	host := server.String()
	return runAll(
		[][]string{
			{"route", "-q", "-n", "add", "-host", host, gateway},
			{"route", "-q", "-n", "add", "-net", "0.0.0.0/1", "-interface", tunName},
			{"route", "-q", "-n", "add", "-net", "128.0.0.0/1", "-interface", tunName},
		},
		[][]string{
			{"route", "-q", "-n", "delete", "-host", host},
			nil, // removed with the interface
			nil,
		},
	)
}

func EnableNAT(tunName, outInterface string, subnet netip.Prefix) (Cleanup, error) {
	return nil, fmt.Errorf("NAT is only supported on a Linux server")
}
