//go:build !linux && !darwin

package netcfg

import (
	"errors"
	"net/netip"
)

var errUnsupported = errors.New("network configuration is not supported on this OS")

func ConfigureInterface(name string, addr netip.Prefix, mtu int) error { return errUnsupported }

func RouteAllTraffic(tunName string, server netip.Addr) (Cleanup, error) {
	return nil, errUnsupported
}

func EnableNAT(tunName, outInterface string, subnet netip.Prefix) (Cleanup, error) {
	return nil, errUnsupported
}

func KillSwitch(tunName string, server netip.Addr, allowLAN bool) (Cleanup, error) {
	return nil, errUnsupported
}

func SetDNS(tunName string, servers []netip.Addr) (Cleanup, error) { return nil, errUnsupported }

func Reset() error { return errUnsupported }
