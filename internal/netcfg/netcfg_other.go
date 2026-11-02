//go:build !linux && !darwin && !windows

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

func EnableNAT(tunName, outInterface string, subnet, guestPool netip.Prefix) (Cleanup, error) {
	return nil, errUnsupported
}

func KillSwitch(tunName string, server netip.Addr, allowLAN, blockIPv4 bool) (Cleanup, error) {
	return nil, errUnsupported
}

func SetDNS(tunName string, servers []netip.Addr) (Cleanup, error) { return nil, errUnsupported }

func Reset() error { return errUnsupported }
