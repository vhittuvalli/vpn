package netcfg

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// On Windows, interfaces are configured through the IP Helper API (WireGuard's
// winipcfg package), not by running commands.

func luidOf(name string) (winipcfg.LUID, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("finding adapter %q: %w", name, err)
	}
	return winipcfg.LUIDFromIndex(uint32(ifc.Index))
}

// ConfigureInterface assigns addr to the adapter, sets its MTU, and gives it
// the highest priority, so its DNS servers are asked first.
func ConfigureInterface(name string, addr netip.Prefix, mtu int) error {
	luid, err := luidOf(name)
	if err != nil {
		return err
	}
	if err := luid.SetIPAddresses([]netip.Prefix{addr}); err != nil {
		return fmt.Errorf("setting the adapter's address: %w", err)
	}
	iface, err := luid.IPInterface(windows.AF_INET)
	if err != nil {
		return err
	}
	iface.NLMTU = uint32(mtu)
	iface.UseAutomaticMetric = false
	iface.Metric = 0
	if err := iface.Set(); err != nil {
		return fmt.Errorf("setting the adapter's MTU: %w", err)
	}
	return nil
}

// RouteAllTraffic sends all IPv4 traffic through the tunnel, except traffic
// to the VPN server itself, which keeps using the current default route.
func RouteAllTraffic(tunName string, server netip.Addr) (Cleanup, error) {
	tunLUID, err := luidOf(tunName)
	if err != nil {
		return nil, err
	}
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return nil, err
	}
	var routes []Route
	for i := range rows {
		r := &rows[i]
		metric := r.Metric
		if iface, err := r.InterfaceLUID.IPInterface(windows.AF_INET); err == nil {
			metric += iface.Metric
		}
		routes = append(routes, Route{
			Interface: uint64(r.InterfaceLUID), Prefix: r.DestinationPrefix.Prefix(),
			NextHop: r.NextHop.Addr(), Metric: metric,
		})
	}
	best, ok := BestDefaultRoute(routes, uint64(tunLUID))
	if !ok {
		return nil, errors.New("no default route to the internet")
	}
	physical := winipcfg.LUID(best.Interface)
	host := netip.PrefixFrom(server, 32)
	if err := physical.AddRoute(host, best.NextHop, 0); err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return nil, fmt.Errorf("route to the VPN server: %w", err)
	}
	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := tunLUID.AddRoute(netip.MustParsePrefix(half), netip.IPv4Unspecified(), 0); err != nil {
			physical.DeleteRoute(host, best.NextHop)
			return nil, fmt.Errorf("routing traffic through the tunnel: %w", err)
		}
	}
	// The tunnel's routes go away with the adapter.
	return func() { physical.DeleteRoute(host, best.NextHop) }, nil
}

func EnableNAT(tunName, outInterface string, subnet, guestPool netip.Prefix) (Cleanup, error) {
	return nil, errors.New("NAT is only supported on a Linux server")
}
