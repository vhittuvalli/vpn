package netcfg

import (
	"errors"
	"log"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/firewall"
)

// KillSwitch uses the Windows Filtering Platform rules from WireGuard for
// Windows: only the tunnel, loopback, DHCP and this program itself (for the
// encrypted traffic to the server) may send anything. That also blocks
// IPv6 and DNS outside the tunnel. The rules live in a dynamic session, so
// Windows removes them if the program exits or crashes.
//
// They can't yet make exceptions, so on Windows the kill switch is always
// on while all traffic goes through the VPN, the local network isn't
// reachable, and other programs can't reach the server directly.
func KillSwitch(tunName string, server netip.Addr, allowLAN, blockIPv4 bool) (Cleanup, error) {
	luid, err := luidOf(tunName)
	if err != nil {
		return nil, err
	}
	if !blockIPv4 || allowLAN {
		log.Print("note: on Windows the kill switch is always on and blocks the local network")
	}
	if err := firewall.EnableFirewall(uint64(luid), false, nil); err != nil {
		// The rules recognize the VPN's own traffic by the Windows
		// service's SID, which a program started from a terminal doesn't
		// have.
		if errors.Is(err, windows.ERROR_NO_SUCH_GROUP) {
			if blockIPv4 {
				return nil, errors.New("on Windows the kill switch only works inside the VPN service: use the app (or `vpn service`), or connect with --no-kill-switch")
			}
			log.Print("warning: without the VPN service, IPv6 and DNS outside the tunnel aren't blocked")
			return func() {}, nil
		}
		return nil, err
	}
	return firewall.DisableFirewall, nil
}

// SetDNS points the tunnel adapter at servers. With the adapter's top
// priority and the firewall blocking DNS elsewhere, lookups go through the
// tunnel.
func SetDNS(tunName string, servers []netip.Addr) (Cleanup, error) {
	luid, err := luidOf(tunName)
	if err != nil {
		return nil, err
	}
	if err := luid.SetDNS(windows.AF_INET, servers, nil); err != nil {
		return nil, err
	}
	return func() { luid.FlushDNS(windows.AF_INET) }, nil
}

// Reset has nothing to undo on Windows: the firewall rules disappear with
// the process and the DNS settings with the adapter.
func Reset() error { return nil }
