package netcfg

import (
	"errors"
	"log"
	"net/netip"
	"os/exec"
)

const killSwitchChain = "VPN_KILLSWITCH"

// KillSwitch blocks outgoing traffic that would bypass the tunnel. IPv6,
// which the tunnel doesn't carry, is always blocked so it can't leak around
// it. With blockIPv4 (the kill switch proper), all IPv4 is blocked too except
// through the tunnel and to the VPN server itself (any protocol, so SSH to it
// still works), so nothing leaks if the tunnel drops. With allowLAN, the
// local network stays reachable.
func KillSwitch(tunName string, server netip.Addr, allowLAN, blockIPv4 bool) (Cleanup, error) {
	Reset() // remove leftovers from a crashed run
	for _, cmd := range killSwitchCommands(tunName, server, allowLAN, blockIPv4) {
		if _, err := run(cmd[0], cmd[1:]...); err != nil {
			Reset()
			return nil, err
		}
	}
	return func() { Reset() }, nil
}

func killSwitchCommands(tunName string, server netip.Addr, allowLAN, blockIPv4 bool) [][]string {
	accept := func(ipt string, args ...string) []string {
		return append(append([]string{ipt, "-A", killSwitchChain}, args...), "-j", "ACCEPT")
	}
	var cmds [][]string
	if blockIPv4 {
		cmds = [][]string{
			{"iptables", "-N", killSwitchChain},
			accept("iptables", "-o", "lo"),
			accept("iptables", "-o", tunName),
			accept("iptables", "-d", server.String()),
			accept("iptables", "-p", "udp", "--sport", "68", "--dport", "67"),
		}
		if allowLAN {
			for _, n := range LocalNetworks4 {
				cmds = append(cmds, accept("iptables", "-d", n))
			}
		}
		cmds = append(cmds,
			[]string{"iptables", "-A", killSwitchChain, "-j", "REJECT"},
			[]string{"iptables", "-I", "OUTPUT", "1", "-j", killSwitchChain},
		)
	}
	cmds = append(cmds,
		[]string{"ip6tables", "-N", killSwitchChain},
		accept("ip6tables", "-o", "lo"),
	)
	if allowLAN {
		for _, n := range LocalNetworks6 {
			cmds = append(cmds, accept("ip6tables", "-d", n))
		}
	}
	return append(cmds,
		[]string{"ip6tables", "-A", killSwitchChain, "-j", "REJECT"},
		[]string{"ip6tables", "-I", "OUTPUT", "1", "-j", killSwitchChain},
	)
}

// SetDNS points the system resolver at servers for all lookups, using
// systemd-resolved's per-interface settings.
func SetDNS(tunName string, servers []netip.Addr) (Cleanup, error) {
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return nil, errors.New("setting DNS needs systemd-resolved (resolvectl)")
	}
	args := []string{"dns", tunName}
	for _, s := range servers {
		args = append(args, s.String())
	}
	if _, err := run("resolvectl", args...); err != nil {
		return nil, err
	}
	// "~." makes this interface's servers handle every domain.
	if _, err := run("resolvectl", "domain", tunName, "~."); err != nil {
		run("resolvectl", "revert", tunName)
		return nil, err
	}
	return func() { run("resolvectl", "revert", tunName) }, nil
}

// Reset removes the kill switch, for recovering after the client was killed
// without a chance to clean up. DNS settings vanish with the interface.
func Reset() error {
	var errs []error
	for _, ipt := range []string{"iptables", "ip6tables"} {
		if _, err := run(ipt, "-L", killSwitchChain, "-n"); err != nil {
			continue // not installed
		}
		for {
			if _, err := run(ipt, "-D", "OUTPUT", "-j", killSwitchChain); err != nil {
				break
			}
		}
		for _, cmd := range [][]string{{"-F", killSwitchChain}, {"-X", killSwitchChain}} {
			if _, err := run(ipt, cmd...); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		log.Printf("reset: %v", err)
		return err
	}
	return nil
}
