package netcfg

import (
	"errors"
	"log"
	"net/netip"
	"os/exec"
	"strconv"
)

const killSwitchChain = "VPN_KILLSWITCH"

// KillSwitch blocks all outgoing traffic except through the tunnel and to
// the VPN server itself, so nothing leaks if the tunnel drops. It also
// blocks all IPv6, which the tunnel doesn't carry.
func KillSwitch(tunName string, server netip.AddrPort) (Cleanup, error) {
	Reset() // remove leftovers from a crashed run
	v4 := [][]string{
		{"iptables", "-N", killSwitchChain},
		{"iptables", "-A", killSwitchChain, "-o", "lo", "-j", "ACCEPT"},
		{"iptables", "-A", killSwitchChain, "-o", tunName, "-j", "ACCEPT"},
		{"iptables", "-A", killSwitchChain, "-p", "udp", "-d", server.Addr().String(), "--dport", strconv.Itoa(int(server.Port())), "-j", "ACCEPT"},
		{"iptables", "-A", killSwitchChain, "-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT"},
		{"iptables", "-A", killSwitchChain, "-j", "REJECT"},
		{"iptables", "-I", "OUTPUT", "1", "-j", killSwitchChain},
		{"ip6tables", "-N", killSwitchChain},
		{"ip6tables", "-A", killSwitchChain, "-o", "lo", "-j", "ACCEPT"},
		{"ip6tables", "-A", killSwitchChain, "-j", "REJECT"},
		{"ip6tables", "-I", "OUTPUT", "1", "-j", killSwitchChain},
	}
	for _, cmd := range v4 {
		if _, err := run(cmd[0], cmd[1:]...); err != nil {
			Reset()
			return nil, err
		}
	}
	return func() { Reset() }, nil
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
