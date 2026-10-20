package netcfg

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
)

// The kill switch uses pf, macOS's packet filter. Rules go in an anchor under
// "com.apple/", which the stock /etc/pf.conf already evaluates, so the
// system's own configuration is never edited.
const pfAnchor = "com.apple/250.vpn-killswitch"

// KillSwitch blocks outgoing traffic that would bypass the tunnel. IPv6,
// which the tunnel doesn't carry, is always blocked so it can't leak around
// it. With blockIPv4 (the kill switch proper), all IPv4 is blocked too except
// through the tunnel and to the VPN server itself (any protocol, so SSH to it
// still works), so nothing leaks if the tunnel drops. With allowLAN, the
// local network stays reachable.
func KillSwitch(tunName string, server netip.Addr, allowLAN, blockIPv4 bool) (Cleanup, error) {
	rules := pfRules(tunName, server, allowLAN, blockIPv4)

	// Make sure the main ruleset references the com.apple anchors.
	if out, _ := run("pfctl", "-s", "rules"); !strings.Contains(out, `anchor "com.apple/*"`) {
		if _, err := run("pfctl", "-f", "/etc/pf.conf"); err != nil {
			return nil, err
		}
	}
	if _, err := runInput(rules, "pfctl", "-a", pfAnchor, "-f", "-"); err != nil {
		return nil, err
	}
	// -E enables pf and returns a reference token, so we don't turn pf off
	// if something else on the system also uses it.
	out, err := run("pfctl", "-E")
	if err != nil {
		run("pfctl", "-a", pfAnchor, "-F", "all")
		return nil, err
	}
	token := ""
	for _, line := range strings.Split(out, "\n") {
		if t, ok := strings.CutPrefix(strings.TrimSpace(line), "Token : "); ok {
			token = t
		}
	}
	return func() {
		run("pfctl", "-a", pfAnchor, "-F", "all")
		if token != "" {
			run("pfctl", "-X", token)
		}
	}, nil
}

func pfRules(tunName string, server netip.Addr, allowLAN, blockIPv4 bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "pass out quick on lo0 all\n")
	fmt.Fprintf(&b, "pass out quick on %s all\n", tunName)
	if blockIPv4 {
		fmt.Fprintf(&b, "pass out quick inet from any to %s\n", server)
		fmt.Fprintf(&b, "pass out quick inet proto udp from any port 68 to any port 67\n")
		if allowLAN {
			fmt.Fprintf(&b, "pass out quick inet from any to { %s }\n", strings.Join(LocalNetworks4, ", "))
		}
	}
	if allowLAN {
		fmt.Fprintf(&b, "pass out quick inet6 from any to { %s }\n", strings.Join(LocalNetworks6, ", "))
	}
	if blockIPv4 {
		fmt.Fprintf(&b, "block drop out quick all\n")
	} else {
		fmt.Fprintf(&b, "block drop out quick inet6 all\n")
	}
	return b.String()
}

// DNS: macOS resolvers are set per network service (Wi-Fi, Ethernet, ...).
// The previous settings are saved to a file so `vpn reset` can restore them
// even if the client crashed.
const dnsBackupFile = "/var/run/vpn-dns-backup.json"

func SetDNS(tunName string, servers []netip.Addr) (Cleanup, error) {
	services, err := networkServices()
	if err != nil {
		return nil, err
	}
	backup := map[string][]string{}
	for _, svc := range services {
		out, err := run("networksetup", "-getdnsservers", svc)
		if err != nil {
			continue
		}
		if strings.Contains(out, "aren't any") {
			backup[svc] = []string{"Empty"}
		} else {
			backup[svc] = strings.Fields(out)
		}
	}
	data, _ := json.Marshal(backup)
	if err := os.WriteFile(dnsBackupFile, data, 0o600); err != nil {
		return nil, err
	}
	addrs := make([]string, len(servers))
	for i, s := range servers {
		addrs[i] = s.String()
	}
	for svc := range backup {
		if _, err := run("networksetup", append([]string{"-setdnsservers", svc}, addrs...)...); err != nil {
			restoreDNS()
			return nil, err
		}
	}
	flushDNSCache()
	return func() { restoreDNS() }, nil
}

func restoreDNS() error {
	data, err := os.ReadFile(dnsBackupFile)
	if err != nil {
		return err
	}
	var backup map[string][]string
	if err := json.Unmarshal(data, &backup); err != nil {
		return err
	}
	for svc, servers := range backup {
		if _, err := run("networksetup", append([]string{"-setdnsservers", svc}, servers...)...); err != nil {
			log.Printf("restoring DNS for %s: %v", svc, err)
		}
	}
	os.Remove(dnsBackupFile)
	flushDNSCache()
	return nil
}

func flushDNSCache() {
	run("dscacheutil", "-flushcache")
	run("killall", "-HUP", "mDNSResponder")
}

func networkServices() ([]string, error) {
	out, err := run("networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	var services []string
	for i, line := range strings.Split(strings.TrimSpace(out), "\n") {
		// The first line is a note; disabled services start with "*".
		if i == 0 || line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		services = append(services, line)
	}
	if len(services) == 0 {
		return nil, errors.New("no network services found")
	}
	return services, nil
}

// Reset removes the kill switch and restores DNS, for recovering after the
// client was killed without a chance to clean up.
func Reset() error {
	_, err := run("pfctl", "-a", pfAnchor, "-F", "all")
	if dnsErr := restoreDNS(); dnsErr != nil && !os.IsNotExist(dnsErr) {
		err = errors.Join(err, dnsErr)
	}
	return err
}
