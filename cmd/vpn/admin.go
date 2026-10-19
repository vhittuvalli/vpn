package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/vhittuvalli/vpn/internal/accesskey"
	"github.com/vhittuvalli/vpn/internal/config"
	"github.com/vhittuvalli/vpn/internal/human"
	"github.com/vhittuvalli/vpn/internal/protocol"
	"github.com/vhittuvalli/vpn/internal/vpn"
)

// Where `vpn setup` puts things. The other admin commands default to the
// same config file.
const (
	serverConfigPath = "/etc/vpn/server.json"
	installedBinary  = "/usr/local/bin/vpn"
	unitPath         = "/etc/systemd/system/vpn.service"
)

const unitFile = `[Unit]
Description=vpn server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/vpn server -c /etc/vpn/server.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
# Signal only the server on stop, so the iptables commands it runs while
# cleaning up aren't killed halfway and leave stale rules behind.
KillMode=mixed
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
`

var deviceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)

// setup turns a fresh Linux machine into a server: config, systemd service,
// firewall rules, and a first access key.
func setup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	endpoint := fs.String("endpoint", "", "public IP or hostname clients connect to (detected if omitted)")
	name := fs.String("name", "my-device", "name for the first device")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		return errors.New("setup runs on a Linux server; on this machine, use the app or `vpn connect`")
	}
	if err := requireRoot(); err != nil {
		return err
	}
	if _, err := os.Stat(serverConfigPath); err == nil {
		return fmt.Errorf("this server is already set up (%s exists); add devices with: sudo vpn invite NAME", serverConfigPath)
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("setup needs systemd; run `vpn server -c server.json` yourself instead")
	}

	iface, ifaceAddr, err := defaultInterface()
	if err != nil {
		return err
	}
	if *endpoint == "" {
		if ifaceAddr.IsPrivate() || ifaceAddr.IsLoopback() {
			return fmt.Errorf("%s has the private address %s; pass this server's public IP: sudo vpn setup --endpoint 203.0.113.10", iface, ifaceAddr)
		}
		*endpoint = ifaceAddr.String()
	}

	key, err := protocol.GeneratePrivateKey()
	if err != nil {
		return err
	}
	f := &config.ServerFile{
		PrivateKey:   key.String(),
		Endpoint:     *endpoint,
		ListenPort:   config.DefaultUDPPort,
		HTTPSPort:    443,
		Address:      "10.8.0.1/24",
		NATInterface: iface,
		Peers:        []config.PeerFile{},
	}
	step("Writing " + serverConfigPath)
	if err := os.MkdirAll("/etc/vpn", 0o700); err != nil {
		return err
	}
	if err := f.Write(serverConfigPath); err != nil {
		return err
	}

	if self, err := os.Executable(); err == nil && self != installedBinary {
		step("Installing " + installedBinary)
		if err := copyFile(self, installedBinary, 0o755); err != nil {
			return err
		}
	}

	if ufwActive() {
		step("Opening UDP 51820 and 443 in the firewall (ufw)")
		for _, rule := range []string{"51820/udp", "443/udp"} {
			if out, err := exec.Command("ufw", "allow", rule).CombinedOutput(); err != nil {
				return fmt.Errorf("ufw allow %s: %v: %s", rule, err, out)
			}
		}
	}

	step("Starting the vpn service")
	if err := os.WriteFile(unitPath, []byte(unitFile), 0o644); err != nil {
		return err
	}
	for _, cmd := range [][]string{{"daemon-reload"}, {"enable", "--now", "vpn"}} {
		if out, err := exec.Command("systemctl", cmd...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s: %v: %s", strings.Join(cmd, " "), err, out)
		}
	}

	k, err := addDevice(serverConfigPath, *name)
	if err != nil {
		return err
	}
	fmt.Printf("\nYour server is running at %s.\n", *endpoint)
	printKey(k)
	fmt.Println("If your cloud provider has its own firewall, allow UDP 51820 and UDP 443 there too.")
	fmt.Println("Add more devices with: sudo vpn invite NAME")
	return nil
}

func invite(args []string) error {
	fs := flag.NewFlagSet("invite", flag.ContinueOnError)
	path := fs.String("c", serverConfigPath, "server config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: sudo vpn invite NAME   (for example: sudo vpn invite alex-phone)")
	}
	if err := requireRoot(); err != nil {
		return err
	}
	k, err := addDevice(*path, fs.Arg(0))
	if err != nil {
		return err
	}
	printKey(k)
	return nil
}

// addDevice adds a peer with a fresh key and the next free address, tells
// the running server, and returns the device's access key.
func addDevice(path, name string) (*accesskey.Key, error) {
	if !deviceName.MatchString(name) {
		return nil, fmt.Errorf("%q isn't a usable name: use up to 32 letters, digits, dots, dashes or underscores", name)
	}
	f, err := config.ReadServerFile(path)
	if err != nil {
		return nil, err
	}
	if f.Endpoint == "" {
		return nil, fmt.Errorf(`%s has no "endpoint": add "endpoint": "<this server's public IP>" to it`, path)
	}
	serverKey, err := protocol.ParsePrivateKey(f.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("%s: private_key: %w", path, err)
	}
	subnet, err := netip.ParsePrefix(f.Address)
	if err != nil {
		return nil, fmt.Errorf("%s: address: %w", path, err)
	}
	used := map[netip.Addr]bool{subnet.Addr(): true}
	for _, p := range f.Peers {
		if p.Name == name {
			return nil, fmt.Errorf("a device named %q already exists; pick another name, or remove it first with: sudo vpn revoke %s", name, name)
		}
		if a, err := netip.ParseAddr(p.Address); err == nil {
			used[a] = true
		}
	}
	addr := netip.Addr{}
	for a := subnet.Masked().Addr().Next(); subnet.Contains(a); a = a.Next() {
		if !used[a] && subnet.Contains(a.Next()) { // skip the broadcast address
			addr = a
			break
		}
	}
	if !addr.IsValid() {
		return nil, fmt.Errorf("no free addresses left in %s", subnet.Masked())
	}

	device, err := protocol.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	f.Peers = append(f.Peers, config.PeerFile{Name: name, PublicKey: device.Public().String(), Address: addr.String()})
	if err := f.Write(path); err != nil {
		return nil, err
	}
	reloadServer()

	udp := f.ListenPort
	if udp == 0 {
		udp = config.DefaultUDPPort
	}
	return &accesskey.Key{
		Name: name, Host: f.Endpoint, UDPPort: udp, HTTPSPort: f.HTTPSPort,
		ServerPublicKey: serverKey.Public(), PrivateKey: device,
		Address: netip.PrefixFrom(addr, subnet.Bits()),
	}, nil
}

func revoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	path := fs.String("c", serverConfigPath, "server config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: sudo vpn revoke NAME")
	}
	if err := requireRoot(); err != nil {
		return err
	}
	f, err := config.ReadServerFile(*path)
	if err != nil {
		return err
	}
	kept := f.Peers[:0]
	for _, p := range f.Peers {
		if p.Name != fs.Arg(0) {
			kept = append(kept, p)
		}
	}
	if len(kept) == len(f.Peers) {
		return fmt.Errorf("no device named %q; see the list with: sudo vpn devices", fs.Arg(0))
	}
	f.Peers = kept
	if err := f.Write(*path); err != nil {
		return err
	}
	reloadServer()
	fmt.Printf("Removed %s. Its access key no longer works.\n", fs.Arg(0))
	return nil
}

func devices(args []string) error {
	fs := flag.NewFlagSet("devices", flag.ContinueOnError)
	path := fs.String("c", serverConfigPath, "server config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireRoot(); err != nil {
		return err
	}
	f, err := config.ReadServerFile(*path)
	if err != nil {
		return err
	}
	if len(f.Peers) == 0 {
		fmt.Println("No devices yet. Add one with: sudo vpn invite NAME")
		return nil
	}

	// The running server refreshes status.json every few seconds. If it's
	// missing or old, the server isn't running: show the last known numbers
	// with everyone offline.
	now := time.Now()
	byKey := map[string]vpn.PeerStats{}
	status, err := vpn.ReadStatus(statusPath(*path))
	stale := err != nil || now.Sub(status.Updated) > 30*time.Second
	if err == nil {
		for _, st := range status.Peers {
			byKey[st.PublicKey] = st
		}
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "DEVICE\tADDRESS\tSTATUS\tLAST SEEN\tFROM\tDOWNLOADED\tUPLOADED")
	for _, p := range f.Peers {
		st, known := byKey[p.PublicKey]
		state, seen, from, down, up := "offline", "never", "-", "-", "-"
		if known {
			if st.Online && !stale {
				state = "online " + human.Duration(now.Sub(st.ConnectedAt))
				seen = "now"
			} else {
				seen = human.Ago(st.LastSeen, now)
			}
			if host, _, err := net.SplitHostPort(st.From); err == nil {
				from = host
			}
			down, up = human.Bytes(st.TxBytes), human.Bytes(st.RxBytes)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", p.Name, p.Address, state, seen, from, down, up)
	}
	w.Flush()
	switch {
	case err != nil && !errors.Is(err, os.ErrNotExist):
		fmt.Fprintf(os.Stderr, "\ncouldn't read usage: %v\n", err)
	case stale:
		fmt.Println("\nThe vpn server doesn't seem to be running; showing the last known usage.")
	}
	return nil
}

// reloadServer asks a running vpn service to re-read its device list.
func reloadServer() {
	if exec.Command("systemctl", "is-active", "--quiet", "vpn").Run() != nil {
		fmt.Fprintln(os.Stderr, "note: the vpn service isn't running; the change applies when it starts")
		return
	}
	if out, err := exec.Command("systemctl", "kill", "--signal=HUP", "--kill-whom=main", "vpn").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "note: couldn't tell the running server (%v: %s); restart it with: sudo systemctl restart vpn\n", err, strings.TrimSpace(string(out)))
	}
}

func printKey(k *accesskey.Key) {
	fmt.Printf("\nAccess key for %s (treat it like a password):\n\n%s\n\n", k.Name, k)
	fmt.Println("Paste it into the VPN app, or on Linux run: sudo vpn connect <key>")
	fmt.Println()
}

func step(msg string) { fmt.Println("==> " + msg) }

// defaultInterface returns the interface and IPv4 address of the default route.
func defaultInterface() (string, netip.Addr, error) {
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return "", netip.Addr{}, fmt.Errorf("finding the default route: %w", err)
	}
	fields := strings.Fields(string(out))
	iface := ""
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" {
			iface = fields[i+1]
			break
		}
	}
	if iface == "" {
		return "", netip.Addr{}, errors.New("this machine has no default route to the internet")
	}
	out, err = exec.Command("ip", "-4", "-o", "addr", "show", "dev", iface).Output()
	if err != nil {
		return "", netip.Addr{}, fmt.Errorf("reading %s's address: %w", iface, err)
	}
	// e.g. "2: eth0    inet 203.0.113.10/20 brd ... scope global eth0", one
	// line per address. Cloud VMs often add a private address to the same
	// interface, so prefer a public one.
	var first netip.Addr
	fields = strings.Fields(string(out))
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] != "inet" {
			continue
		}
		p, err := netip.ParsePrefix(fields[i+1])
		if err != nil {
			continue
		}
		if !p.Addr().IsPrivate() && !p.Addr().IsLoopback() {
			return iface, p.Addr(), nil
		}
		if !first.IsValid() {
			first = p.Addr()
		}
	}
	if first.IsValid() {
		return iface, first, nil
	}
	return "", netip.Addr{}, fmt.Errorf("%s has no IPv4 address", iface)
}

func ufwActive() bool {
	out, err := exec.Command("ufw", "status").Output()
	return err == nil && strings.Contains(string(out), "Status: active")
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
