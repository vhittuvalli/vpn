package netid

import (
	"os/exec"
	"strings"
)

// Current identifies the network behind the default route.
func Current() (Network, error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return Network{}, ErrUnknown
	}
	gateway, iface := parseRoute(string(out))
	if gateway == "" || iface == "" {
		return Network{}, ErrUnknown
	}
	out, _ = exec.Command("arp", "-n", gateway).Output()
	mac := parseARP(string(out))

	wifi := iface == wifiInterface()
	ssid := ""
	if wifi {
		out, _ = exec.Command("ipconfig", "getsummary", iface).Output()
		ssid = parseSSID(string(out))
	}
	return identify(ssid, mac, wifi)
}

// parseRoute reads the gateway and interface from `route -n get default`.
func parseRoute(out string) (gateway, iface string) {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		switch k {
		case "gateway":
			gateway = strings.TrimSpace(v)
		case "interface":
			iface = strings.TrimSpace(v)
		}
	}
	return gateway, iface
}

// parseARP reads the MAC address from `arp -n IP`, e.g.
// "? (10.0.0.1) at a0:bc:6f:76:b5:2 on en0 ifscope [ethernet]".
func parseARP(out string) string {
	fields := strings.Fields(out)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "at" {
			return fields[i+1]
		}
	}
	return ""
}

// parseSSID reads the Wi-Fi name from `ipconfig getsummary en0`.
func parseSSID(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "SSID : "); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// wifiInterface returns the Wi-Fi device name, usually en0.
func wifiInterface() string {
	out, err := exec.Command("networksetup", "-listallhardwareports").Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) == "Hardware Port: Wi-Fi" && i+1 < len(lines) {
			if dev, ok := strings.CutPrefix(strings.TrimSpace(lines[i+1]), "Device: "); ok {
				return dev
			}
		}
	}
	return ""
}
