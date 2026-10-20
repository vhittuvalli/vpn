// Package netid identifies the network this machine is on, for trusted
// networks: the VPN pauses on networks the user trusts and connects
// everywhere else.
//
// A network is its Wi-Fi name together with the hardware address of its
// router. Anyone can broadcast a Wi-Fi network with a familiar name, so the
// name alone would let a fake hotspot switch the VPN off; matching the
// router's address as well makes that much harder.
package netid

import (
	"errors"
	"fmt"
	"strings"
)

// Network is the network currently in use.
type Network struct {
	ID   string // stable identifier: name and router address
	Name string // what to show people: the Wi-Fi name, or "Ethernet"
}

// ErrUnknown means the network can't be identified right now (no default
// route, or the router's address isn't known yet).
var ErrUnknown = errors.New("network not identified")

func identify(ssid, routerMAC string, wifi bool) (Network, error) {
	mac := normalizeMAC(routerMAC)
	if mac == "" {
		return Network{}, ErrUnknown
	}
	switch {
	case !wifi:
		return Network{ID: "wired|" + mac, Name: "Ethernet"}, nil
	case ssid == "" || strings.Contains(ssid, "redacted"):
		// macOS can hide the Wi-Fi name from background processes; the
		// router's address still tells networks apart.
		return Network{ID: "wifi|" + mac, Name: "Wi-Fi (router " + mac + ")"}, nil
	default:
		return Network{ID: "wifi|" + ssid + "|" + mac, Name: ssid}, nil
	}
}

// normalizeMAC turns "a0:bc:6f:76:b5:2" (as arp prints it) into
// "a0:bc:6f:76:b5:02", and rejects anything that isn't a MAC address.
func normalizeMAC(s string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(s)), ":")
	if len(parts) != 6 {
		return ""
	}
	allZero := true
	for i, p := range parts {
		var b uint8
		if len(p) == 0 || len(p) > 2 {
			return ""
		}
		if _, err := fmt.Sscanf(p, "%x", &b); err != nil {
			return ""
		}
		if b != 0 {
			allZero = false
		}
		parts[i] = fmt.Sprintf("%02x", b)
	}
	if allZero {
		return ""
	}
	return strings.Join(parts, ":")
}
