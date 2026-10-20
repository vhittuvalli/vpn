package netid

import "testing"

// Outputs captured from macOS 15.
func TestParseDarwin(t *testing.T) {
	gw, iface := parseRoute(`   route to: default
destination: default
       mask: default
    gateway: 10.148.0.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
`)
	if gw != "10.148.0.1" || iface != "en0" {
		t.Errorf("route: %q %q", gw, iface)
	}
	if mac := parseARP("? (10.148.0.1) at a0:bc:6f:76:b5:2 on en0 ifscope [ethernet]\n"); mac != "a0:bc:6f:76:b5:2" {
		t.Errorf("arp: %q", mac)
	}
	if mac := parseARP("10.148.0.1 (10.148.0.1) -- no entry\n"); mac != "" {
		t.Errorf("arp without entry: %q", mac)
	}
	if ssid := parseSSID("<dictionary> {\n  Hashed-BSSID : 7e:48:7d:62:aa:87\n  SSID : utexas\n}\n"); ssid != "utexas" {
		t.Errorf("ssid: %q", ssid)
	}
}
