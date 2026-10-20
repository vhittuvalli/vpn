package netid

import "testing"

func TestIdentify(t *testing.T) {
	home, err := identify("HomeWiFi", "a0:bc:6f:76:b5:2", true)
	if err != nil || home.Name != "HomeWiFi" || home.ID != "wifi|HomeWiFi|a0:bc:6f:76:b5:02" {
		t.Fatalf("home = %+v, %v", home, err)
	}
	// A hotspot with the same name but a different router is a different
	// network.
	fake, _ := identify("HomeWiFi", "de:ad:be:ef:00:01", true)
	if fake.ID == home.ID {
		t.Fatal("a same-named hotspot matched the trusted network")
	}
	hidden, _ := identify("<redacted>", "a0:bc:6f:76:b5:02", true)
	if hidden.ID != "wifi|a0:bc:6f:76:b5:02" {
		t.Errorf("hidden name: %+v", hidden)
	}
	wired, _ := identify("", "a0:bc:6f:76:b5:02", false)
	if wired.ID != "wired|a0:bc:6f:76:b5:02" || wired.Name != "Ethernet" {
		t.Errorf("wired: %+v", wired)
	}
	for _, mac := range []string{"", "(incomplete)", "00:00:00:00:00:00", "zz:bc:6f:76:b5:02", "a0:bc:6f:76:b5"} {
		if _, err := identify("HomeWiFi", mac, true); err != ErrUnknown {
			t.Errorf("router %q: want ErrUnknown, got %v", mac, err)
		}
	}
}
