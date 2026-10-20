package main

import "testing"

func TestNewerVersion(t *testing.T) {
	for _, c := range []struct {
		latest, current string
		want            bool
	}{
		{"v0.2.1", "v0.2.0", true},
		{"v0.10.0", "v0.9.9", true},
		{"v1.0.0", "v0.99.0", true},
		{"v0.2.0", "v0.2.0", false},
		{"v0.2.0", "v0.2.1", false},
		{"v0.2.0", "v0.2.0-rc1", true},
		{"v0.2.0-rc1", "v0.2.0", false},
		{"v0.2.0-rc2", "v0.2.0-rc1", true},
		{"v0.2.1", "dev", false},
		{"garbage", "v0.2.0", false},
	} {
		if got := newerVersion(c.latest, c.current); got != c.want {
			t.Errorf("newerVersion(%q, %q) = %v, want %v", c.latest, c.current, got, c.want)
		}
	}
}
