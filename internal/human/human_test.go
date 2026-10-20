package human

import (
	"testing"
	"time"
)

func TestBytes(t *testing.T) {
	for n, want := range map[uint64]string{
		0: "0 B", 999: "999 B", 1000: "1.0 KB", 3_456: "3.5 KB",
		80_000_000: "80.0 MB", 1_300_000_000: "1.3 GB", 2_000_000_000_000: "2.0 TB",
	} {
		if got := Bytes(n); got != want {
			t.Errorf("Bytes(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		40 * time.Second:               "40s",
		5*time.Minute + 20*time.Second: "5m",
		2*time.Hour + 14*time.Minute:   "2h 14m",
		76*time.Hour + 30*time.Minute:  "3d 4h",
	} {
		if got := Duration(d); got != want {
			t.Errorf("Duration(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestAgo(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		t    time.Time
		want string
	}{
		{time.Time{}, "never"},
		{now.Add(-20 * time.Second), "just now"},
		{now.Add(-5 * time.Minute), "5 min ago"},
		{now.Add(-1 * time.Hour), "1 hour ago"},
		{now.Add(-3 * time.Hour), "3 hours ago"},
		{now.Add(-50 * time.Hour), "2 days ago"},
	} {
		if got := Ago(c.t, now); got != c.want {
			t.Errorf("Ago(%v) = %q, want %q", now.Sub(c.t), got, c.want)
		}
	}
}
