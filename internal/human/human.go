// Package human formats sizes, durations and times for people.
package human

import (
	"fmt"
	"time"
)

// Bytes formats n as "512 B", "3.4 KB", "1.3 GB" (powers of 1000, like
// macOS Finder).
func Bytes(n uint64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	v, i := float64(n)/unit, 0
	for v >= unit && i < 4 {
		v /= unit
		i++
	}
	return fmt.Sprintf("%.1f %cB", v, "KMGTP"[i])
}

// Duration formats d coarsely: "40s", "5m", "2h 14m", "3d 4h".
func Duration(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
	}
}

// Ago formats how long before now t was: "just now", "5 min ago",
// "3 hours ago", "2 days ago", or "never" for the zero time.
func Ago(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	plural := func(n int, unit string) string {
		if n == 1 {
			return fmt.Sprintf("1 %s ago", unit)
		}
		return fmt.Sprintf("%d %ss ago", n, unit)
	}
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return plural(int(d.Hours()), "hour")
	default:
		return plural(int(d.Hours())/24, "day")
	}
}
