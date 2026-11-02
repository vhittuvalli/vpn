package main

import (
	"testing"
	"time"

	"github.com/vhittuvalli/vpn/internal/config"
	"github.com/vhittuvalli/vpn/internal/vpn"
)

func TestGuestLimitsColumn(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	used := vpn.PeerStats{RxBytes: 20_500_000, TxBytes: 100_000_000}
	for _, c := range []struct {
		peer config.PeerFile
		want string
	}{
		{config.PeerFile{Name: "laptop"}, "-"},
		{config.PeerFile{Guest: true, ExpiresAt: "2026-11-02T12:42:00Z", QuotaBytes: 500_000_000}, "42m left · 120.5 MB of 500.0 MB"},
		{config.PeerFile{Guest: true, ExpiresAt: "2026-11-02T11:00:00Z", QuotaBytes: 500_000_000}, "expired · 120.5 MB of 500.0 MB"},
		{config.PeerFile{Guest: true, ExpiresAt: "2026-11-02T13:00:00Z"}, "1h 0m left · 120.5 MB used"},
	} {
		if got := guestLimits(c.peer, used, now); got != c.want {
			t.Errorf("guestLimits(%+v) = %q, want %q", c.peer, got, c.want)
		}
	}
}
