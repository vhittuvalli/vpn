package guestapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vhittuvalli/vpn/internal/accesskey"
	"github.com/vhittuvalli/vpn/internal/config"
	"github.com/vhittuvalli/vpn/internal/protocol"
	"github.com/vhittuvalli/vpn/internal/registry"
)

const site = "https://vhittuvalli.github.io"

type fixture struct {
	h       *Handler
	reg     registry.Registry
	issued  int
	logPath string
	now     time.Time
}

func newFixture(t *testing.T, guests config.GuestFile) *fixture {
	t.Helper()
	dir := t.TempDir()
	sk, _ := protocol.GeneratePrivateKey()
	reg := registry.Registry{Path: filepath.Join(dir, "server.json")}
	f := &config.ServerFile{PrivateKey: sk.String(), Endpoint: "203.0.113.10", Address: "10.8.0.1/24", Guests: &guests, Peers: []config.PeerFile{}}
	if err := f.Write(reg.Path); err != nil {
		t.Fatal(err)
	}
	fx := &fixture{reg: reg, logPath: filepath.Join(dir, "guest-keys.log"), now: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}
	fx.h = fx.handler()
	return fx
}

// handler builds a fresh Handler over the same files, like a restart.
func (fx *fixture) handler() *Handler {
	return &Handler{
		Registry: fx.reg,
		Settings: func() config.Guests {
			f, _ := config.ReadServerFile(fx.reg.Path)
			g, _ := f.GuestSettings()
			return g
		},
		OnIssue: func() { fx.issued++ },
		LogPath: fx.logPath,
		Now:     func() time.Time { return fx.now },
	}
}

func (fx *fixture) do(method, path, ip, origin, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = ip + ":40000"
	if strings.Contains(ip, ":") {
		req.RemoteAddr = "[" + ip + "]:40000"
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	fx.h.ServeHTTP(w, req)
	return w
}

func code(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var e errorResponse
	json.Unmarshal(w.Body.Bytes(), &e)
	return e.Code
}

func TestIssueKey(t *testing.T) {
	fx := newFixture(t, config.GuestFile{Enabled: true, TTL: "1h", QuotaBytes: 500_000_000})
	w := fx.do("POST", "/guest-key", "198.51.100.7", site, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var resp keyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	key, err := accesskey.Parse(resp.Key)
	if err != nil {
		t.Fatalf("returned key doesn't parse: %v", err)
	}
	if !strings.HasPrefix(key.Name, "guest-") || resp.ExpiresAt != "2026-11-02T13:00:00Z" || resp.QuotaBytes != 500_000_000 {
		t.Fatalf("response: %+v (key %+v)", resp, key)
	}
	if fx.issued != 1 {
		t.Fatal("the running server wasn't told about the new guest")
	}
	if w.Header().Get("Access-Control-Allow-Origin") != site {
		t.Fatal("missing CORS header for the project site")
	}

	// The guest is in server.json and the issue is logged with the IP.
	s, err := config.LoadServer(fx.reg.Path)
	if err != nil || len(s.Peers) != 1 || !s.Peers[0].Guest || s.Peers[0].Name != key.Name {
		t.Fatalf("server.json: %+v, %v", s, err)
	}
	logData, _ := os.ReadFile(fx.logPath)
	var rec IssueRecord
	if err := json.Unmarshal(logData, &rec); err != nil || rec.Name != key.Name || rec.IP != "198.51.100.7" {
		t.Fatalf("log: %s", logData)
	}
	if info, _ := os.Stat(fx.logPath); info.Mode().Perm() != 0o600 {
		t.Fatalf("log permissions %v", info.Mode().Perm())
	}
}

func TestPerIPLimit(t *testing.T) {
	fx := newFixture(t, config.GuestFile{Enabled: true, PerIPPerDay: 3})
	for i := range 3 {
		if w := fx.do("POST", "/guest-key", "198.51.100.7", site, ""); w.Code != http.StatusOK {
			t.Fatalf("key %d: %d %s", i+1, w.Code, w.Body)
		}
	}
	w := fx.do("POST", "/guest-key", "198.51.100.7", site, "")
	if w.Code != http.StatusTooManyRequests || code(t, w) != "rate_limited" || w.Header().Get("Retry-After") == "" {
		t.Fatalf("fourth key: %d %s (Retry-After %q)", w.Code, w.Body, w.Header().Get("Retry-After"))
	}
	// Other people aren't affected.
	if w := fx.do("POST", "/guest-key", "198.51.100.8", site, ""); w.Code != http.StatusOK {
		t.Fatalf("another IP: %d", w.Code)
	}

	// The limit survives a restart, because it's rebuilt from the log.
	fx.h = fx.handler()
	if w := fx.do("POST", "/guest-key", "198.51.100.7", site, ""); w.Code != http.StatusTooManyRequests {
		t.Fatalf("after restart: %d", w.Code)
	}
	// A day later it resets.
	fx.now = fx.now.Add(24*time.Hour + time.Second)
	if w := fx.do("POST", "/guest-key", "198.51.100.7", site, ""); w.Code != http.StatusOK {
		t.Fatalf("next day: %d %s", w.Code, w.Body)
	}
}

func TestPerIPLimitGroupsIPv6(t *testing.T) {
	fx := newFixture(t, config.GuestFile{Enabled: true, PerIPPerDay: 1})
	if w := fx.do("POST", "/guest-key", "2001:db8:1:2::10", site, ""); w.Code != http.StatusOK {
		t.Fatalf("first: %d", w.Code)
	}
	// Another address in the same /64 is the same household.
	if w := fx.do("POST", "/guest-key", "2001:db8:1:2:abcd::99", site, ""); w.Code != http.StatusTooManyRequests {
		t.Fatalf("same /64: %d", w.Code)
	}
}

func TestMaxActiveGuests(t *testing.T) {
	fx := newFixture(t, config.GuestFile{Enabled: true, MaxActiveGuests: 2, PerIPPerDay: 5, TTL: "1h"})
	fx.do("POST", "/guest-key", "198.51.100.1", site, "")
	fx.do("POST", "/guest-key", "198.51.100.2", site, "")
	w := fx.do("POST", "/guest-key", "198.51.100.3", site, "")
	if w.Code != http.StatusServiceUnavailable || code(t, w) != "full" {
		t.Fatalf("third guest: %d %s", w.Code, w.Body)
	}
	// A refused request doesn't use up that person's daily allowance.
	fx.now = fx.now.Add(2 * time.Hour) // the first two have expired
	for range 5 {
		fx.reg.SweepGuests(fx.now, nil)
		if w := fx.do("POST", "/guest-key", "198.51.100.3", site, ""); w.Code != http.StatusOK {
			t.Fatalf("after slots freed: %d %s", w.Code, w.Body)
		}
		fx.now = fx.now.Add(2 * time.Hour)
	}
}

func TestDisabled(t *testing.T) {
	fx := newFixture(t, config.GuestFile{Enabled: false})
	w := fx.do("POST", "/guest-key", "198.51.100.7", site, "")
	if w.Code != http.StatusServiceUnavailable || code(t, w) != "disabled" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var st statusResponse
	json.Unmarshal(fx.do("GET", "/guest-status", "198.51.100.7", site, "").Body.Bytes(), &st)
	if st.Available {
		t.Fatal("status says available while guests are off")
	}
}

func TestStatus(t *testing.T) {
	fx := newFixture(t, config.GuestFile{Enabled: true, MaxActiveGuests: 2})
	fx.do("POST", "/guest-key", "198.51.100.1", site, "")
	var st statusResponse
	w := fx.do("GET", "/guest-status", "198.51.100.9", site, "")
	json.Unmarshal(w.Body.Bytes(), &st)
	if w.Code != http.StatusOK || st != (statusResponse{Available: true, Active: 1, Max: 2}) {
		t.Fatalf("%d %+v", w.Code, st)
	}
	fx.do("POST", "/guest-key", "198.51.100.2", site, "")
	json.Unmarshal(fx.do("GET", "/guest-status", "198.51.100.9", site, "").Body.Bytes(), &st)
	if st.Available || st.Active != 2 {
		t.Fatalf("full: %+v", st)
	}
}

func TestCORS(t *testing.T) {
	fx := newFixture(t, config.GuestFile{Enabled: true})
	pre := fx.do("OPTIONS", "/guest-key", "198.51.100.7", site, "")
	if pre.Code != http.StatusNoContent || pre.Header().Get("Access-Control-Allow-Origin") != site ||
		!strings.Contains(pre.Header().Get("Access-Control-Allow-Methods"), "POST") {
		t.Fatalf("preflight: %d %v", pre.Code, pre.Header())
	}
	other := fx.do("GET", "/guest-status", "198.51.100.7", "https://evil.example", "")
	if got := other.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("other origin allowed: %q", got)
	}
}

func TestRequestLimits(t *testing.T) {
	fx := newFixture(t, config.GuestFile{Enabled: true})
	if w := fx.do("POST", "/guest-key", "198.51.100.7", site, strings.Repeat("x", 4096)); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("big body: %d", w.Code)
	}
	if w := fx.do("GET", "/guest-key", "198.51.100.7", site, ""); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /guest-key: %d", w.Code)
	}
	if w := fx.do("POST", "/guest-status", "198.51.100.7", site, ""); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /guest-status: %d", w.Code)
	}
	if w := fx.do("GET", "/", "198.51.100.7", site, ""); w.Code != http.StatusNotFound {
		t.Fatalf("GET /: %d", w.Code)
	}
}
