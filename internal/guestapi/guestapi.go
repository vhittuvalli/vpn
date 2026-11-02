// Package guestapi is the small HTTPS endpoint that hands out guest access
// keys to visitors of the project site:
//
//	POST /guest-key     → {"key": "vpn://...", "expires_at": "...", "quota_bytes": N}
//	GET  /guest-status  → {"available": true, "active": 1, "max": 3,
//	                       "month_sent_bytes": N, "month_cap_bytes": N, "resets_at": "..."}
//
// Guests are created through the registry, the same way `vpn invite` adds
// devices. Abuse limits: a few keys per client IP per day, a cap on active
// guests, a global cap on keys per minute, tiny request bodies, and
// timeouts. Every issued key is logged with the time, guest name and the
// requesting IP.
package guestapi

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/vhittuvalli/vpn/internal/budget"
	"github.com/vhittuvalli/vpn/internal/config"
	"github.com/vhittuvalli/vpn/internal/registry"
)

const (
	maxBody         = 1 << 10 // bytes; requests carry no meaningful body
	window          = 24 * time.Hour
	globalPerMinute = 30
)

// Handler serves the endpoint.
type Handler struct {
	Registry registry.Registry
	// Settings returns the current guest settings (they change on reload).
	Settings func() config.Guests
	// OnIssue is called after a guest is added, to load it into the running
	// server.
	OnIssue func()
	// LogPath is where issued keys are recorded, one JSON line each.
	LogPath string
	// Budget reports this month's transfer against the cap; while it's
	// exceeded (or unknown) no keys are issued. Nil means no cap.
	Budget func() budget.Usage
	Now    func() time.Time

	mu       sync.Mutex
	byClient map[string][]time.Time // issue times in the last 24 h, per client
	recent   []time.Time            // issue times in the last minute, all clients
	loaded   bool
}

// IssueRecord is one line of the issue log.
type IssueRecord struct {
	Time      time.Time `json:"time"`
	Name      string    `json:"name"`
	IP        string    `json:"ip"`
	ExpiresAt string    `json:"expires_at"`
}

type keyResponse struct {
	Key        string `json:"key"`
	ExpiresAt  string `json:"expires_at"`
	QuotaBytes uint64 `json:"quota_bytes"`
}

type statusResponse struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"` // when not available: disabled, full or budget
	Active    int    `json:"active"`
	Max       int    `json:"max"`

	// This month's transfer for the whole server, against the cap.
	MonthSentBytes uint64 `json:"month_sent_bytes,omitempty"`
	MonthCapBytes  uint64 `json:"month_cap_bytes,omitempty"`
	ResetsAt       string `json:"resets_at,omitempty"`
}

type errorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	h.cors(w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	switch r.URL.Path {
	case "/guest-key":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
			return
		}
		h.issue(w, r)
	case "/guest-status":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
			return
		}
		h.status(w)
	default:
		writeError(w, http.StatusNotFound, "not_found", "nothing here")
	}
}

// cors lets the allowed web pages read responses. Other origins get no CORS
// headers, so browsers block them; the abuse limits apply to everyone.
func (h *Handler) cors(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "Origin")
	origin := r.Header.Get("Origin")
	if origin == "" || !slices.Contains(h.Settings().AllowedOrigins, origin) {
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Max-Age", "600")
	}
}

func (h *Handler) issue(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if _, err := io.Copy(io.Discard, r.Body); err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", "request body too large")
		return
	}
	settings := h.Settings()
	if !settings.Enabled {
		writeError(w, http.StatusServiceUnavailable, "disabled", "guest access is turned off right now")
		return
	}
	if h.Budget != nil {
		if u := h.Budget(); u.Exceeded() {
			w.Header().Set("Retry-After", strconv.Itoa(int(time.Until(u.ResetsAt).Seconds())+1))
			writeError(w, http.StatusServiceUnavailable, "budget", "this month's demo bandwidth is used up; guest keys come back on "+u.ResetsAt.Format("January 2"))
			return
		}
	}
	ip, client := clientOf(r)
	now := h.now()

	// Reserve this client's slot before the slow part, so parallel
	// requests can't slip past the limit; give it back on failure.
	h.mu.Lock()
	h.loadLog(now)
	h.prune(now)
	if settings.PerIPPerDay > 0 && len(h.byClient[client]) >= settings.PerIPPerDay {
		retry := h.byClient[client][0].Add(window).Sub(now)
		h.mu.Unlock()
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "rate_limited",
			fmt.Sprintf("you've already had %d guest keys today", settings.PerIPPerDay))
		return
	}
	if len(h.recent) >= globalPerMinute {
		h.mu.Unlock()
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusServiceUnavailable, "busy", "lots of people are asking right now; try again in a minute")
		return
	}
	h.byClient[client] = append(h.byClient[client], now)
	h.recent = append(h.recent, now)
	h.mu.Unlock()

	added, err := h.Registry.AddGuest(now)
	if err != nil {
		h.release(client, now)
		switch {
		case errors.Is(err, registry.ErrGuestsFull), errors.Is(err, registry.ErrNoAddress):
			w.Header().Set("Retry-After", "300")
			writeError(w, http.StatusServiceUnavailable, "full", "all guest slots are in use; try again later")
		case errors.Is(err, registry.ErrGuestsDisabled):
			writeError(w, http.StatusServiceUnavailable, "disabled", "guest access is turned off right now")
		default:
			log.Printf("guest key: %v", err)
			writeError(w, http.StatusInternalServerError, "error", "something went wrong on the server")
		}
		return
	}
	if h.OnIssue != nil {
		h.OnIssue()
	}
	rec := IssueRecord{Time: now.UTC(), Name: added.Peer.Name, IP: ip.String(), ExpiresAt: added.Peer.ExpiresAt}
	if err := h.appendLog(rec); err != nil {
		log.Printf("guest key log: %v", err)
	}
	log.Printf("guest key issued: %s to %s, expires %s", rec.Name, rec.IP, rec.ExpiresAt)
	writeJSON(w, http.StatusOK, keyResponse{Key: added.Key.String(), ExpiresAt: added.Peer.ExpiresAt, QuotaBytes: added.Peer.QuotaBytes})
}

func (h *Handler) status(w http.ResponseWriter) {
	enabled, active, max, err := h.Registry.GuestCount(h.now())
	if err != nil {
		log.Printf("guest status: %v", err)
		writeError(w, http.StatusInternalServerError, "error", "something went wrong on the server")
		return
	}
	resp := statusResponse{Active: active, Max: max}
	over := false
	if h.Budget != nil {
		u := h.Budget()
		over = u.Exceeded()
		resp.MonthSentBytes, resp.MonthCapBytes = u.SentBytes, u.CapBytes
		resp.ResetsAt = u.ResetsAt.Format(time.RFC3339)
	}
	switch {
	case !enabled:
		resp.Reason = "disabled"
	case over:
		resp.Reason = "budget"
	case active >= max:
		resp.Reason = "full"
	default:
		resp.Available = true
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) release(client string, t time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if i := slices.Index(h.byClient[client], t); i >= 0 {
		h.byClient[client] = slices.Delete(h.byClient[client], i, i+1)
	}
	if i := slices.Index(h.recent, t); i >= 0 {
		h.recent = slices.Delete(h.recent, i, i+1)
	}
}

// prune forgets issues older than the windows. h.mu must be held.
func (h *Handler) prune(now time.Time) {
	for c, times := range h.byClient {
		times = slices.DeleteFunc(times, func(t time.Time) bool { return now.Sub(t) >= window })
		if len(times) == 0 {
			delete(h.byClient, c)
		} else {
			h.byClient[c] = times
		}
	}
	h.recent = slices.DeleteFunc(h.recent, func(t time.Time) bool { return now.Sub(t) >= time.Minute })
}

// loadLog seeds the per-client counts from the issue log once, so a
// restart doesn't reset anyone's daily limit. h.mu must be held.
func (h *Handler) loadLog(now time.Time) {
	if h.loaded {
		return
	}
	h.loaded = true
	h.byClient = map[string][]time.Time{}
	f, err := os.Open(h.LogPath)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var rec IssueRecord
		if json.Unmarshal(sc.Bytes(), &rec) != nil || now.Sub(rec.Time) >= window {
			continue
		}
		if ip, err := netip.ParseAddr(rec.IP); err == nil {
			c := clientKey(ip)
			h.byClient[c] = append(h.byClient[c], rec.Time)
		}
	}
}

func (h *Handler) appendLog(rec IssueRecord) error {
	if h.LogPath == "" {
		return nil
	}
	f, err := os.OpenFile(h.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	line, _ := json.Marshal(rec)
	_, err = f.Write(append(line, '\n'))
	return err
}

// clientOf returns the caller's IP and the key it is rate limited under.
// The endpoint is reached directly, never through a proxy, so the TCP peer
// address is the client; forwarding headers are ignored since anyone can
// set them.
func clientOf(r *http.Request) (netip.Addr, string) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, r.RemoteAddr
	}
	ip = ip.Unmap()
	return ip, clientKey(ip)
}

// clientKey groups IPv6 clients by /64, since one home or phone usually has
// a whole /64 to pick addresses from.
func clientKey(ip netip.Addr) string {
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.String()
	}
	return ip.String()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorResponse{Error: msg, Code: code})
}
