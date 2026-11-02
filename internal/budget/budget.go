// Package budget keeps a server within its hosting plan's monthly transfer
// allowance. It counts everything the server sends to the internet in the
// current calendar month (UTC), the way DigitalOcean bills outbound
// transfer, so guests can be cut off before they could cause any charge.
//
// The count comes from the network interface's byte counter, sampled
// periodically. The running total is saved to disk, so restarts and
// reboots (which reset the kernel's counter) don't lose it.
package budget

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"
)

// State is what's saved between samples.
type State struct {
	Month       string    `json:"month"`        // "2026-11"
	SentBytes   uint64    `json:"sent_bytes"`   // sent to the internet this month
	LastCounter uint64    `json:"last_counter"` // interface counter at the last sample
	Updated     time.Time `json:"updated"`
}

// Usage is the month so far, for display.
type Usage struct {
	SentBytes uint64
	CapBytes  uint64
	ResetsAt  time.Time
	Known     bool // false until the counter has been read successfully
}

// Exceeded reports whether guests must be cut off: the cap is reached, or
// the count isn't known (it fails closed, so a broken meter can't cost
// money).
func (u Usage) Exceeded() bool { return !u.Known || u.SentBytes >= u.CapBytes }

// Meter samples a byte counter into a monthly total.
type Meter struct {
	Path string                 // where State is saved
	Read func() (uint64, error) // the interface's transmit counter

	mu     sync.Mutex
	state  State
	loaded bool
	known  bool
}

// Sample reads the counter, adds what was sent since the last sample to
// this month's total, and saves it.
func (m *Meter) Sample(now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.loaded {
		m.loaded = true
		if st, err := ReadState(m.Path); err == nil {
			m.state = st
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	counter, err := m.Read()
	if err != nil {
		m.known = false
		return err
	}
	month := Month(now)
	fresh := m.state.Updated.IsZero()
	if m.state.Month != month {
		m.state.SentBytes, m.state.Month = 0, month
	}
	switch {
	case fresh:
		// First run: the counter covers everything since boot, which may
		// include earlier months. Count it all; overcounting is the safe
		// direction.
		m.state.SentBytes += counter
	case counter >= m.state.LastCounter:
		m.state.SentBytes += counter - m.state.LastCounter
	default:
		// The counter went backwards: the machine rebooted (or the
		// interface was reset), so everything it shows is new.
		m.state.SentBytes += counter
	}
	m.state.LastCounter, m.state.Updated = counter, now.UTC()
	m.known = true
	return writeState(m.Path, m.state)
}

// Usage reports the month so far against capBytes.
func (m *Meter) Usage(now time.Time, capBytes uint64) Usage {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := Usage{CapBytes: capBytes, ResetsAt: NextMonth(now), Known: m.known}
	if m.state.Month == Month(now) {
		u.SentBytes = m.state.SentBytes
	}
	return u
}

// Month names the calendar month (UTC) that now falls in.
func Month(now time.Time) string { return now.UTC().Format("2006-01") }

// NextMonth is when the current month's count starts over.
func NextMonth(now time.Time) time.Time {
	y, mo, _ := now.UTC().Date()
	return time.Date(y, mo+1, 1, 0, 0, 0, 0, time.UTC)
}

// ReadState reads the saved total (for `vpn guests`).
func ReadState(path string) (State, error) {
	var st State
	data, err := os.ReadFile(path)
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(data, &st)
}

func writeState(path string, st State) error {
	data, _ := json.MarshalIndent(st, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// InterfaceCounter returns a reader for a Linux interface's transmit byte
// counter, e.g. "eth0".
func InterfaceCounter(iface string) func() (uint64, error) {
	return func() (uint64, error) {
		if iface == "" {
			return 0, errors.New("no internet interface configured (nat_interface)")
		}
		return readCounter("/sys/class/net/" + iface + "/statistics/tx_bytes")
	}
}
