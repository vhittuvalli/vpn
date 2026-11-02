package budget

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

type fakeCounter struct {
	n   uint64
	err error
}

func (f *fakeCounter) read() (uint64, error) { return f.n, f.err }

func newMeter(t *testing.T) (*Meter, *fakeCounter, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "usage.json")
	c := &fakeCounter{}
	return &Meter{Path: path, Read: c.read}, c, path
}

var nov = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

func TestAccumulates(t *testing.T) {
	m, c, _ := newMeter(t)
	c.n = 1000 // first run counts everything since boot
	m.Sample(nov)
	c.n = 1500
	m.Sample(nov.Add(30 * time.Second))
	c.n = 4500
	m.Sample(nov.Add(time.Minute))
	if u := m.Usage(nov.Add(time.Minute), 10_000); u.SentBytes != 4500 || u.Exceeded() {
		t.Fatalf("usage %+v", u)
	}
	c.n = 10_000
	m.Sample(nov.Add(2 * time.Minute))
	if u := m.Usage(nov.Add(2*time.Minute), 10_000); !u.Exceeded() {
		t.Fatalf("cap reached but not exceeded: %+v", u)
	}
}

func TestRebootAndRestart(t *testing.T) {
	m, c, path := newMeter(t)
	c.n = 5000
	m.Sample(nov)
	c.n = 8000
	m.Sample(nov.Add(time.Minute))

	// The server restarts: a new meter picks up the saved total.
	m2 := &Meter{Path: path, Read: c.read}
	c.n = 9000
	m2.Sample(nov.Add(2 * time.Minute))
	if u := m2.Usage(nov.Add(2*time.Minute), 1<<40); u.SentBytes != 9000 {
		t.Fatalf("after restart: %d, want 9000", u.SentBytes)
	}

	// The machine reboots: the counter starts over, and all of it is new.
	c.n = 700
	m2.Sample(nov.Add(time.Hour))
	if u := m2.Usage(nov.Add(time.Hour), 1<<40); u.SentBytes != 9700 {
		t.Fatalf("after reboot: %d, want 9700", u.SentBytes)
	}
}

func TestNewMonth(t *testing.T) {
	m, c, _ := newMeter(t)
	c.n = 5000
	m.Sample(nov)
	dec := time.Date(2026, 12, 1, 0, 0, 10, 0, time.UTC)
	if u := m.Usage(dec, 10_000); u.SentBytes != 0 || !u.ResetsAt.Equal(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("new month before a sample: %+v", u)
	}
	c.n = 5300
	m.Sample(dec)
	if u := m.Usage(dec, 10_000); u.SentBytes != 300 {
		t.Fatalf("new month: %d, want 300", u.SentBytes)
	}
}

// If the counter can't be read, guests are cut off rather than risk a bill.
func TestFailsClosed(t *testing.T) {
	m, c, _ := newMeter(t)
	if u := m.Usage(nov, 1<<40); !u.Exceeded() {
		t.Fatal("unknown usage must count as exceeded")
	}
	c.err = errors.New("no such interface")
	if err := m.Sample(nov); err == nil {
		t.Fatal("expected the read error")
	}
	if !m.Usage(nov, 1<<40).Exceeded() {
		t.Fatal("unreadable counter must count as exceeded")
	}
	c.err = nil
	c.n = 10
	m.Sample(nov)
	if m.Usage(nov, 1<<40).Exceeded() {
		t.Fatal("known and under the cap")
	}
}

func TestStateFile(t *testing.T) {
	m, c, path := newMeter(t)
	c.n = 42
	m.Sample(nov)
	st, err := ReadState(path)
	if err != nil || st.Month != "2026-11" || st.SentBytes != 42 {
		t.Fatalf("%+v, %v", st, err)
	}
	// Windows has no Unix permission bits.
	if info, _ := os.Stat(path); runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("permissions %v", info.Mode().Perm())
	}
}

func TestInterfaceCounterNeedsInterface(t *testing.T) {
	if _, err := InterfaceCounter("")(); err == nil {
		t.Fatal("expected an error without an interface")
	}
}

// The kernel writes the counter as a decimal number and a newline.
func TestReadCounter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tx_bytes")
	os.WriteFile(path, []byte("229829728\n"), 0o644)
	if n, err := readCounter(path); err != nil || n != 229829728 {
		t.Fatalf("got %d, %v", n, err)
	}
	os.WriteFile(path, []byte("garbage\n"), 0o644)
	if _, err := readCounter(path); err == nil {
		t.Fatal("parsed garbage")
	}
}
