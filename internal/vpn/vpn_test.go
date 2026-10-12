package vpn

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/vhittuvalli/vpn/internal/config"
	"github.com/vhittuvalli/vpn/internal/protocol"
)

// fakeTun stands in for a real TUN device: the test injects packets the
// "OS" sends (Read) and observes packets the VPN delivers (Write).
type fakeTun struct {
	fromOS chan []byte
	toOS   chan []byte
	closed chan struct{}
}

func newFakeTun() *fakeTun {
	return &fakeTun{make(chan []byte, 16), make(chan []byte, 16), make(chan struct{})}
}

func (f *fakeTun) Name() string { return "fake0" }

func (f *fakeTun) Read(p []byte) (int, error) {
	select {
	case pkt := <-f.fromOS:
		return copy(p, pkt), nil
	case <-f.closed:
		return 0, os.ErrClosed
	}
}

func (f *fakeTun) Write(p []byte) (int, error) {
	f.toOS <- bytes.Clone(p)
	return len(p), nil
}

func (f *fakeTun) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}

func (f *fakeTun) expect(t *testing.T, want []byte) {
	t.Helper()
	select {
	case got := <-f.toOS:
		if !bytes.Equal(got, want) {
			t.Fatalf("delivered %x, want %x", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("packet never arrived")
	}
}

func (f *fakeTun) expectNothing(t *testing.T) {
	t.Helper()
	select {
	case got := <-f.toOS:
		t.Fatalf("unexpected packet delivered: %x", got)
	case <-time.After(200 * time.Millisecond):
	}
}

func ipv4Packet(src, dst string, payload string) []byte {
	p := make([]byte, 20, 20+len(payload))
	p[0] = 0x45
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	return append(p, payload...)
}

func key(t *testing.T) protocol.Key {
	k, err := protocol.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestEndToEnd(t *testing.T) {
	serverKey, clientKey := key(t), key(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	serverTun := newFakeTun()
	server := NewServer(&config.Server{
		PrivateKey: serverKey,
		Address:    netip.MustParsePrefix("10.8.0.1/24"),
		Peers: []config.Peer{{
			Name: "laptop", PublicKey: clientKey.Public(), Address: netip.MustParseAddr("10.8.0.2"),
		}},
	}, serverTun, serverConn)
	go server.Run(ctx)

	clientConn, err := net.DialUDP("udp4", nil, serverConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	clientTun := newFakeTun()
	client := NewClient(&config.Client{PrivateKey: clientKey, ServerPublicKey: serverKey.Public()}, clientTun, clientConn)
	connected := make(chan struct{})
	client.OnConnect = func() { close(connected) }
	go client.Run(ctx)

	select {
	case <-connected:
	case <-time.After(3 * time.Second):
		t.Fatal("handshake never completed")
	}

	// Client -> server.
	up := ipv4Packet("10.8.0.2", "10.8.0.1", "ping")
	clientTun.fromOS <- up
	serverTun.expect(t, up)

	// Server -> client.
	down := ipv4Packet("10.8.0.1", "10.8.0.2", "pong")
	serverTun.fromOS <- down
	clientTun.expect(t, down)

	// A client claiming another tunnel address is dropped by the server.
	clientTun.fromOS <- ipv4Packet("10.8.0.99", "10.8.0.1", "spoofed")
	serverTun.expectNothing(t)

	// A raw replay of a captured data packet is dropped too.
	client.mu.Lock()
	sess := client.current
	client.mu.Unlock()
	msg, _ := sess.Seal(ipv4Packet("10.8.0.2", "10.8.0.1", "again"))
	clientConn.Write(msg)
	serverTun.expect(t, ipv4Packet("10.8.0.2", "10.8.0.1", "again"))
	clientConn.Write(msg)
	serverTun.expectNothing(t)
}

func TestUnknownClientRejected(t *testing.T) {
	serverKey, allowedKey, strangerKey := key(t), key(t), key(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(&config.Server{
		PrivateKey: serverKey,
		Address:    netip.MustParsePrefix("10.8.0.1/24"),
		Peers:      []config.Peer{{Name: "ok", PublicKey: allowedKey.Public(), Address: netip.MustParseAddr("10.8.0.2")}},
	}, newFakeTun(), serverConn)
	go server.Run(ctx)

	clientConn, _ := net.DialUDP("udp4", nil, serverConn.LocalAddr().(*net.UDPAddr))
	_, msg, _ := protocol.CreateInitiation(strangerKey, serverKey.Public(), 1, time.Now())
	clientConn.Write(msg)
	clientConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := clientConn.Read(make([]byte, 1500)); err == nil {
		t.Fatalf("server answered an unknown client with %d bytes", n)
	}
}
