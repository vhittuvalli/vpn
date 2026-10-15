package vpn

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

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
			t.Fatalf("delivered %d bytes %.40x..., want %d bytes %.40x...", len(got), got, len(want), want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("packet never arrived")
	}
}

func (f *fakeTun) expectNothing(t *testing.T) {
	t.Helper()
	select {
	case got := <-f.toOS:
		t.Fatalf("unexpected packet delivered: %x", got)
	case <-time.After(300 * time.Millisecond):
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

func privateKey(t *testing.T) protocol.PrivateKey {
	k, err := protocol.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type testNet struct {
	server, client       *fakeTun
	clientVPN            *Client
	serverVPN            *Server
	clientConn           ClientTransport
	serverKey, clientKey protocol.PrivateKey
}

// start runs a server and a connected client over the given transport.
func start(t *testing.T, transport string, loadThreshold int) *testNet {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	tn := &testNet{server: newFakeTun(), client: newFakeTun(), serverKey: privateKey(t), clientKey: privateKey(t)}
	serverPub := tn.serverKey.Public()

	var st ServerTransport
	var addr string
	switch transport {
	case "udp":
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		st, addr = NewUDPServer(conn), conn.LocalAddr().String()
	case "https":
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		cert, err := SelfSignedCert("localhost")
		if err != nil {
			t.Fatal(err)
		}
		st, addr = NewHTTPSServer(pc, cert, serverPub), pc.LocalAddr().String()
	}
	server := NewServer(&config.Server{
		PrivateKey: tn.serverKey,
		Address:    netip.MustParsePrefix("10.8.0.1/24"),
		Peers: []config.Peer{{
			Name: "laptop", PublicKey: tn.clientKey.Public(), Address: netip.MustParseAddr("10.8.0.2"),
		}},
	}, tn.server, st)
	server.LoadThreshold = loadThreshold
	tn.serverVPN = server
	go server.Run(ctx)

	switch transport {
	case "udp":
		raddr, _ := net.ResolveUDPAddr("udp4", addr)
		conn, err := net.DialUDP("udp4", nil, raddr)
		if err != nil {
			t.Fatal(err)
		}
		tn.clientConn = UDPClient{conn}
	case "https":
		tn.clientConn = NewHTTPSClient(addr, "localhost", serverPub)
	}
	tn.clientVPN = NewClient(&config.Client{PrivateKey: tn.clientKey, ServerPublicKey: serverPub}, tn.client, tn.clientConn)
	connected := make(chan struct{})
	tn.clientVPN.OnConnect = func() { close(connected) }
	go tn.clientVPN.Run(ctx)

	select {
	case <-connected:
	case <-time.After(10 * time.Second):
		t.Fatal("handshake never completed")
	}
	return tn
}

func TestEndToEnd(t *testing.T) {
	for _, transport := range []string{"udp", "https"} {
		t.Run(transport, func(t *testing.T) {
			tn := start(t, transport, DefaultLoadThreshold)

			up := ipv4Packet("10.8.0.2", "10.8.0.1", "ping")
			tn.client.fromOS <- up
			tn.server.expect(t, up)

			down := ipv4Packet("10.8.0.1", "10.8.0.2", "pong")
			tn.server.fromOS <- down
			tn.client.expect(t, down)

			// A full-size packet still fits in one datagram.
			mtu := config.DefaultMTU
			if transport == "https" {
				mtu = config.HTTPSMTU
			}
			big := ipv4Packet("10.8.0.2", "10.8.0.1", strings.Repeat("x", mtu-20))
			tn.client.fromOS <- big
			tn.server.expect(t, big)

			// A client claiming another tunnel address is dropped by the server.
			tn.client.fromOS <- ipv4Packet("10.8.0.99", "10.8.0.1", "spoofed")
			tn.server.expectNothing(t)
		})
	}
}

func TestCookiesUnderLoad(t *testing.T) {
	// A threshold of 0 means every handshake needs a cookie first.
	for _, transport := range []string{"udp", "https"} {
		t.Run(transport, func(t *testing.T) {
			tn := start(t, transport, 0)
			tn.clientVPN.mu.Lock()
			gotCookie := tn.clientVPN.cookie != nil
			tn.clientVPN.mu.Unlock()
			if !gotCookie {
				t.Fatal("client connected without going through the cookie exchange")
			}
			up := ipv4Packet("10.8.0.2", "10.8.0.1", "made it")
			tn.client.fromOS <- up
			tn.server.expect(t, up)
		})
	}
}

func TestReplayDropped(t *testing.T) {
	tn := start(t, "udp", DefaultLoadThreshold)
	tn.clientVPN.mu.Lock()
	sess := tn.clientVPN.current
	tn.clientVPN.mu.Unlock()
	pkt := ipv4Packet("10.8.0.2", "10.8.0.1", "again")
	msg, _ := sess.Seal(pkt)
	tn.clientConn.Write(msg)
	tn.server.expect(t, pkt)
	tn.clientConn.Write(msg)
	tn.server.expectNothing(t)
}

func TestPeerChangesWhileRunning(t *testing.T) {
	tn := start(t, "udp", DefaultLoadThreshold)
	laptop := config.Peer{Name: "laptop", PublicKey: tn.clientKey.Public(), Address: netip.MustParseAddr("10.8.0.2")}
	phone := config.Peer{Name: "phone", PublicKey: privateKey(t).Public(), Address: netip.MustParseAddr("10.8.0.3")}

	// Adding a device leaves the connected one alone.
	if added, removed := tn.serverVPN.SetPeers([]config.Peer{laptop, phone}); added != 1 || removed != 0 {
		t.Fatalf("adding phone: added %d, removed %d", added, removed)
	}
	up := ipv4Packet("10.8.0.2", "10.8.0.1", "still here")
	tn.client.fromOS <- up
	tn.server.expect(t, up)

	// Revoking it cuts it off immediately, in both directions.
	if added, removed := tn.serverVPN.SetPeers([]config.Peer{phone}); added != 0 || removed != 1 {
		t.Fatalf("revoking laptop: added %d, removed %d", added, removed)
	}
	tn.client.fromOS <- ipv4Packet("10.8.0.2", "10.8.0.1", "revoked")
	tn.server.expectNothing(t)
	tn.server.fromOS <- ipv4Packet("10.8.0.1", "10.8.0.2", "revoked")
	tn.client.expectNothing(t)
}

func TestUnknownClientRejected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverKey, allowedKey, strangerKey := privateKey(t), privateKey(t), privateKey(t)
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(&config.Server{
		PrivateKey: serverKey,
		Address:    netip.MustParsePrefix("10.8.0.1/24"),
		Peers:      []config.Peer{{Name: "ok", PublicKey: allowedKey.Public(), Address: netip.MustParseAddr("10.8.0.2")}},
	}, newFakeTun(), NewUDPServer(conn))
	go server.Run(ctx)

	client, _ := net.DialUDP("udp4", nil, conn.LocalAddr().(*net.UDPAddr))
	hs, _ := protocol.CreateInitiation(protocol.NewIdentity(strangerKey), serverKey.Public(), 1, time.Now())
	protocol.AddMACs(hs.Message, serverKey.Public(), nil)
	for _, f := range protocol.Fragment(hs.Message) {
		client.Write(f)
	}
	client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if n, err := client.Read(make([]byte, 1500)); err == nil {
		t.Fatalf("server answered an unknown client with %d bytes", n)
	}
}

func TestHTTPSDecoy(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := SelfSignedCert("localhost")
	srv := NewHTTPSServer(pc, cert, privateKey(t).Public())
	defer srv.Close()

	rt := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer rt.Close()
	for _, path := range []string{"/", "/.well-known/masque/ip/"} {
		resp, err := (&http.Client{Transport: rt, Timeout: 5 * time.Second}).Get("https://" + pc.LocalAddr().String() + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(body), "It works!") {
			t.Fatalf("GET %s: %s %q, want the decoy page", path, resp.Status, body)
		}
	}
}
