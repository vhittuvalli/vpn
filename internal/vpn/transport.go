package vpn

import (
	"context"
	"net"
	"net/netip"

	"golang.org/x/net/ipv4"
)

// The protocol runs over any transport that carries datagrams: plain UDP, or
// HTTP/3 datagrams (see https.go) to look like ordinary web traffic.

// Endpoint is where the server sends messages for one peer connection.
// Implementations must be comparable so the server can tell when a peer
// has moved.
type Endpoint interface {
	Send(msg []byte) error
	String() string // an address, used for cookies and logs
}

// ServerTransport delivers messages from any client.
type ServerTransport interface {
	Receive(buf []byte) (int, Endpoint, error)
	Close() error
}

// ClientTransport carries messages to and from one server.
type ClientTransport interface {
	Read(buf []byte) (int, error)
	Write(msg []byte) (int, error)
	Close() error
	String() string
}

// readyWaiter is implemented by transports that need time to connect, so
// the first handshake isn't sent into the void.
type readyWaiter interface {
	WaitReady(ctx context.Context) error
}

// UDP

// UDPServer replies to each packet from the local address it arrived on.
// A server with several addresses (common on cloud VMs) would otherwise
// answer from whichever one the routing table picks, and clients and NAT
// routers drop replies from an address they didn't send to.
type UDPServer struct {
	conn *net.UDPConn
	pc   *ipv4.PacketConn
}

func NewUDPServer(conn *net.UDPConn) *UDPServer {
	pc := ipv4.NewPacketConn(conn)
	// Not every platform supports this; replies then use the default source.
	pc.SetControlMessage(ipv4.FlagDst, true)
	return &UDPServer{conn: conn, pc: pc}
}

func (s *UDPServer) Receive(buf []byte) (int, Endpoint, error) {
	n, cm, src, err := s.pc.ReadFrom(buf)
	if err != nil {
		return 0, nil, err
	}
	from := src.(*net.UDPAddr).AddrPort()
	ep := udpEndpoint{pc: s.pc, addr: netip.AddrPortFrom(from.Addr().Unmap(), from.Port())}
	if cm != nil {
		ep.local, _ = netip.AddrFromSlice(cm.Dst.To4())
	}
	return n, ep, nil
}

func (s *UDPServer) Close() error { return s.conn.Close() }

type udpEndpoint struct {
	pc    *ipv4.PacketConn
	addr  netip.AddrPort
	local netip.Addr // our address the peer sent to
}

func (e udpEndpoint) Send(msg []byte) error {
	var cm *ipv4.ControlMessage
	if e.local.IsValid() {
		cm = &ipv4.ControlMessage{Src: e.local.AsSlice()}
	}
	_, err := e.pc.WriteTo(msg, cm, net.UDPAddrFromAddrPort(e.addr))
	return err
}

func (e udpEndpoint) String() string { return e.addr.String() }

// UDPClient is a UDP socket connected to the server.
type UDPClient struct{ *net.UDPConn }

func (c UDPClient) String() string { return c.RemoteAddr().String() }
