package vpn

import (
	"context"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/vhittuvalli/vpn/internal/config"
	"github.com/vhittuvalli/vpn/internal/protocol"
	"github.com/vhittuvalli/vpn/internal/tun"
)

type Server struct {
	static     protocol.Key
	dev        tun.Device
	conn       *net.UDPConn
	peersByKey map[protocol.Key]*serverPeer
	peersByIP  map[netip.Addr]*serverPeer

	mu       sync.RWMutex
	sessions map[uint32]*serverSession // by our local index
}

type serverPeer struct {
	name      string
	publicKey protocol.Key
	ip        netip.Addr

	mu            sync.Mutex
	endpoint      netip.AddrPort // where the peer last sent from
	current       *protocol.Session
	previous      *protocol.Session // kept briefly so in-flight packets survive a rekey
	lastTimestamp protocol.Timestamp
}

type serverSession struct {
	*protocol.Session
	peer *serverPeer
}

func NewServer(cfg *config.Server, dev tun.Device, conn *net.UDPConn) *Server {
	s := &Server{
		static:     cfg.PrivateKey,
		dev:        dev,
		conn:       conn,
		peersByKey: map[protocol.Key]*serverPeer{},
		peersByIP:  map[netip.Addr]*serverPeer{},
		sessions:   map[uint32]*serverSession{},
	}
	for _, p := range cfg.Peers {
		sp := &serverPeer{name: p.Name, publicKey: p.PublicKey, ip: p.Address}
		s.peersByKey[p.PublicKey] = sp
		s.peersByIP[p.Address] = sp
	}
	return s
}

// Run serves until ctx is canceled or the device or socket fails.
func (s *Server) Run(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		s.conn.Close()
		s.dev.Close()
	}()
	go s.expireSessions(ctx)
	err := firstError(s.udpLoop, s.tunLoop)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (s *Server) udpLoop() error {
	buf := make([]byte, 65535)
	for {
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return err
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		if n == 0 {
			continue
		}
		switch buf[0] {
		case protocol.TypeInitiation:
			s.handleInitiation(buf[:n], from)
		case protocol.TypeData:
			s.handleData(buf[:n], from)
		}
	}
}

func (s *Server) handleInitiation(msg []byte, from netip.AddrPort) {
	init, err := protocol.ConsumeInitiation(s.static, msg)
	if err != nil {
		return // not for us, or forged
	}
	p := s.peersByKey[init.PeerStatic]
	if p == nil {
		log.Printf("rejected handshake from %s: unknown public key %s", from, init.PeerStatic)
		return
	}
	p.mu.Lock()
	if !init.Timestamp.After(p.lastTimestamp) {
		p.mu.Unlock()
		log.Printf("rejected handshake for %s from %s: replayed", p.name, from)
		return
	}
	p.lastTimestamp = init.Timestamp
	p.mu.Unlock()

	index := s.reserveIndex()
	sess, resp, err := init.CreateResponse(index)
	if err != nil {
		s.dropIndex(index)
		return
	}
	s.mu.Lock()
	s.sessions[index] = &serverSession{Session: sess, peer: p}
	s.mu.Unlock()

	p.mu.Lock()
	stale := p.previous
	p.previous, p.current = p.current, sess
	fresh := p.endpoint != from
	p.endpoint = from
	p.mu.Unlock()
	if stale != nil {
		s.dropIndex(stale.LocalIndex)
	}

	if _, err := s.conn.WriteToUDPAddrPort(resp, from); err != nil {
		log.Printf("sending handshake response to %s: %v", p.name, err)
		return
	}
	if fresh {
		log.Printf("peer %s (%s) connected from %s", p.name, p.ip, from)
	}
}

func (s *Server) handleData(msg []byte, from netip.AddrPort) {
	index, ok := protocol.ReceiverIndex(msg)
	if !ok {
		return
	}
	s.mu.RLock()
	ss := s.sessions[index]
	s.mu.RUnlock()
	if ss == nil {
		return
	}
	packet, err := ss.Open(msg)
	if err != nil {
		return
	}
	p := ss.peer
	p.mu.Lock()
	if p.endpoint != from {
		log.Printf("peer %s moved to %s", p.name, from)
		p.endpoint = from
	}
	p.mu.Unlock()
	if len(packet) == 0 {
		return // keepalive
	}
	// A peer may only send from its own tunnel address; otherwise one client
	// could impersonate another.
	if src, ok := ipv4Src(packet); !ok || src != p.ip {
		return
	}
	if _, err := s.dev.Write(packet); err != nil {
		log.Printf("writing to %s: %v", s.dev.Name(), err)
	}
}

func (s *Server) tunLoop() error {
	buf := make([]byte, 65535)
	for {
		n, err := s.dev.Read(buf)
		if err != nil {
			return err
		}
		dst, ok := ipv4Dst(buf[:n])
		if !ok {
			continue
		}
		p := s.peersByIP[dst]
		if p == nil {
			continue
		}
		p.mu.Lock()
		sess, ep := p.current, p.endpoint
		p.mu.Unlock()
		if sess == nil || !ep.IsValid() {
			continue // peer not connected
		}
		out, err := sess.Seal(buf[:n])
		if err != nil {
			continue
		}
		s.conn.WriteToUDPAddrPort(out, ep)
	}
}

func (s *Server) reserveIndex() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		i := protocol.RandomIndex()
		if _, taken := s.sessions[i]; !taken {
			s.sessions[i] = nil
			return i
		}
	}
}

func (s *Server) dropIndex(i uint32) {
	s.mu.Lock()
	delete(s.sessions, i)
	s.mu.Unlock()
}

func (s *Server) expireSessions(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.mu.Lock()
		for i, ss := range s.sessions {
			if ss != nil && ss.Expired() {
				delete(s.sessions, i)
			}
		}
		s.mu.Unlock()
		for _, p := range s.peersByKey {
			p.mu.Lock()
			if p.previous != nil && p.previous.Expired() {
				p.previous = nil
			}
			if p.current != nil && p.current.Expired() {
				p.current = nil
				log.Printf("peer %s disconnected (no handshake for %s)", p.name, protocol.RejectAfterTime)
				p.endpoint = netip.AddrPort{}
			}
			p.mu.Unlock()
		}
	}
}
