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

// DefaultLoadThreshold is how many handshakes per second the server handles
// before it starts demanding cookies.
const DefaultLoadThreshold = 50

type Server struct {
	id         *protocol.Identity
	dev        tun.Device
	transports []ServerTransport
	peersByKey map[protocol.PublicKey]*serverPeer
	peersByIP  map[netip.Addr]*serverPeer
	cookies    *protocol.CookieChecker
	fragments  *protocol.Reassembler[Endpoint]

	// LoadThreshold may be changed before Run (tests set it to 0 so cookies
	// are always required).
	LoadThreshold int

	mu       sync.RWMutex
	sessions map[uint32]*serverSession // by our local index

	loadMu       sync.Mutex
	loadWindow   time.Time
	loadCount    int
	lastBySource map[string]time.Time
}

type serverPeer struct {
	name      string
	publicKey protocol.PublicKey
	ip        netip.Addr

	mu            sync.Mutex
	endpoint      Endpoint // where the peer last sent from
	current       *protocol.Session
	previous      *protocol.Session // kept briefly so in-flight packets survive a rekey
	lastTimestamp protocol.Timestamp
}

type serverSession struct {
	*protocol.Session
	peer *serverPeer
}

func NewServer(cfg *config.Server, dev tun.Device, transports ...ServerTransport) *Server {
	id := protocol.NewIdentity(cfg.PrivateKey)
	s := &Server{
		id:            id,
		dev:           dev,
		transports:    transports,
		peersByKey:    map[protocol.PublicKey]*serverPeer{},
		peersByIP:     map[netip.Addr]*serverPeer{},
		cookies:       protocol.NewCookieChecker(id.Public),
		fragments:     protocol.NewReassembler[Endpoint](),
		LoadThreshold: DefaultLoadThreshold,
		sessions:      map[uint32]*serverSession{},
		lastBySource:  map[string]time.Time{},
	}
	for _, p := range cfg.Peers {
		sp := &serverPeer{name: p.Name, publicKey: p.PublicKey, ip: p.Address}
		s.peersByKey[p.PublicKey] = sp
		s.peersByIP[p.Address] = sp
	}
	return s
}

// Run serves until ctx is canceled or the device or a transport fails.
func (s *Server) Run(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		for _, t := range s.transports {
			t.Close()
		}
		s.dev.Close()
	}()
	go s.expireSessions(ctx)
	loops := []func() error{s.tunLoop}
	for _, t := range s.transports {
		loops = append(loops, func() error { return s.receiveLoop(t) })
	}
	err := firstError(loops...)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (s *Server) receiveLoop(t ServerTransport) error {
	buf := make([]byte, 65535)
	for {
		n, ep, err := t.Receive(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		msg := buf[:n]
		switch msg[0] {
		case protocol.TypeData:
			s.handleData(msg, ep)
		case protocol.TypeFragment:
			if whole, ok := s.fragments.Add(ep, msg); ok && whole[0] == protocol.TypeInitiation {
				s.handleInitiation(whole, ep)
			}
		}
	}
}

func (s *Server) handleInitiation(msg []byte, ep Endpoint) {
	if !s.cookies.CheckMAC1(msg) {
		return // sender doesn't know our public key
	}
	if s.underLoad() {
		if !s.cookies.CheckMAC2(msg, ep.String()) {
			if reply, err := s.cookies.CreateReply(msg, ep.String()); err == nil {
				ep.Send(reply)
			}
			return
		}
		if !s.allowSource(ep) {
			return
		}
	}

	init, err := protocol.ConsumeInitiation(s.id, msg, func(k protocol.PublicKey) bool {
		return s.peersByKey[k] != nil
	})
	if err == protocol.ErrUnknownPeer {
		log.Printf("rejected handshake from %s: unknown public key", ep)
		return
	}
	if err != nil {
		return
	}
	p := s.peersByKey[init.Peer]
	p.mu.Lock()
	if !init.Timestamp.After(p.lastTimestamp) {
		p.mu.Unlock()
		log.Printf("rejected handshake for %s from %s: replayed", p.name, ep)
		return
	}
	p.lastTimestamp = init.Timestamp
	p.mu.Unlock()

	index := s.reserveIndex()
	sess, resp, err := init.CreateResponse(s.id, index)
	if err != nil {
		s.dropIndex(index)
		return
	}
	protocol.AddMACs(resp, p.publicKey, nil)
	s.mu.Lock()
	s.sessions[index] = &serverSession{Session: sess, peer: p}
	s.mu.Unlock()

	p.mu.Lock()
	stale := p.previous
	p.previous, p.current = p.current, sess
	fresh := p.endpoint != ep
	p.endpoint = ep
	p.mu.Unlock()
	if stale != nil {
		s.dropIndex(stale.LocalIndex)
	}

	for _, frag := range protocol.Fragment(resp) {
		if err := ep.Send(frag); err != nil {
			log.Printf("sending handshake response to %s: %v", p.name, err)
			return
		}
	}
	if fresh {
		log.Printf("peer %s (%s) connected from %s", p.name, p.ip, ep)
	}
}

// underLoad counts handshakes in the current one-second window.
func (s *Server) underLoad() bool {
	s.loadMu.Lock()
	defer s.loadMu.Unlock()
	if time.Since(s.loadWindow) > time.Second {
		s.loadWindow, s.loadCount = time.Now(), 0
	}
	s.loadCount++
	return s.loadCount > s.LoadThreshold
}

// allowSource lets each source IP start at most one handshake per second
// while the server is under load.
func (s *Server) allowSource(ep Endpoint) bool {
	host, _, err := net.SplitHostPort(ep.String())
	if err != nil {
		host = ep.String()
	}
	s.loadMu.Lock()
	defer s.loadMu.Unlock()
	if time.Since(s.lastBySource[host]) < time.Second {
		return false
	}
	s.lastBySource[host] = time.Now()
	return true
}

func (s *Server) handleData(msg []byte, ep Endpoint) {
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
	if p.endpoint != ep {
		log.Printf("peer %s moved to %s", p.name, ep)
		p.endpoint = ep
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
		if sess == nil || ep == nil {
			continue // peer not connected
		}
		out, err := sess.Seal(buf[:n])
		if err != nil {
			continue
		}
		ep.Send(out)
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
		s.loadMu.Lock()
		for host, last := range s.lastBySource {
			if time.Since(last) > time.Second {
				delete(s.lastBySource, host)
			}
		}
		s.loadMu.Unlock()
		for _, p := range s.peersByKey {
			p.mu.Lock()
			if p.previous != nil && p.previous.Expired() {
				p.previous = nil
			}
			if p.current != nil && p.current.Expired() {
				p.current = nil
				p.endpoint = nil
				log.Printf("peer %s disconnected (no handshake for %s)", p.name, protocol.RejectAfterTime)
			}
			p.mu.Unlock()
		}
	}
}
