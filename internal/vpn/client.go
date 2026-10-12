package vpn

import (
	"context"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vhittuvalli/vpn/internal/config"
	"github.com/vhittuvalli/vpn/internal/protocol"
	"github.com/vhittuvalli/vpn/internal/tun"
)

type Client struct {
	static    protocol.Key
	serverKey protocol.Key
	dev       tun.Device
	conn      *net.UDPConn // connected to the server

	mu          sync.Mutex
	pending     *protocol.InitiatorHandshake
	current     *protocol.Session
	previous    *protocol.Session
	established chan struct{}
	lastSent    atomic.Int64 // unix nanos

	// OnConnect, if set, is called once after the first handshake succeeds.
	OnConnect func()
}

func NewClient(cfg *config.Client, dev tun.Device, conn *net.UDPConn) *Client {
	return &Client{
		static:      cfg.PrivateKey,
		serverKey:   cfg.ServerPublicKey,
		dev:         dev,
		conn:        conn,
		established: make(chan struct{}, 1),
	}
}

// Run keeps the tunnel up until ctx is canceled or the device or socket fails.
func (c *Client) Run(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		c.conn.Close()
		c.dev.Close()
	}()
	go c.handshakeLoop(ctx)
	go c.keepaliveLoop(ctx)
	err := firstError(c.udpLoop, c.tunLoop)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// handshakeLoop performs the first handshake, retrying until the server
// answers, then repeats it every RekeyAfterTime so keys are short-lived.
func (c *Client) handshakeLoop(ctx context.Context) {
	connected := false
	for {
		hs, msg, err := protocol.CreateInitiation(c.static, c.serverKey, protocol.RandomIndex(), time.Now())
		if err != nil {
			log.Printf("creating handshake: %v", err)
			return
		}
		c.mu.Lock()
		c.pending = hs
		c.mu.Unlock()
		c.send(msg)

		wait := protocol.HandshakeRetry
		select {
		case <-ctx.Done():
			return
		case <-c.established:
			if !connected {
				connected = true
				log.Printf("connected to %s", c.conn.RemoteAddr())
				if c.OnConnect != nil {
					c.OnConnect()
				}
			}
			wait = protocol.RekeyAfterTime
		case <-time.After(protocol.HandshakeRetry):
			log.Printf("no handshake response from %s, retrying", c.conn.RemoteAddr())
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// keepaliveLoop sends an empty packet when the tunnel has been idle, so NAT
// routers between client and server keep the UDP mapping open.
func (c *Client) keepaliveLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if time.Since(time.Unix(0, c.lastSent.Load())) < protocol.KeepaliveInterval {
			continue
		}
		c.mu.Lock()
		sess := c.current
		c.mu.Unlock()
		if sess == nil {
			continue
		}
		if out, err := sess.Seal(nil); err == nil {
			c.send(out)
		}
	}
}

func (c *Client) udpLoop() error {
	buf := make([]byte, 65535)
	for {
		n, err := c.conn.Read(buf)
		if err != nil {
			return err
		}
		msg := buf[:n]
		index, ok := protocol.ReceiverIndex(msg)
		if !ok {
			continue
		}
		switch msg[0] {
		case protocol.TypeResponse:
			c.handleResponse(msg, index)
		case protocol.TypeData:
			c.mu.Lock()
			var sess *protocol.Session
			for _, s := range []*protocol.Session{c.current, c.previous} {
				if s != nil && s.LocalIndex == index {
					sess = s
				}
			}
			c.mu.Unlock()
			if sess == nil {
				continue
			}
			packet, err := sess.Open(msg)
			if err != nil || len(packet) == 0 {
				continue
			}
			if _, err := c.dev.Write(packet); err != nil {
				log.Printf("writing to %s: %v", c.dev.Name(), err)
			}
		}
	}
}

func (c *Client) handleResponse(msg []byte, index uint32) {
	c.mu.Lock()
	hs := c.pending
	if hs == nil || hs.LocalIndex != index {
		c.mu.Unlock()
		return
	}
	sess, err := hs.ConsumeResponse(msg)
	if err != nil {
		c.mu.Unlock()
		return
	}
	c.pending = nil
	c.previous, c.current = c.current, sess
	c.mu.Unlock()

	select {
	case c.established <- struct{}{}:
	default:
	}
	// Confirm the new session to the server right away.
	if out, err := sess.Seal(nil); err == nil {
		c.send(out)
	}
}

func (c *Client) tunLoop() error {
	buf := make([]byte, 65535)
	for {
		n, err := c.dev.Read(buf)
		if err != nil {
			return err
		}
		if _, ok := ipv4Dst(buf[:n]); !ok {
			continue
		}
		c.mu.Lock()
		sess := c.current
		c.mu.Unlock()
		if sess == nil {
			continue // not connected yet
		}
		out, err := sess.Seal(buf[:n])
		if err != nil {
			continue
		}
		c.send(out)
	}
}

func (c *Client) send(msg []byte) {
	c.lastSent.Store(time.Now().UnixNano())
	c.conn.Write(msg)
}
