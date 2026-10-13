package vpn

import (
	"bytes"
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vhittuvalli/vpn/internal/config"
	"github.com/vhittuvalli/vpn/internal/protocol"
	"github.com/vhittuvalli/vpn/internal/tun"
)

type Client struct {
	id        *protocol.Identity
	serverKey protocol.PublicKey
	dev       tun.Device
	conn      ClientTransport
	fragments *protocol.Reassembler[struct{}]

	mu          sync.Mutex
	pending     *protocol.InitiatorHandshake
	cookie      []byte
	cookieTime  time.Time
	current     *protocol.Session
	previous    *protocol.Session
	established chan struct{}
	lastSent    atomic.Int64 // unix nanos

	// OnConnect, if set, is called once after the first handshake succeeds.
	OnConnect func()
}

func NewClient(cfg *config.Client, dev tun.Device, conn ClientTransport) *Client {
	return &Client{
		id:          protocol.NewIdentity(cfg.PrivateKey),
		serverKey:   cfg.ServerPublicKey,
		dev:         dev,
		conn:        conn,
		fragments:   protocol.NewReassembler[struct{}](),
		established: make(chan struct{}, 1),
	}
}

// Run keeps the tunnel up until ctx is canceled or the device or transport fails.
func (c *Client) Run(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		c.conn.Close()
		c.dev.Close()
	}()
	go c.handshakeLoop(ctx)
	go c.keepaliveLoop(ctx)
	err := firstError(c.receiveLoop, c.tunLoop)
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
		if w, ok := c.conn.(readyWaiter); ok {
			if err := w.WaitReady(ctx); err != nil {
				return
			}
		}
		hs, err := protocol.CreateInitiation(c.id, c.serverKey, protocol.RandomIndex(), time.Now())
		if err != nil {
			log.Printf("creating handshake: %v", err)
			return
		}
		c.mu.Lock()
		c.pending = hs
		c.mu.Unlock()
		c.sendInitiation(hs)

		wait := protocol.HandshakeRetry
		select {
		case <-ctx.Done():
			return
		case <-c.established:
			if !connected {
				connected = true
				log.Printf("connected to %s", c.conn)
				if c.OnConnect != nil {
					c.OnConnect()
				}
			}
			wait = protocol.RekeyAfterTime
		case <-time.After(protocol.HandshakeRetry):
			log.Printf("no handshake response from %s, retrying", c.conn)
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// sendInitiation adds MACs (with the current cookie, if any) and sends the
// initiation as fragments.
func (c *Client) sendInitiation(hs *protocol.InitiatorHandshake) {
	c.mu.Lock()
	cookie := c.cookie
	if time.Since(c.cookieTime) > protocol.CookieLifetime {
		cookie = nil
	}
	protocol.AddMACs(hs.Message, c.serverKey, cookie)
	msg := bytes.Clone(hs.Message)
	c.mu.Unlock()
	for _, frag := range protocol.Fragment(msg) {
		c.send(frag)
	}
}

// keepaliveLoop sends an empty packet when the tunnel has been idle, so NAT
// routers between client and server keep the connection open.
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

func (c *Client) receiveLoop() error {
	buf := make([]byte, 65535)
	for {
		n, err := c.conn.Read(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		msg := buf[:n]
		switch msg[0] {
		case protocol.TypeFragment:
			if whole, ok := c.fragments.Add(struct{}{}, msg); ok {
				c.handleResponse(whole)
			}
		case protocol.TypeCookieReply:
			c.handleCookieReply(msg)
		case protocol.TypeData:
			c.handleData(msg)
		}
	}
}

func (c *Client) handleResponse(msg []byte) {
	index, ok := protocol.ReceiverIndex(msg)
	if !ok || msg[0] != protocol.TypeResponse || !protocol.CheckMAC1(msg, c.id.Public) {
		return
	}
	c.mu.Lock()
	hs := c.pending
	if hs == nil || hs.LocalIndex != index {
		c.mu.Unlock()
		return
	}
	sess, err := hs.ConsumeResponse(msg)
	if err != nil {
		c.mu.Unlock()
		log.Printf("bad handshake response: %v", err)
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

// handleCookieReply stores the cookie and resends the pending initiation
// with it, so a server under load answers without waiting for a retry.
func (c *Client) handleCookieReply(msg []byte) {
	c.mu.Lock()
	hs := c.pending
	if hs == nil {
		c.mu.Unlock()
		return
	}
	cookie, err := protocol.ConsumeCookieReply(msg, hs.Message, c.serverKey)
	if err != nil {
		c.mu.Unlock()
		return
	}
	c.cookie, c.cookieTime = cookie, time.Now()
	c.mu.Unlock()
	c.sendInitiation(hs)
}

func (c *Client) handleData(msg []byte) {
	index, ok := protocol.ReceiverIndex(msg)
	if !ok {
		return
	}
	c.mu.Lock()
	var sess *protocol.Session
	for _, s := range []*protocol.Session{c.current, c.previous} {
		if s != nil && s.LocalIndex == index {
			sess = s
		}
	}
	c.mu.Unlock()
	if sess == nil {
		return
	}
	packet, err := sess.Open(msg)
	if err != nil || len(packet) == 0 {
		return
	}
	if _, err := c.dev.Write(packet); err != nil {
		log.Printf("writing to %s: %v", c.dev.Name(), err)
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
