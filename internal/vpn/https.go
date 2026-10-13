package vpn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/vhittuvalli/vpn/internal/protocol"
)

// The HTTPS transport disguises the tunnel as HTTP/3 web traffic on port 443.
//
// The client opens a QUIC connection, then sends an Extended CONNECT request
// for the "connect-ip" protocol, as in MASQUE (RFC 9484), the protocol
// behind Apple's iCloud Private Relay. VPN messages then travel as HTTP/3
// datagrams (RFC 9297) on that request. To anyone watching the network it is
// an HTTP/3 connection, and anyone who visits the server in a browser gets
// an ordinary web page.
//
// The request path contains a token derived from the server's public key,
// so a scanner that doesn't know the key can't even find the VPN endpoint.
// TLS here is only camouflage: the client doesn't check the certificate,
// because the VPN handshake inside already authenticates the server with
// post-quantum signatures.

const (
	connectIPProtocol = "connect-ip"
	contextIDZero     = 0 // RFC 9484: context 0 carries the payload
)

var quicConfig = &quic.Config{
	EnableDatagrams: true,
	MaxIdleTimeout:  60 * time.Second,
	KeepAlivePeriod: 15 * time.Second,
}

// HTTPSPath returns the secret CONNECT path for a server.
func HTTPSPath(server protocol.PublicKey) string {
	h := protocol.Hash([]byte("vpn-from-scratch https path"), server[:])
	return "/.well-known/masque/ip/" + hex.EncodeToString(h[:12]) + "/"
}

// HTTPSServer accepts VPN clients over HTTP/3 and serves a decoy page to
// everyone else.
type HTTPSServer struct {
	srv      *http3.Server
	path     string
	incoming chan httpsDatagram
	done     chan struct{}
	once     sync.Once
}

type httpsDatagram struct {
	msg []byte
	ep  *httpsEndpoint
}

type httpsEndpoint struct {
	str    *http3.Stream
	remote string
}

func (e *httpsEndpoint) Send(msg []byte) error {
	return e.str.SendDatagram(append([]byte{contextIDZero}, msg...))
}

func (e *httpsEndpoint) String() string { return e.remote }

// NewHTTPSServer starts serving on pc.
func NewHTTPSServer(pc net.PacketConn, cert tls.Certificate, server protocol.PublicKey) *HTTPSServer {
	s := &HTTPSServer{
		path:     HTTPSPath(server),
		incoming: make(chan httpsDatagram, 256),
		done:     make(chan struct{}),
	}
	s.srv = &http3.Server{
		TLSConfig:       http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		QUICConfig:      quicConfig,
		EnableDatagrams: true,
		Handler:         http.HandlerFunc(s.handle),
	}
	go func() {
		if err := s.srv.Serve(pc); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			select {
			case <-s.done:
			default:
				log.Printf("https transport: %v", err)
			}
		}
	}()
	return s
}

func (s *HTTPSServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect || r.Proto != connectIPProtocol || r.URL.Path != s.path {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, decoyPage)
		return
	}
	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(http.StatusOK)
	w.(http.Flusher).Flush()
	str := w.(http3.HTTPStreamer).HTTPStream()
	defer str.Close()
	ep := &httpsEndpoint{str: str, remote: r.RemoteAddr}
	for {
		d, err := str.ReceiveDatagram(r.Context())
		if err != nil {
			return
		}
		if len(d) < 2 || d[0] != contextIDZero {
			continue
		}
		select {
		case s.incoming <- httpsDatagram{d[1:], ep}:
		case <-s.done:
			return
		}
	}
}

func (s *HTTPSServer) Receive(buf []byte) (int, Endpoint, error) {
	select {
	case d := <-s.incoming:
		return copy(buf, d.msg), d.ep, nil
	case <-s.done:
		return 0, nil, net.ErrClosed
	}
}

func (s *HTTPSServer) Close() error {
	s.once.Do(func() { close(s.done) })
	return s.srv.Close()
}

const decoyPage = `<!doctype html>
<html><head><title>Welcome</title></head>
<body><h1>It works!</h1><p>This server is up and running.</p></body></html>
`

// SelfSignedCert makes a throwaway certificate for serverName.
func SelfSignedCert(serverName string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// HTTPSClient tunnels to the server over HTTP/3, reconnecting when the QUIC
// connection drops (for example after a network change or server restart).
type HTTPSClient struct {
	addr, serverName, path string

	ctx    context.Context
	cancel context.CancelFunc

	mu   sync.Mutex
	conn *quic.Conn
	str  *http3.RequestStream
	up   chan struct{} // closed when str is usable
}

func NewHTTPSClient(addr, serverName string, server protocol.PublicKey) *HTTPSClient {
	ctx, cancel := context.WithCancel(context.Background())
	c := &HTTPSClient{
		addr: addr, serverName: serverName, path: HTTPSPath(server),
		ctx: ctx, cancel: cancel, up: make(chan struct{}),
	}
	go c.connectLoop()
	return c
}

func (c *HTTPSClient) String() string { return "https://" + c.addr }

func (c *HTTPSClient) connectLoop() {
	backoff := time.Second
	for c.ctx.Err() == nil {
		conn, str, err := c.dial()
		if err != nil {
			log.Printf("https transport: %v (retrying in %s)", err, backoff)
			select {
			case <-time.After(backoff):
			case <-c.ctx.Done():
				return
			}
			backoff = min(2*backoff, 30*time.Second)
			continue
		}
		backoff = time.Second
		c.mu.Lock()
		c.conn, c.str = conn, str
		close(c.up)
		c.mu.Unlock()

		select {
		case <-str.Context().Done():
		case <-conn.Context().Done():
		case <-c.ctx.Done():
		}
		conn.CloseWithError(0, "")
		c.mu.Lock()
		c.conn, c.str = nil, nil
		c.up = make(chan struct{})
		c.mu.Unlock()
	}
}

func (c *HTTPSClient) dial() (*quic.Conn, *http3.RequestStream, error) {
	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()
	tlsConf := &tls.Config{
		ServerName:         c.serverName,
		NextProtos:         []string{http3.NextProtoH3},
		InsecureSkipVerify: true, // the VPN handshake authenticates the server
	}
	conn, err := quic.DialAddr(ctx, c.addr, tlsConf, quicConfig)
	if err != nil {
		return nil, nil, err
	}
	cc := (&http3.Transport{EnableDatagrams: true}).NewClientConn(conn)
	select {
	case <-cc.ReceivedSettings():
	case <-ctx.Done():
		conn.CloseWithError(0, "")
		return nil, nil, ctx.Err()
	}
	if s := cc.Settings(); !s.EnableDatagrams || !s.EnableExtendedConnect {
		conn.CloseWithError(0, "")
		return nil, nil, errors.New("server doesn't support HTTP/3 datagrams")
	}
	str, err := cc.OpenRequestStream(ctx)
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, nil, err
	}
	u := &url.URL{Scheme: "https", Host: c.serverName, Path: c.path}
	err = str.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  connectIPProtocol,
		Host:   c.serverName,
		URL:    u,
		Header: http.Header{"Capsule-Protocol": {"?1"}},
	})
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, nil, err
	}
	resp, err := str.ReadResponse()
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		conn.CloseWithError(0, "")
		return nil, nil, fmt.Errorf("server answered %s; check server_public_key", resp.Status)
	}
	return conn, str, nil
}

func (c *HTTPSClient) Read(buf []byte) (int, error) {
	for {
		c.mu.Lock()
		str, up := c.str, c.up
		c.mu.Unlock()
		if str == nil {
			select {
			case <-up:
				continue
			case <-c.ctx.Done():
				return 0, net.ErrClosed
			}
		}
		d, err := str.ReceiveDatagram(c.ctx)
		if err != nil {
			if c.ctx.Err() != nil {
				return 0, net.ErrClosed
			}
			// The connection loop notices and reconnects; wait for it.
			select {
			case <-str.Context().Done():
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		if len(d) < 2 || d[0] != contextIDZero {
			continue
		}
		return copy(buf, d[1:]), nil
	}
}

// WaitReady blocks until the HTTP/3 tunnel is up.
func (c *HTTPSClient) WaitReady(ctx context.Context) error {
	for {
		c.mu.Lock()
		str, up := c.str, c.up
		c.mu.Unlock()
		if str != nil {
			return nil
		}
		select {
		case <-up:
		case <-ctx.Done():
			return ctx.Err()
		case <-c.ctx.Done():
			return net.ErrClosed
		}
	}
}

var errNotConnected = errors.New("https transport not connected")

func (c *HTTPSClient) Write(msg []byte) (int, error) {
	c.mu.Lock()
	str := c.str
	c.mu.Unlock()
	if str == nil {
		return 0, errNotConnected
	}
	if err := str.SendDatagram(append([]byte{contextIDZero}, msg...)); err != nil {
		return 0, err
	}
	return len(msg), nil
}

func (c *HTTPSClient) Close() error {
	c.cancel()
	return nil
}
