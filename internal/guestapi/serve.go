package guestapi

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// Listener is the endpoint running on TCP 443 with a Let's Encrypt
// certificate for hostname, fetched and renewed by autocert. Let's Encrypt
// checks control of the name over the same port (TLS-ALPN-01), so TCP 443
// must be reachable from the internet.
type Listener struct {
	Hostname string
	srv      *http.Server
}

// Listen starts serving h on addr (":443") until Close. Certificates are
// cached in cacheDir so restarts don't request new ones.
func Listen(addr, hostname, cacheDir string, h http.Handler) (*Listener, error) {
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(hostname),
		Cache:      autocert.DirCache(cacheDir),
	}
	tlsConf := m.TLSConfig()
	tlsConf.MinVersion = tls.VersionTLS12
	srv := &http.Server{
		Handler:           h,
		TLSConfig:         tlsConf,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second, // the first request also waits for the certificate
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          log.New(log.Writer(), "guest endpoint: ", log.Ltime),
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("guest endpoint stopped: %v", err)
		}
	}()
	log.Printf("guest key endpoint on https://%s (TCP %s)", hostname, addr)
	return &Listener{Hostname: hostname, srv: srv}, nil
}

// Close stops the endpoint, letting requests in flight finish.
func (l *Listener) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return l.srv.Shutdown(ctx)
}
