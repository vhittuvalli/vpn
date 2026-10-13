// Command vpn is a small from-scratch post-quantum VPN.
//
//	vpn version                     print the version
//	vpn genkey                      print a new private key
//	vpn pubkey < private.key        print the public key for a private key
//	sudo vpn server -c server.json  run the server
//	sudo vpn client -c client.json  connect to a server
//	sudo vpn reset                  undo kill switch and DNS after a crash
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/vhittuvalli/vpn/internal/config"
	"github.com/vhittuvalli/vpn/internal/netcfg"
	"github.com/vhittuvalli/vpn/internal/protocol"
	"github.com/vhittuvalli/vpn/internal/tun"
	"github.com/vhittuvalli/vpn/internal/vpn"
)

// version is set at release time with -ldflags "-X main.version=v1.2.3".
var version = "dev"

const usage = `usage:
  vpn version                     print the version
  vpn genkey                      print a new private key
  vpn pubkey < private.key        print the public key for a private key
  sudo vpn server -c server.json  run the server
  sudo vpn client -c client.json  connect to a server
  sudo vpn reset                  undo kill switch and DNS after a crash
`

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "version", "-v", "--version":
		fmt.Println("vpn", version)
	case "genkey":
		err = genkey()
	case "pubkey":
		err = pubkey()
	case "server":
		err = runServer(os.Args[2:])
	case "client":
		err = runClient(os.Args[2:])
	case "reset":
		err = reset()
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func genkey() error {
	k, err := protocol.GeneratePrivateKey()
	if err != nil {
		return err
	}
	fmt.Println(k)
	return nil
}

func pubkey() error {
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return errors.New("pubkey: expected a private key on stdin")
	}
	k, err := protocol.ParsePrivateKey(strings.TrimSpace(line))
	if err != nil {
		return err
	}
	fmt.Println(k.Public())
	return nil
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("this needs root: run with sudo")
	}
	return nil
}

func configFlag(name string, args []string) (string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	path := fs.String("c", name+".json", "config file")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	return *path, requireRoot()
}

func reset() error {
	if err := requireRoot(); err != nil {
		return err
	}
	if err := netcfg.Reset(); err != nil {
		return err
	}
	log.Print("kill switch removed and DNS restored")
	return nil
}

func runServer(args []string) error {
	path, err := configFlag("server", args)
	if err != nil {
		return err
	}
	cfg, err := config.LoadServer(path)
	if err != nil {
		return err
	}
	public := cfg.PrivateKey.Public()

	dev, err := tun.Create()
	if err != nil {
		return err
	}
	defer dev.Close()
	if err := netcfg.ConfigureInterface(dev.Name(), cfg.Address, cfg.MTU); err != nil {
		return err
	}
	if cfg.NATInterface != "" {
		undo, err := netcfg.EnableNAT(dev.Name(), cfg.NATInterface, cfg.Address)
		if err != nil {
			return err
		}
		defer undo()
	}

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{Port: cfg.ListenPort})
	if err != nil {
		return err
	}
	transports := []vpn.ServerTransport{vpn.NewUDPServer(udp)}
	log.Printf("listening on UDP %d", cfg.ListenPort)
	if cfg.HTTPSPort != 0 {
		cert, err := loadCert(cfg)
		if err != nil {
			return err
		}
		pc, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", cfg.HTTPSPort))
		if err != nil {
			return err
		}
		transports = append(transports, vpn.NewHTTPSServer(pc, cert, public))
		log.Printf("listening on HTTPS (HTTP/3) %d", cfg.HTTPSPort)
	}
	log.Printf("server %s, tunnel %s on %s, %d peer(s)", public, cfg.Address, dev.Name(), len(cfg.Peers))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = vpn.NewServer(cfg, dev, transports...).Run(ctx)
	log.Print("shutting down")
	return err
}

func loadCert(cfg *config.Server) (tls.Certificate, error) {
	if cfg.TLSCert != "" {
		return tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	}
	return vpn.SelfSignedCert(cfg.ServerName)
}

func runClient(args []string) error {
	path, err := configFlag("client", args)
	if err != nil {
		return err
	}
	cfg, err := config.LoadClient(path)
	if err != nil {
		return err
	}
	raddr, err := net.ResolveUDPAddr("udp4", cfg.Server)
	if err != nil {
		return fmt.Errorf("resolving server: %w", err)
	}
	server := raddr.AddrPort()
	server = netip.AddrPortFrom(server.Addr().Unmap(), server.Port())

	dev, err := tun.Create()
	if err != nil {
		return err
	}
	defer dev.Close()
	if err := netcfg.ConfigureInterface(dev.Name(), cfg.Address, cfg.MTU); err != nil {
		return err
	}

	// The kill switch goes up before anything is sent, so there is no
	// moment where traffic could leak.
	var cleanups []netcfg.Cleanup
	var cleanupMu sync.Mutex
	addCleanup := func(c netcfg.Cleanup) {
		cleanupMu.Lock()
		cleanups = append(cleanups, c)
		cleanupMu.Unlock()
	}
	defer func() {
		cleanupMu.Lock()
		defer cleanupMu.Unlock()
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}()
	if cfg.KillSwitch {
		undo, err := netcfg.KillSwitch(dev.Name(), server)
		if err != nil {
			return fmt.Errorf("kill switch: %w", err)
		}
		addCleanup(undo)
		log.Print("kill switch on: traffic outside the VPN is blocked")
	}

	var conn vpn.ClientTransport
	switch cfg.Transport {
	case "https":
		conn = vpn.NewHTTPSClient(server.String(), cfg.ServerName, cfg.ServerPublicKey)
	default:
		udp, err := net.DialUDP("udp4", nil, raddr)
		if err != nil {
			return err
		}
		conn = vpn.UDPClient{UDPConn: udp}
	}
	log.Printf("tunnel %s on %s, connecting to %s", cfg.Address, dev.Name(), conn)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client := vpn.NewClient(cfg, dev, conn)
	// Routes and DNS change only once the tunnel works, so a down server
	// doesn't cut this machine off (unless the kill switch is on).
	client.OnConnect = func() {
		if cfg.RouteAllTraffic {
			undo, err := netcfg.RouteAllTraffic(dev.Name(), server.Addr())
			if err != nil {
				log.Printf("routing all traffic: %v", err)
				return
			}
			addCleanup(undo)
			log.Print("all IPv4 traffic now goes through the VPN")
		}
		if len(cfg.DNS) > 0 {
			undo, err := netcfg.SetDNS(dev.Name(), cfg.DNS)
			if err != nil {
				log.Printf("setting DNS: %v", err)
				return
			}
			addCleanup(undo)
			log.Printf("DNS now goes to %v through the VPN", cfg.DNS)
		}
	}
	err = client.Run(ctx)
	log.Print("disconnected")
	return err
}
