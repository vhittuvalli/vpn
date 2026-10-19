// Command vpn is a small from-scratch post-quantum VPN. Run it without
// arguments for usage. Inside VPN.app it starts the menu bar app.
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
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vhittuvalli/vpn/internal/accesskey"
	"github.com/vhittuvalli/vpn/internal/config"
	"github.com/vhittuvalli/vpn/internal/daemon"
	"github.com/vhittuvalli/vpn/internal/netcfg"
	"github.com/vhittuvalli/vpn/internal/protocol"
	"github.com/vhittuvalli/vpn/internal/tun"
	"github.com/vhittuvalli/vpn/internal/tunnel"
	"github.com/vhittuvalli/vpn/internal/vpn"
)

// version is set at release time with -ldflags "-X main.version=v1.2.3".
var version = "dev"

const usage = `usage:
  Run a server (Linux):
    sudo vpn setup                  set up this machine as a server and print an access key
    sudo vpn invite NAME            add a device and print its access key
    sudo vpn revoke NAME            remove a device
    sudo vpn devices                list devices

  Connect:
    sudo vpn connect ACCESS_KEY     connect until Ctrl-C (add --https to look like web traffic)
    vpn app                         open the menu bar app (macOS)

  Other:
    vpn version                     print the version
    sudo vpn reset                  undo kill switch and DNS after a crash
    sudo vpn server -c server.json  run the server in the foreground
    sudo vpn client -c client.json  connect with a hand-written config
    vpn genkey, vpn pubkey          make keys for hand-written configs
`

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) < 2 || strings.HasPrefix(os.Args[1], "-psn_") {
		if inAppBundle() {
			if err := runApp(); err != nil {
				log.Fatal(err)
			}
			return
		}
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
	case "connect":
		err = connect(os.Args[2:])
	case "setup":
		err = setup(os.Args[2:])
	case "invite":
		err = invite(os.Args[2:])
	case "revoke":
		err = revoke(os.Args[2:])
	case "devices":
		err = devices(os.Args[2:])
	case "daemon":
		err = runDaemon(os.Args[2:])
	case "app":
		err = runApp()
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
	srv := vpn.NewServer(cfg, dev, transports...)

	// Per-device usage goes to status.json next to the config, for
	// `vpn devices`; totals carry over from the last run.
	status := statusPath(path)
	if err := srv.LoadStatus(status); err != nil {
		log.Printf("reading %s: %v (starting usage from zero)", status, err)
	}
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := srv.WriteStatus(status); err != nil {
					log.Printf("writing %s: %v", status, err)
				}
			}
		}
	}()
	defer srv.WriteStatus(status)

	// `vpn invite` and `vpn revoke` edit the config and send SIGHUP; only
	// the device list is reloaded, without dropping anyone else.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for range hup {
			next, err := config.LoadServer(path)
			if err != nil {
				log.Printf("reload: %v (keeping the current devices)", err)
				continue
			}
			added, removed := srv.SetPeers(next.Peers)
			log.Printf("reloaded devices: %d total, %d added, %d removed", len(next.Peers), added, removed)
		}
	}()

	err = srv.Run(ctx)
	log.Print("shutting down")
	return err
}

func statusPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "status.json")
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return tunnel.Run(ctx, cfg, nil)
}

func connect(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	https := fs.Bool("https", false, "tunnel over HTTPS (HTTP/3) on port 443 so it looks like web traffic")
	noKill := fs.Bool("no-kill-switch", false, "let traffic bypass the VPN if the tunnel drops")
	blockLAN := fs.Bool("block-lan", false, "also block the local network (printers, file shares) while connected")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: sudo vpn connect [--https] [--no-kill-switch] [--block-lan] ACCESS_KEY")
	}
	if err := requireRoot(); err != nil {
		return err
	}
	key, err := accesskey.Parse(fs.Arg(0))
	if err != nil {
		return err
	}
	cfg, err := key.Client(*https, !*noKill, !*blockLAN)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return tunnel.Run(ctx, cfg, func(s tunnel.State, _ *vpn.Client) {
		if s == tunnel.Connected {
			log.Print("connected; press Ctrl-C to disconnect")
		}
	})
}

func runDaemon(args []string) error {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	owner := fs.Int("owner", 0, "user ID allowed to control the service, besides root")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireRoot(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return daemon.Run(ctx, version, *owner)
}
