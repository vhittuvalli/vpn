// Command vpn is a small from-scratch VPN.
//
//	vpn genkey                      print a new private key
//	vpn pubkey < private.key        print the public key for a private key
//	sudo vpn server -c server.json  run the server
//	sudo vpn client -c client.json  connect to a server
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/vhittuvalli/vpn/internal/config"
	"github.com/vhittuvalli/vpn/internal/netcfg"
	"github.com/vhittuvalli/vpn/internal/protocol"
	"github.com/vhittuvalli/vpn/internal/tun"
	"github.com/vhittuvalli/vpn/internal/vpn"
)

const usage = `usage:
  vpn genkey                      print a new private key
  vpn pubkey < private.key        print the public key for a private key
  sudo vpn server -c server.json  run the server
  sudo vpn client -c client.json  connect to a server
`

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "genkey":
		err = genkey()
	case "pubkey":
		err = pubkey()
	case "server":
		err = runServer(os.Args[2:])
	case "client":
		err = runClient(os.Args[2:])
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
	k, err := protocol.ParseKey(strings.TrimSpace(line))
	if err != nil {
		return err
	}
	fmt.Println(k.Public())
	return nil
}

func configFlag(name string, args []string) (string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	path := fs.String("c", name+".json", "config file")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if os.Geteuid() != 0 {
		return "", errors.New("creating a network interface needs root: run with sudo")
	}
	return *path, nil
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

	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: cfg.ListenPort})
	if err != nil {
		return err
	}
	log.Printf("server %s listening on UDP %d, tunnel %s on %s, %d peer(s)",
		cfg.PrivateKey.Public(), cfg.ListenPort, cfg.Address, dev.Name(), len(cfg.Peers))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = vpn.NewServer(cfg, dev, conn).Run(ctx)
	log.Print("shutting down")
	return err
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
	serverIP, _ := netip.AddrFromSlice(raddr.IP.To4())

	dev, err := tun.Create()
	if err != nil {
		return err
	}
	defer dev.Close()
	if err := netcfg.ConfigureInterface(dev.Name(), cfg.Address, cfg.MTU); err != nil {
		return err
	}

	conn, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		return err
	}
	log.Printf("tunnel %s on %s, connecting to %s", cfg.Address, dev.Name(), raddr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client := vpn.NewClient(cfg, dev, conn)
	var undoRoutes netcfg.Cleanup
	if cfg.RouteAllTraffic {
		// Only take over the default route once the tunnel works, so a
		// down server doesn't cut this machine off the internet.
		client.OnConnect = func() {
			undo, err := netcfg.RouteAllTraffic(dev.Name(), serverIP)
			if err != nil {
				log.Printf("routing all traffic: %v", err)
				return
			}
			undoRoutes = undo
			log.Print("all IPv4 traffic now goes through the VPN")
		}
	}
	err = client.Run(ctx)
	if undoRoutes != nil {
		undoRoutes()
	}
	log.Print("disconnected")
	return err
}
