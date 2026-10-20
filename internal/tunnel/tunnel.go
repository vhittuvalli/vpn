// Package tunnel brings a client connection up and tears it down: the TUN
// device, kill switch, routes and DNS around a vpn.Client. Both `vpn client`
// and the background service behind the Mac app use it.
package tunnel

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"

	"github.com/vhittuvalli/vpn/internal/config"
	"github.com/vhittuvalli/vpn/internal/netcfg"
	"github.com/vhittuvalli/vpn/internal/tun"
	"github.com/vhittuvalli/vpn/internal/vpn"
)

// State is where a connection is in its life.
type State int

const (
	Connecting State = iota // tunnel is up, waiting for the server to answer
	Connected               // handshake done; traffic flows through the VPN
)

// Run connects to the server in cfg and keeps the tunnel up until ctx is
// canceled. It undoes every change it made to the system before returning.
// onState, if set, is called as the connection progresses, with the client
// so callers can read its Stats.
func Run(ctx context.Context, cfg *config.Client, onState func(State, *vpn.Client)) error {
	if onState == nil {
		onState = func(State, *vpn.Client) {}
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
	// When all traffic goes through the VPN, IPv6 (which the tunnel doesn't
	// carry) is blocked even without the kill switch, or it would quietly
	// bypass the tunnel and reveal this machine's address.
	if cfg.KillSwitch || cfg.RouteAllTraffic {
		undo, err := netcfg.KillSwitch(dev.Name(), server.Addr(), cfg.AllowLAN, cfg.KillSwitch)
		if err != nil {
			return fmt.Errorf("kill switch: %w", err)
		}
		addCleanup(undo)
		if cfg.KillSwitch {
			log.Print("kill switch on: traffic outside the VPN is blocked")
		} else {
			log.Print("IPv6 blocked so it can't bypass the VPN")
		}
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
	client := vpn.NewClient(cfg, dev, conn)
	onState(Connecting, client)

	// Routes and DNS change only once the tunnel works, so a down server
	// doesn't cut this machine off (unless the kill switch is on).
	client.OnConnect = func() {
		defer onState(Connected, client)
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
