package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/vhittuvalli/vpn/internal/daemon"
)

const serviceUsage = `usage:
  vpn service              show the background service's state
  vpn service on           connect
  vpn service off          disconnect
  vpn service key KEY      set the access key`

// serviceCommand controls the background service the Mac and Windows apps
// use, the same way their menus do. It's for scripts and for testing the
// service without the app.
func serviceCommand(args []string) error {
	req := daemon.Request{Cmd: daemon.CmdStatus}
	switch {
	case len(args) == 0 || args[0] == "status":
	case args[0] == "on" && len(args) == 1:
		req.Cmd = daemon.CmdOn
	case args[0] == "off" && len(args) == 1:
		req.Cmd = daemon.CmdOff
	case args[0] == "key" && len(args) == 2:
		req = daemon.Request{Cmd: daemon.CmdSetKey, Key: args[1]}
	default:
		return errors.New(serviceUsage)
	}
	s, err := daemon.Call(req)
	if err != nil {
		return fmt.Errorf("the VPN service isn't answering (is it installed and running?): %w", err)
	}
	fmt.Printf("state: %s\n", s.State)
	if s.HasKey {
		fmt.Printf("device: %s on %s\n", s.Name, s.Server)
	} else {
		fmt.Println("no access key yet")
	}
	if s.State == daemon.StateOn && s.ConnectedSince != 0 {
		fmt.Printf("connected for %s\n", time.Since(time.Unix(s.ConnectedSince, 0)).Round(time.Second))
	}
	if s.Error != "" {
		return errors.New(s.Error)
	}
	return nil
}
