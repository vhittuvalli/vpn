package main

import (
	"errors"
	"flag"
	"fmt"
	"os/exec"
	"time"

	"github.com/vhittuvalli/vpn/internal/config"
	"github.com/vhittuvalli/vpn/internal/human"
	"github.com/vhittuvalli/vpn/internal/registry"
)

const guestsUsage = `usage:
  sudo vpn guests          show whether guest access is on and who's using it
  sudo vpn guests on       start handing out guest keys (opens TCP 443)
  sudo vpn guests off      stop handing out keys; current guests run out their time
  sudo vpn guests purge    remove every guest now`

func guests(args []string) error {
	fs := flag.NewFlagSet("guests", flag.ContinueOnError)
	path := fs.String("c", serverConfigPath, "server config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 1 {
		return errors.New(guestsUsage)
	}
	if err := requireRoot(); err != nil {
		return err
	}
	reg := registry.Registry{Path: *path}
	switch fs.Arg(0) {
	case "":
		return guestStatus(reg)
	case "on":
		if err := reg.SetGuestsEnabled(true); err != nil {
			return err
		}
		if ufwActive() {
			if out, err := exec.Command("ufw", "allow", "443/tcp").CombinedOutput(); err != nil {
				return fmt.Errorf("ufw allow 443/tcp: %v: %s", err, out)
			}
			fmt.Println("Opened TCP 443 in the firewall (ufw).")
		}
		reloadServer()
		f, err := config.ReadServerFile(*path)
		if err != nil {
			return err
		}
		g, err := f.GuestSettings()
		if err != nil {
			return err
		}
		fmt.Printf("Guest access is on: https://%s/guest-key hands out %s keys with %s of data each,\n", g.Hostname, human.Duration(g.TTL), human.Bytes(g.QuotaBytes))
		fmt.Printf("up to %d guests at once and %d keys per visitor per day.\n", g.MaxActive, g.PerIPPerDay)
		fmt.Println("If your host has its own firewall, allow TCP 443 there too. The first request")
		fmt.Println("fetches a Let's Encrypt certificate, which takes a few seconds.")
	case "off":
		if err := reg.SetGuestsEnabled(false); err != nil {
			return err
		}
		reloadServer()
		fmt.Println("Guest access is off. Current guests keep working until their time runs out;")
		fmt.Println("remove them now with: sudo vpn guests purge")
	case "purge":
		removed, err := reg.RemoveIf(func(p config.PeerFile) bool { return p.Guest })
		if err != nil {
			return err
		}
		if len(removed) == 0 {
			fmt.Println("No guests to remove.")
			return nil
		}
		reloadServer()
		fmt.Printf("Removed %d guest(s). Their keys no longer work.\n", len(removed))
	default:
		return errors.New(guestsUsage)
	}
	return nil
}

func guestStatus(reg registry.Registry) error {
	enabled, active, max, err := reg.GuestCount(time.Now())
	if err != nil {
		return err
	}
	state := "off"
	if enabled {
		state = "on"
	}
	fmt.Printf("Guest access is %s. %d of %d guest slots in use.\n", state, active, max)
	fmt.Println("See each guest's time and data with: sudo vpn devices")
	return nil
}
