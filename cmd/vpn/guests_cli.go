package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/vhittuvalli/vpn/internal/budget"
	"github.com/vhittuvalli/vpn/internal/config"
	"github.com/vhittuvalli/vpn/internal/guestapi"
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
	now := time.Now()
	enabled, active, max, err := reg.GuestCount(now)
	if err != nil {
		return err
	}
	f, err := config.ReadServerFile(reg.Path)
	if err != nil {
		return err
	}
	g, err := f.GuestSettings()
	if err != nil {
		return err
	}

	state := "off"
	if enabled {
		state = "on"
	}
	fmt.Printf("Guest access is %s. %d of %d guest slots in use.\n\n", state, active, max)

	// This month's transfer for the whole server, as `vpn server` measures it.
	month := now.UTC().Format("January")
	resets := budget.NextMonth(now).Format("January 2")
	st, err := budget.ReadState(usagePath(reg.Path))
	switch {
	case err != nil:
		fmt.Printf("Sent this %s: not measured yet (the server measures it while running).\n", month)
	case st.Month != budget.Month(now):
		fmt.Printf("Sent this %s: nothing measured yet. Cap %s; resets %s.\n", month, gib(g.MonthlyCapBytes), resets)
	default:
		pct := float64(st.SentBytes) / float64(g.MonthlyCapBytes) * 100
		fmt.Printf("Sent this %s: %s of the %s cap (%.0f%%), all devices and guests.\n", month, gib(st.SentBytes), gib(g.MonthlyCapBytes), pct)
		if st.SentBytes >= g.MonthlyCapBytes {
			fmt.Printf("The cap is reached: guests are cut off until %s. Your own devices still work.\n", resets)
		} else {
			fmt.Printf("Resets %s. Guests are cut off if it reaches the cap.\n", resets)
		}
	}

	// Keys handed out, from the issue log.
	thisMonth, today := 0, 0
	if data, err := os.ReadFile(guestLogPath(reg.Path)); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			var rec guestapi.IssueRecord
			if json.Unmarshal([]byte(line), &rec) != nil {
				continue
			}
			if budget.Month(rec.Time) == budget.Month(now) {
				thisMonth++
			}
			if rec.Time.UTC().Format(time.DateOnly) == now.UTC().Format(time.DateOnly) {
				today++
			}
		}
	}
	fmt.Printf("Guest keys handed out: %d this month, %d today.\n", thisMonth, today)
	fmt.Println("\nEach guest's time and data: sudo vpn devices")
	fmt.Println("Every key issued (time, name, IP): " + guestLogPath(reg.Path))
	return nil
}

// gib formats bytes in GiB, the unit hosting providers bill transfer in.
func gib(n uint64) string {
	if n%(1<<30) == 0 {
		return fmt.Sprintf("%d GiB", n>>30)
	}
	return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
}
