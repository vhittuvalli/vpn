//go:build (darwin && cgo) || windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"fyne.io/systray"

	"github.com/vhittuvalli/vpn/internal/accesskey"
	"github.com/vhittuvalli/vpn/internal/daemon"
	"github.com/vhittuvalli/vpn/internal/human"
)

// The menu bar (macOS) or tray (Windows) app runs as the user. The tunnel
// itself runs in a privileged service (`vpn daemon`) that the app installs
// once, after asking for the user's permission, and controls over a local
// socket or named pipe. Platform details (installing the service, dialogs,
// icons, the login item) are in app_darwin.go and app_windows.go.
const (
	pollInterval  = 1500 * time.Millisecond
	dialogTitle   = "VPN"
	keyPromptText = "Paste the access key from your server. It starts with vpn://"
	latestRelease = "https://api.github.com/repos/vhittuvalli/vpn/releases/latest"
	downloadPage  = "https://vhittuvalli.github.io/vpn/"
	guestKeyPage  = downloadPage + "#try" // the demo server's free guest keys
	freeKeyButton = "Get a Free Key"
	updateEvery   = 12 * time.Hour
)

var errCanceled = errors.New("canceled")

func runApp() error {
	// One icon per user, even if the app is opened twice.
	if !singleInstance() {
		return nil
	}
	a := &app{}
	systray.Run(a.ready, func() {})
	return nil
}

type app struct {
	mu      sync.Mutex
	status  *daemon.Status
	busy    bool // a command is in flight
	setupOK bool

	mStatus, mDetails, mToggle, mAnyway, mTrust, mKill, mLAN, mHTTPS, mKey, mLogin, mUpdate, mQuit *systray.MenuItem
}

func (a *app) ready() {
	setTrayIcon(false)
	systray.SetTooltip("VPN")

	a.mStatus = systray.AddMenuItem("Starting…", "")
	a.mStatus.Disable()
	a.mDetails = systray.AddMenuItem("", "Time connected · downloaded / uploaded · round trip to the server")
	a.mDetails.Disable()
	a.mDetails.Hide()
	a.mToggle = systray.AddMenuItem("Turn On", "")
	a.mAnyway = systray.AddMenuItem("Connect Anyway", "Connect on this trusted network until you change networks")
	a.mAnyway.Hide()
	systray.AddSeparator()
	a.mTrust = systray.AddMenuItemCheckbox("Trust This Network", "The VPN pauses on trusted networks and connects everywhere else", false)
	a.mTrust.Disable()
	a.mKill = systray.AddMenuItemCheckbox("Block internet if the VPN drops", "Nothing leaves this computer outside the VPN while it's on", true)
	a.mLAN = systray.AddMenuItemCheckbox("Allow local network", "Printers, AirDrop, Chromecast and your router stay reachable while connected", true)
	if !platformKillSwitchOptional {
		// The kill switch can't be turned off here yet, and with it the
		// local network is blocked too; show that rather than offer it.
		a.mKill.SetTooltip("Always on for this version on " + platformName)
		a.mKill.Disable()
		a.mLAN.SetTitle("Allow local network (not on " + platformName + " yet)")
		a.mLAN.Uncheck()
		a.mLAN.Disable()
	}
	if !platformTrustedNetworks {
		a.mTrust.Hide()
	}
	a.mHTTPS = systray.AddMenuItemCheckbox("Disguise as web traffic", "Tunnel over HTTPS on port 443, for networks that block VPNs", false)
	a.mKey = systray.AddMenuItem("Add Access Key…", "")
	a.mLogin = systray.AddMenuItemCheckbox("Open at Login", "", loginItemEnabled())
	systray.AddSeparator()
	a.mUpdate = systray.AddMenuItem("Update Available", "Opens the download page")
	a.mUpdate.Hide()
	a.mQuit = systray.AddMenuItem("Quit VPN", "Turns the VPN off and quits")

	go a.clicks()
	go a.start()
	go a.checkForUpdates()
}

// checkForUpdates asks GitHub for the latest release shortly after launch
// and twice a day, and shows a menu item when it's newer than this app.
func (a *app) checkForUpdates() {
	time.Sleep(10 * time.Second)
	for {
		if tag, err := latestVersion(); err != nil {
			log.Printf("checking for updates: %v", err)
		} else if newerVersion(tag, version) {
			a.mUpdate.SetTitle("Update Available: " + tag + "…")
			a.mUpdate.Show()
		}
		time.Sleep(updateEvery)
	}
}

func latestVersion() (string, error) {
	req, err := http.NewRequest("GET", latestRelease, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "vpn-app/"+version)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub answered %s", resp.Status)
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", err
	}
	return rel.TagName, nil
}

// start makes sure the root service is installed and current, then keeps
// the menu in sync with it.
func (a *app) start() {
	s, err := daemon.Call(daemon.Request{Cmd: daemon.CmdStatus})
	// Install when missing, outdated (the app was updated), or set up by
	// another user of this computer.
	if err != nil || s.Version != version || strings.HasPrefix(s.Error, "not allowed") {
		a.setStatusText("Setting up…")
		first := err != nil
		if err := installService(); err != nil {
			a.setStatusText("Setup needed: click to try again")
			a.mStatus.Enable()
			go func() {
				<-a.mStatus.ClickedCh
				a.mStatus.Disable()
				a.start()
			}()
			if !errors.Is(err, errCanceled) {
				alert("VPN couldn't set up its background service.", err.Error())
			}
			return
		}
		if first && !loginItemEnabled() {
			setLoginItem(true)
			a.mLogin.Check()
		}
	}
	a.mu.Lock()
	a.setupOK = true
	a.mu.Unlock()

	s, _ = daemon.Call(daemon.Request{Cmd: daemon.CmdStatus})
	if s != nil && !s.HasKey {
		a.askForKey(true)
	}
	for {
		a.refresh()
		time.Sleep(pollInterval)
	}
}

func (a *app) refresh() {
	s, err := daemon.Call(daemon.Request{Cmd: daemon.CmdStatus})
	if err != nil {
		s = &daemon.Status{State: daemon.StateOff, Error: "the background service isn't responding"}
	}
	a.show(s)
}

func (a *app) show(s *daemon.Status) {
	a.mu.Lock()
	a.status = s
	busy := a.busy
	a.mu.Unlock()

	where := s.Server
	if s.Name != "" {
		where = s.Name + " → " + s.Server
	}
	switch {
	case busy:
	case !s.HasKey:
		a.setStatusText("Add an access key to get started")
	case s.State == daemon.StateOn:
		a.setStatusText("Connected · " + s.Server)
	case s.State == daemon.StatePaused:
		a.setStatusText("Paused on trusted network · " + s.Network)
	case s.State == daemon.StateConnecting && s.Error != "":
		a.setStatusText("Reconnecting… (" + shorten(s.Error, 40) + ")")
	case s.State == daemon.StateConnecting:
		a.setStatusText("Connecting to " + s.Server + "…")
	case s.Error != "":
		a.setStatusText(shorten(s.Error, 60))
	default:
		a.setStatusText("VPN is off · " + where)
	}

	if d := details(s); d != "" && !busy {
		a.mDetails.SetTitle(d)
		a.mDetails.Show()
	} else {
		a.mDetails.Hide()
	}

	on := s.State != daemon.StateOff
	if on {
		a.mToggle.SetTitle("Turn Off")
	} else {
		a.mToggle.SetTitle("Turn On")
	}
	if s.HasKey && !busy {
		a.mToggle.Enable()
	} else {
		a.mToggle.Disable()
	}
	if s.State == daemon.StatePaused && !busy {
		a.mAnyway.Show()
	} else {
		a.mAnyway.Hide()
	}
	if s.Network != "" {
		a.mTrust.SetTitle("Trust This Network (" + s.Network + ")")
		a.mTrust.Enable()
	} else {
		a.mTrust.SetTitle("Trust This Network")
		a.mTrust.Disable()
	}
	setChecked(a.mTrust, s.NetworkTrusted)
	setTrayIcon(s.State == daemon.StateOn)
	setChecked(a.mHTTPS, s.HTTPS)
	if platformKillSwitchOptional {
		setChecked(a.mKill, s.KillSwitch)
		setChecked(a.mLAN, s.AllowLAN)
	}
	if s.HasKey {
		a.mKey.SetTitle("Change Access Key…")
	} else {
		a.mKey.SetTitle("Add Access Key…")
	}
}

// details is the second menu line while connected, e.g.
// "2h 14m · ↓ 1.3 GB  ↑ 80.0 MB · 42 ms".
func details(s *daemon.Status) string {
	if s.State != daemon.StateOn || s.ConnectedSince == 0 {
		return ""
	}
	d := human.Duration(time.Since(time.Unix(s.ConnectedSince, 0))) +
		" · ↓ " + human.Bytes(s.RxBytes) + "  ↑ " + human.Bytes(s.TxBytes)
	if s.RTTMillis > 0 {
		d += fmt.Sprintf(" · %d ms", s.RTTMillis)
	}
	return d
}

func (a *app) clicks() {
	for {
		select {
		case <-a.mToggle.ClickedCh:
			a.mu.Lock()
			on := a.status != nil && a.status.State != daemon.StateOff
			a.mu.Unlock()
			if on {
				a.command("Turning off…", daemon.Request{Cmd: daemon.CmdOff})
			} else {
				a.command("Connecting…", daemon.Request{Cmd: daemon.CmdOn})
			}
		case <-a.mAnyway.ClickedCh:
			a.command("Connecting…", daemon.Request{Cmd: daemon.CmdOn})
		case <-a.mTrust.ClickedCh:
			v := !a.mTrust.Checked()
			a.command("Applying…", daemon.Request{Cmd: daemon.CmdTrust, Trust: &v})
		case <-a.mKill.ClickedCh:
			v := !a.mKill.Checked()
			a.command("Applying…", daemon.Request{Cmd: daemon.CmdSettings, KillSwitch: &v})
		case <-a.mLAN.ClickedCh:
			v := !a.mLAN.Checked()
			a.command("Applying…", daemon.Request{Cmd: daemon.CmdSettings, AllowLAN: &v})
		case <-a.mHTTPS.ClickedCh:
			v := !a.mHTTPS.Checked()
			a.command("Applying…", daemon.Request{Cmd: daemon.CmdSettings, HTTPS: &v})
		case <-a.mKey.ClickedCh:
			go a.askForKey(false)
		case <-a.mLogin.ClickedCh:
			v := !a.mLogin.Checked()
			if err := setLoginItem(v); err != nil {
				alert("Couldn't change Open at Login.", err.Error())
			}
			setChecked(a.mLogin, loginItemEnabled())
		case <-a.mUpdate.ClickedCh:
			openURL(downloadPage)
		case <-a.mQuit.ClickedCh:
			a.mStatus.SetTitle("Turning off…")
			daemon.Call(daemon.Request{Cmd: daemon.CmdOff})
			systray.Quit()
			return
		}
	}
}

// command sends a request in the background, showing progress text until
// the service answers.
func (a *app) command(progress string, req daemon.Request) {
	a.mu.Lock()
	if a.busy || !a.setupOK {
		a.mu.Unlock()
		return
	}
	a.busy = true
	a.mu.Unlock()
	a.setStatusText(progress)
	a.mToggle.Disable()
	go func() {
		s, err := daemon.Call(req)
		a.mu.Lock()
		a.busy = false
		a.mu.Unlock()
		if err != nil {
			alert("The VPN service didn't answer.", err.Error())
			a.refresh()
			return
		}
		a.show(s)
	}()
}

func (a *app) askForKey(firstRun bool) {
	a.mu.Lock()
	ok := a.setupOK
	a.mu.Unlock()
	if !ok {
		return
	}
	text := keyPromptText
	if firstRun {
		text = "Welcome! " + text
	}
	for {
		key, wantsFreeKey, err := promptForKey(text)
		if err != nil {
			return // canceled
		}
		if wantsFreeKey {
			openURL(guestKeyPage)
			text = "Your browser is opening a page with free guest keys. Click Get a guest key there, copy it, then paste it here."
			continue
		}
		if _, err := accesskey.Parse(key); err != nil {
			text = "That didn't work: " + err.Error() + ".\n\n" + keyPromptText
			continue
		}
		s, err := daemon.Call(daemon.Request{Cmd: daemon.CmdSetKey, Key: key})
		if err != nil {
			alert("The VPN service didn't answer.", err.Error())
			return
		}
		if s.Error != "" {
			text = "That didn't work: " + s.Error + ".\n\n" + keyPromptText
			continue
		}
		a.show(s)
		if s.State == daemon.StateOff {
			a.command("Connecting…", daemon.Request{Cmd: daemon.CmdOn})
		}
		return
	}
}

func (a *app) setStatusText(s string) { a.mStatus.SetTitle(s) }

func setChecked(m *systray.MenuItem, v bool) {
	if v {
		m.Check()
	} else {
		m.Uncheck()
	}
}

func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
