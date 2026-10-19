//go:build darwin && cgo

package main

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fyne.io/systray"
	"golang.org/x/sys/unix"

	"github.com/vhittuvalli/vpn/internal/accesskey"
	"github.com/vhittuvalli/vpn/internal/daemon"
)

// The menu bar app runs as the user. The tunnel itself runs in a root
// service (`vpn daemon`) that the app installs once with the user's
// password, and controls over a Unix socket.
const (
	serviceLabel  = "com.vhittuvalli.vpn"
	helperPath    = "/Library/PrivilegedHelperTools/" + serviceLabel
	daemonPlist   = "/Library/LaunchDaemons/" + serviceLabel + ".plist"
	serviceLog    = "/Library/Logs/vpn.log"
	loginAgentID  = serviceLabel + ".app"
	pollInterval  = 1500 * time.Millisecond
	dialogTitle   = "VPN"
	keyPromptText = "Paste the access key from your server. It starts with vpn://"
)

func inAppBundle() bool {
	exe, err := os.Executable()
	return err == nil && strings.Contains(exe, ".app/Contents/MacOS/")
}

func runApp() error {
	// One menu bar icon per user, even if the app is opened twice.
	lock, err := os.OpenFile(filepath.Join(os.TempDir(), "vpn-app.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err == nil {
		if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
			return nil
		}
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

	mStatus, mToggle, mKill, mLAN, mHTTPS, mKey, mLogin, mQuit *systray.MenuItem
}

func (a *app) ready() {
	systray.SetTemplateIcon(shieldIcon(false), shieldIcon(false))
	systray.SetTooltip("VPN")

	a.mStatus = systray.AddMenuItem("Starting…", "")
	a.mStatus.Disable()
	a.mToggle = systray.AddMenuItem("Turn On", "")
	systray.AddSeparator()
	a.mKill = systray.AddMenuItemCheckbox("Block internet if the VPN drops", "Nothing leaves this Mac outside the VPN while it's on", true)
	a.mLAN = systray.AddMenuItemCheckbox("Allow local network", "Printers, AirDrop, Chromecast and your router stay reachable while connected", true)
	a.mHTTPS = systray.AddMenuItemCheckbox("Disguise as web traffic", "Tunnel over HTTPS on port 443, for networks that block VPNs", false)
	a.mKey = systray.AddMenuItem("Add Access Key…", "")
	a.mLogin = systray.AddMenuItemCheckbox("Open at Login", "", loginItemEnabled())
	systray.AddSeparator()
	a.mQuit = systray.AddMenuItem("Quit VPN", "Turns the VPN off and quits")

	go a.clicks()
	go a.start()
}

// start makes sure the root service is installed and current, then keeps
// the menu in sync with it.
func (a *app) start() {
	s, err := daemon.Call(daemon.Request{Cmd: daemon.CmdStatus})
	// Install when missing, outdated (the app was updated), or set up by
	// another user of this Mac.
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
	case s.State == daemon.StateConnecting && s.Error != "":
		a.setStatusText("Reconnecting… (" + shorten(s.Error, 40) + ")")
	case s.State == daemon.StateConnecting:
		a.setStatusText("Connecting to " + s.Server + "…")
	case s.Error != "":
		a.setStatusText(shorten(s.Error, 60))
	default:
		a.setStatusText("VPN is off · " + where)
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
	systray.SetTemplateIcon(shieldIcon(s.State == daemon.StateOn), shieldIcon(s.State == daemon.StateOn))
	setChecked(a.mKill, s.KillSwitch)
	setChecked(a.mHTTPS, s.HTTPS)
	setChecked(a.mLAN, s.AllowLAN)
	if s.HasKey {
		a.mKey.SetTitle("Change Access Key…")
	} else {
		a.mKey.SetTitle("Add Access Key…")
	}
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
		key, err := promptForKey(text)
		if err != nil {
			return // canceled
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

// ---- Installing the root service --------------------------------------------

var errCanceled = errors.New("canceled")

// installService copies this binary to a root-owned location and registers
// it with launchd, asking for an administrator password once.
func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "vpn-install")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	plist := filepath.Join(tmp, "service.plist")
	if err := os.WriteFile(plist, []byte(fmt.Sprintf(daemonPlistTemplate, serviceLabel, helperPath, os.Getuid(), serviceLog)), 0o644); err != nil {
		return err
	}
	script := strings.Join([]string{
		"launchctl bootout system/" + serviceLabel + " 2>/dev/null || true",
		"mkdir -p /Library/PrivilegedHelperTools",
		"cp " + shq(exe) + " " + shq(helperPath+".new"),
		"xattr -c " + shq(helperPath+".new"),
		"chown root:wheel " + shq(helperPath+".new"),
		"chmod 755 " + shq(helperPath+".new"),
		"mv -f " + shq(helperPath+".new") + " " + shq(helperPath),
		"cp " + shq(plist) + " " + shq(daemonPlist),
		"chown root:wheel " + shq(daemonPlist),
		"chmod 644 " + shq(daemonPlist),
		"launchctl bootstrap system " + shq(daemonPlist),
	}, " && ")
	out, err := exec.Command("osascript", "-e",
		`do shell script "`+asq(script)+`" with administrator privileges with prompt "VPN needs your password once to install its background service, which manages the network connection."`,
	).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "-128") { // user canceled
			return errCanceled
		}
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	for i := 0; i < 40; i++ {
		if s, err := daemon.Call(daemon.Request{Cmd: daemon.CmdStatus}); err == nil && s.Version == version {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("the service was installed but didn't start; see %s", serviceLog)
}

const daemonPlistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>%s</string>
	<key>ProgramArguments</key>
	<array><string>%s</string><string>daemon</string><string>--owner</string><string>%d</string></array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`

// shq quotes s for a POSIX shell.
func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// asq escapes s for an AppleScript string literal.
func asq(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}

// ---- Dialogs ----------------------------------------------------------------

func promptForKey(text string) (string, error) {
	prefill := ""
	if clip, err := exec.Command("pbpaste").Output(); err == nil {
		if c := strings.TrimSpace(string(clip)); strings.HasPrefix(c, "vpn://") {
			prefill = c
		}
	}
	out, err := exec.Command("osascript",
		"-e", `on run argv`,
		"-e", `activate`,
		"-e", `text returned of (display dialog (item 1 of argv) default answer (item 2 of argv) with title "`+dialogTitle+`" buttons {"Cancel", "Connect"} default button "Connect")`,
		"-e", `end run`,
		text, prefill,
	).Output()
	if err != nil {
		return "", errCanceled
	}
	return strings.TrimSpace(string(out)), nil
}

func alert(title, detail string) {
	log.Printf("%s %s", title, detail)
	exec.Command("osascript",
		"-e", `on run argv`,
		"-e", `activate`,
		"-e", `display alert (item 1 of argv) message (item 2 of argv) as warning`,
		"-e", `end run`,
		title, detail,
	).Run()
}

// ---- Open at login ----------------------------------------------------------

func loginAgentPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", loginAgentID+".plist")
}

func loginItemEnabled() bool {
	_, err := os.Stat(loginAgentPath())
	return err == nil
}

func setLoginItem(on bool) error {
	path := loginAgentPath()
	if !on {
		err := os.Remove(path)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>%s</string>
	<key>ProgramArguments</key><array><string>%s</string></array>
	<key>RunAtLoad</key><true/>
	<key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
`, loginAgentID, exe)), 0o644)
}

// ---- Menu bar icon ----------------------------------------------------------

var iconCache = map[bool][]byte{}

// shieldIcon draws the menu bar icon: a shield outline when off, a filled
// shield when connected. It's a template image, so macOS tints it to match
// the menu bar.
func shieldIcon(filled bool) []byte {
	if b, ok := iconCache[filled]; ok {
		return b
	}
	const size, ss = 36, 4 // 18pt at 2x, 4x4 supersampling
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	inside := func(x, y, inset float64) bool {
		// Shield: flat top from 0.18 to 0.82, sides down to 0.55, curving
		// to a point at the bottom.
		l, r, top, bot := 0.2+inset, 0.8-inset, 0.1+inset, 0.92-inset*1.4
		if y < top || y > bot || x < l || x > r {
			return false
		}
		mid := 0.5
		shoulder := top + (bot-top)*0.45
		if y <= shoulder {
			return true
		}
		t := (y - shoulder) / (bot - shoulder)
		half := (r - l) / 2 * (1 - t*t)
		return x >= mid-half && x <= mid+half
	}
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			hits := 0
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					x := (float64(px) + (float64(sx)+0.5)/ss) / size
					y := (float64(py) + (float64(sy)+0.5)/ss) / size
					if inside(x, y, 0) && (filled || !inside(x, y, 0.075)) {
						hits++
					}
				}
			}
			img.SetNRGBA(px, py, color.NRGBA{0, 0, 0, uint8(255 * hits / (ss * ss))})
		}
	}
	var buf bytes.Buffer
	png.Encode(&buf, img)
	iconCache[filled] = buf.Bytes()
	return iconCache[filled]
}
