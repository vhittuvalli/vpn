//go:build darwin && cgo

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/systray"
	"golang.org/x/sys/unix"

	"github.com/vhittuvalli/vpn/internal/daemon"
)

// macOS: the service is a launchd daemon installed with the user's password
// through AppleScript, dialogs are AppleScript too, and the menu bar icon is
// a template image macOS tints to match the menu bar.
const (
	serviceLabel = "com.vhittuvalli.vpn"
	helperPath   = "/Library/PrivilegedHelperTools/" + serviceLabel
	daemonPlist  = "/Library/LaunchDaemons/" + serviceLabel + ".plist"
	serviceLog   = "/Library/Logs/vpn.log"
	loginAgentID = serviceLabel + ".app"

	platformName               = "macOS"
	platformKillSwitchOptional = true
	platformTrustedNetworks    = true
)

func inAppBundle() bool {
	exe, err := os.Executable()
	return err == nil && strings.Contains(exe, ".app/Contents/MacOS/")
}

func singleInstance() bool {
	lock, err := os.OpenFile(filepath.Join(os.TempDir(), "vpn-app.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return true
	}
	return unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) == nil
}

func setTrayIcon(connected bool) {
	icon := shieldTemplate(connected)
	systray.SetTemplateIcon(icon, icon)
}

func openURL(url string) { exec.Command("open", url).Run() }

// ---- Installing the root service --------------------------------------------

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

// promptForKey asks for an access key. wantsFreeKey means the person clicked
// the button to get a guest key from the demo server instead.
func promptForKey(text string) (key string, wantsFreeKey bool, err error) {
	prefill := ""
	if clip, err := exec.Command("pbpaste").Output(); err == nil {
		if c := strings.TrimSpace(string(clip)); strings.HasPrefix(c, "vpn://") {
			prefill = c
		}
	}
	out, err := exec.Command("osascript",
		"-e", `on run argv`,
		"-e", `activate`,
		"-e", `set r to display dialog (item 1 of argv) default answer (item 2 of argv) with title "`+dialogTitle+`" buttons {"`+freeKeyButton+`", "Cancel", "Connect"} default button "Connect" cancel button "Cancel"`,
		"-e", `return (button returned of r) & linefeed & (text returned of r)`,
		"-e", `end run`,
		text, prefill,
	).Output()
	if err != nil {
		return "", false, errCanceled
	}
	button, typed := parseDialogResult(string(out))
	return typed, button == freeKeyButton, nil
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
