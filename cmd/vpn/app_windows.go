package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"fyne.io/systray"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/vhittuvalli/vpn/internal/daemon"
)

// Windows: the service is installed through a UAC prompt, dialogs are small
// Windows Forms windows run by PowerShell (built into Windows 10 and 11),
// and the tray icon is a colored .ico.
const (
	platformName = "Windows"
	// WireGuard's firewall rules can't yet make exceptions, so the kill
	// switch is always on and the local network is blocked while connected.
	platformKillSwitchOptional = false
	platformTrustedNetworks    = false
)

// inAppBundle: VPN.exe started without arguments (double-clicked, or from
// the Run entry) is the tray app.
func inAppBundle() bool { return true }

var instanceMutex windows.Handle

func singleInstance() bool {
	name, _ := windows.UTF16PtrFromString(`Local\VPN-tray-app`)
	h, err := windows.CreateMutex(nil, false, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return false
	}
	instanceMutex = h // held for the life of the process
	return true
}

func setTrayIcon(connected bool) { systray.SetIcon(shieldBadge(connected)) }

func openURL(url string) {
	verb, _ := windows.UTF16PtrFromString("open")
	target, _ := windows.UTF16PtrFromString(url)
	windows.ShellExecute(0, verb, target, nil, nil, windows.SW_SHOWNORMAL)
}

// powershell runs a script without showing a console window. Values go in
// through environment variables, so nothing needs quoting.
func powershell(script string, env ...string) *exec.Cmd {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", encodePS(script))
	cmd.Env = append(os.Environ(), env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	return cmd
}

// encodePS encodes a script for -EncodedCommand: base64 of UTF-16LE.
func encodePS(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// ---- Installing the service -------------------------------------------------

// installService runs `VPN.exe install-service` as administrator (Windows
// shows its UAC prompt), which copies the program to Program Files and
// registers the service, then waits for the service to answer.
func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sid := user.User.Sid.String()
	errFile := filepath.Join(os.TempDir(), "vpn-install-error.txt")
	os.Remove(errFile)
	out, err := powershell(`
$ErrorActionPreference = 'Stop'
try {
  $p = Start-Process -FilePath $env:VPN_EXE -ArgumentList @('install-service', '--owner', $env:VPN_SID, '--error-file', $env:VPN_ERR) -Verb RunAs -Wait -PassThru -WindowStyle Hidden
  exit $p.ExitCode
} catch {
  Write-Output $_.Exception.Message
  exit 2
}`, "VPN_EXE="+exe, "VPN_SID="+sid, "VPN_ERR="+errFile).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(strings.ToLower(msg), "canceled by the user") {
			return errCanceled
		}
		if detail, rerr := os.ReadFile(errFile); rerr == nil {
			msg = strings.TrimSpace(string(detail))
		}
		if msg == "" {
			msg = err.Error()
		}
		return errors.New(msg)
	}
	for i := 0; i < 40; i++ {
		if s, err := daemon.Call(daemon.Request{Cmd: daemon.CmdStatus}); err == nil && s.Version == version {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New(`the service was installed but didn't start; see C:\ProgramData\VPN\vpn.log`)
}

// ---- Dialogs ----------------------------------------------------------------

const keyDialog = `
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
$f = New-Object System.Windows.Forms.Form
$f.Text = 'VPN'; $f.ClientSize = New-Object System.Drawing.Size(500, 150)
$f.StartPosition = 'CenterScreen'; $f.FormBorderStyle = 'FixedDialog'
$f.MaximizeBox = $false; $f.MinimizeBox = $false; $f.TopMost = $true
$l = New-Object System.Windows.Forms.Label
$l.Text = $env:VPN_PROMPT; $l.SetBounds(12, 12, 476, 48)
$t = New-Object System.Windows.Forms.TextBox
$t.SetBounds(12, 66, 476, 24)
$clip = Get-Clipboard -ErrorAction SilentlyContinue
if ($clip -and ("$clip".Trim()).StartsWith('vpn://')) { $t.Text = "$clip".Trim() }
$free = New-Object System.Windows.Forms.Button
$free.Text = $env:VPN_FREE; $free.SetBounds(12, 108, 130, 30); $free.DialogResult = 'Retry'
$cancel = New-Object System.Windows.Forms.Button
$cancel.Text = 'Cancel'; $cancel.SetBounds(312, 108, 85, 30); $cancel.DialogResult = 'Cancel'
$ok = New-Object System.Windows.Forms.Button
$ok.Text = 'Connect'; $ok.SetBounds(403, 108, 85, 30); $ok.DialogResult = 'OK'
$f.Controls.AddRange(@($l, $t, $free, $cancel, $ok))
$f.AcceptButton = $ok; $f.CancelButton = $cancel
$r = $f.ShowDialog()
if ($r -eq 'OK') { Write-Output 'Connect'; Write-Output $t.Text; exit 0 }
if ($r -eq 'Retry') { Write-Output $env:VPN_FREE; exit 0 }
exit 1
`

// promptForKey asks for an access key. wantsFreeKey means the person clicked
// the button to get a guest key from the demo server instead.
func promptForKey(text string) (key string, wantsFreeKey bool, err error) {
	out, err := powershell(keyDialog, "VPN_PROMPT="+text, "VPN_FREE="+freeKeyButton).Output()
	if err != nil {
		return "", false, errCanceled
	}
	button, typed := parseDialogResult(strings.ReplaceAll(string(out), "\r\n", "\n"))
	return typed, button == freeKeyButton, nil
}

func alert(title, detail string) {
	t, _ := windows.UTF16PtrFromString(title)
	d, _ := windows.UTF16PtrFromString(detail)
	windows.MessageBox(0, d, t, windows.MB_OK|windows.MB_ICONWARNING|windows.MB_SETFOREGROUND)
}

// ---- Open at login ----------------------------------------------------------

// loginTarget is the installed copy when there is one, so the entry keeps
// working if the downloaded folder is deleted.
func loginTarget() string {
	installed := filepath.Join(installDir(), "VPN.exe")
	if _, err := os.Stat(installed); err == nil {
		return installed
	}
	exe, _ := os.Executable()
	return exe
}

func loginItemEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(runValue)
	return err == nil
}

func setLoginItem(on bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !on {
		if err := k.DeleteValue(runValue); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
		return nil
	}
	return k.SetStringValue(runValue, fmt.Sprintf(`"%s"`, loginTarget()))
}
