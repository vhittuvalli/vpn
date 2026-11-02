package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName        = "VPN"
	serviceDisplayName = "VPN"
	serviceDescription = "Runs the VPN tunnel for the VPN app: network adapter, routes, DNS and firewall."
)

// installDir is where the service's program lives: under Program Files,
// which ordinary users can't change, so nobody can swap the program a
// SYSTEM service runs.
func installDir() string {
	base := os.Getenv("ProgramFiles")
	if base == "" {
		base = `C:\Program Files`
	}
	return filepath.Join(base, "VPN")
}

func requireRoot() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("this needs administrator rights: run it from an administrator terminal")
	}
	return nil
}

// runService runs under Windows' service manager when started by it, and
// in the foreground otherwise.
func runService(run func(context.Context) error) error {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return run(ctx)
	}
	if dir := os.Getenv("ProgramData"); dir != "" {
		os.MkdirAll(filepath.Join(dir, "VPN"), 0o700)
		if f, err := os.OpenFile(filepath.Join(dir, "VPN", "vpn.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
			log.SetOutput(f)
		}
	}
	return svc.Run(serviceName, &serviceHandler{run: run})
}

type serviceHandler struct{ run func(context.Context) error }

func (h *serviceHandler) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		case err := <-done:
			if err != nil {
				log.Printf("service stopped: %v", err)
				return false, 1
			}
			return false, 0
		}
	}
}

// cmdInstallService copies the program and wintun.dll to Program Files and
// registers (or updates) the service, which starts at boot and restarts if
// it crashes. The app runs this through a UAC prompt.
func cmdInstallService(args []string) error {
	fs := flag.NewFlagSet("install-service", flag.ContinueOnError)
	owner := fs.String("owner", "", "SID of the user allowed to control the service")
	errFile := fs.String("error-file", "", "write any error here too (the app reads it, since this runs without a console)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	err := installServiceAs(*owner)
	if err != nil && *errFile != "" {
		os.WriteFile(*errFile, []byte(err.Error()), 0o644)
	}
	return err
}

func installServiceAs(owner string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if _, err := windows.StringToSid(owner); err != nil {
		return fmt.Errorf("--owner must be a user SID: %w", err)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	dir := installDir()
	exe := filepath.Join(dir, "VPN.exe")

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err == nil {
		stopService(s)
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if !sameFile(self, exe) {
		if err := copyInto(self, exe); err != nil {
			return err
		}
		if err := copyInto(filepath.Join(filepath.Dir(self), "wintun.dll"), filepath.Join(dir, "wintun.dll")); err != nil {
			return fmt.Errorf("wintun.dll must be next to VPN.exe: %w", err)
		}
	}

	if s == nil {
		s, err = m.CreateService(serviceName, exe, mgr.Config{
			DisplayName: serviceDisplayName, Description: serviceDescription,
			StartType: mgr.StartAutomatic, ServiceStartName: "LocalSystem",
		}, "daemon", "--owner", owner)
		if err != nil {
			return err
		}
	} else {
		cfg, err := s.Config()
		if err != nil {
			return err
		}
		cfg.BinaryPathName = fmt.Sprintf(`"%s" daemon --owner %s`, exe, owner)
		cfg.StartType = mgr.StartAutomatic
		if err := s.UpdateConfig(cfg); err != nil {
			return err
		}
	}
	defer s.Close()
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 5 * time.Second}
	s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, 24*60*60)
	return s.Start()
}

// cmdUninstall removes the service, its program folder and the login entry.
// The saved access key in ProgramData is removed too.
func cmdUninstall(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		stopService(s)
		if err := s.Delete(); err != nil {
			s.Close()
			return err
		}
		s.Close()
	}
	os.RemoveAll(installDir())
	if dir := os.Getenv("ProgramData"); dir != "" {
		os.RemoveAll(filepath.Join(dir, "VPN"))
	}
	if k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE); err == nil {
		k.DeleteValue(runValue)
		k.Close()
	}
	fmt.Println("VPN is uninstalled.")
	return nil
}

func stopService(s *mgr.Service) {
	st, err := s.Control(svc.Stop)
	for i := 0; err == nil && st.State != svc.Stopped && i < 50; i++ {
		time.Sleep(200 * time.Millisecond)
		st, err = s.Query()
	}
}

func sameFile(a, b string) bool {
	ai, err1 := os.Stat(a)
	bi, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(ai, bi)
}

// copyInto copies src to dst via a temporary file, so a failed copy never
// leaves a half-written program behind.
func copyInto(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// The app's "Open at Login" entry.
const (
	runKey   = `Software\Microsoft\Windows\CurrentVersion\Run`
	runValue = "VPN"
)
