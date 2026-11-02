//go:build !windows

package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
)

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("this needs root: run with sudo")
	}
	return nil
}

// runService runs the service until interrupted.
func runService(run func(context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx)
}

func cmdInstallService([]string) error {
	return errors.New("install-service is for Windows; on macOS the app installs its service itself")
}

func cmdUninstall([]string) error {
	return errors.New("uninstall is for Windows; see the README for macOS")
}
