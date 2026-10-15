//go:build !darwin || !cgo

package main

import "errors"

func inAppBundle() bool { return false }

func runApp() error {
	return errors.New("the menu bar app is only in VPN.app for macOS; use `sudo vpn connect ACCESS_KEY` instead")
}
