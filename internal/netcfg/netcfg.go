// Package netcfg configures addresses, routes and NAT by running the OS's
// own networking commands (ifconfig/route on macOS, ip/iptables on Linux).
package netcfg

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// Cleanup undoes a configuration change. It is safe to call once.
type Cleanup func()

func run(name string, args ...string) (string, error) {
	return runInput("", name, args...)
}

func runInput(stdin, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// runAll runs each command in order and returns a Cleanup running undo in
// reverse. If a command fails, the steps already applied are undone.
func runAll(do, undo [][]string) (Cleanup, error) {
	cleanup := func(n int) {
		for i := n - 1; i >= 0; i-- {
			if undo[i] == nil {
				continue
			}
			if _, err := run(undo[i][0], undo[i][1:]...); err != nil {
				log.Printf("cleanup: %v", err)
			}
		}
	}
	for i, cmd := range do {
		if _, err := run(cmd[0], cmd[1:]...); err != nil {
			cleanup(i)
			return nil, err
		}
	}
	return func() { cleanup(len(do)) }, nil
}
