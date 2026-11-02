//go:build !darwin && !linux && !windows

package daemon

import (
	"errors"
	"net"
	"time"
)

var errUnsupported = errors.New("the VPN service isn't supported on this OS")

func stateDir() string                     { return "" }
func prepareStateDir(string) error         { return errUnsupported }
func listen(string) (net.Listener, error)  { return nil, errUnsupported }
func closeListener()                       {}
func allowed(net.Conn, string) bool        { return false }
func dial(time.Duration) (net.Conn, error) { return nil, errUnsupported }
