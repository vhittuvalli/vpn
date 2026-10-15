//go:build !darwin && !linux

package daemon

import (
	"errors"
	"net"
)

const stateDir = ""

func peerUID(conn *net.UnixConn) (int, error) { return -1, errors.New("unsupported OS") }
