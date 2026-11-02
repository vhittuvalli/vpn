//go:build !linux && !darwin && !windows

package tun

import (
	"fmt"
	"runtime"
)

func Create() (Device, error) {
	return nil, fmt.Errorf("TUN devices are not supported on %s", runtime.GOOS)
}
