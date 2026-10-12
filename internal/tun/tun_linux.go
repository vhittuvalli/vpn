package tun

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type linuxTun struct {
	f    *os.File
	name string
}

// Create opens a new tunN interface via /dev/net/tun.
func Create() (Device, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	// An empty name asks the kernel to pick the next free tunN. IFF_NO_PI
	// means packets carry no extra header.
	ifr, err := unix.NewIfreq("")
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF: %w", err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	name := ifr.Name()
	return &linuxTun{f: os.NewFile(uintptr(fd), "/dev/net/tun"), name: name}, nil
}

func (t *linuxTun) Name() string                { return t.name }
func (t *linuxTun) Read(p []byte) (int, error)  { return t.f.Read(p) }
func (t *linuxTun) Write(p []byte) (int, error) { return t.f.Write(p) }
func (t *linuxTun) Close() error                { return t.f.Close() }
