package tun

import (
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// macOS exposes TUN devices as "utun" kernel-control sockets. Each packet
// carries a 4-byte header holding the address family.

const (
	sysprotoControl = 2 // SYSPROTO_CONTROL, <sys/sys_domain.h>
	utunOptIfname   = 2 // UTUN_OPT_IFNAME, <net/if_utun.h>
)

type darwinTun struct {
	f    *os.File
	name string
	rbuf []byte
	wmu  sync.Mutex
	wbuf []byte
}

// Create opens a new utunN interface.
func Create() (Device, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, fmt.Errorf("utun socket: %w", err)
	}
	info := &unix.CtlInfo{}
	copy(info.Name[:], "com.apple.net.utun_control")
	if err := unix.IoctlCtlInfo(fd, info); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("utun ctlinfo: %w", err)
	}
	// Unit 0 asks the kernel to pick the next free utunN.
	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: 0}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("utun connect: %w", err)
	}
	name, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfname)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("utun name: %w", err)
	}
	// Non-blocking lets Go's poller wake a pending Read when Close is called.
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &darwinTun{
		f:    os.NewFile(uintptr(fd), name),
		name: name,
		rbuf: make([]byte, 65535+4),
		wbuf: make([]byte, 0, 65535+4),
	}, nil
}

func (t *darwinTun) Name() string { return t.name }

func (t *darwinTun) Read(p []byte) (int, error) {
	for {
		n, err := t.f.Read(t.rbuf[:min(len(p)+4, len(t.rbuf))])
		if err != nil {
			return 0, err
		}
		if n > 4 {
			return copy(p, t.rbuf[4:n]), nil
		}
	}
}

func (t *darwinTun) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	family := byte(unix.AF_INET)
	if p[0]>>4 == 6 {
		family = unix.AF_INET6
	}
	t.wmu.Lock()
	defer t.wmu.Unlock()
	t.wbuf = append(append(t.wbuf[:0], 0, 0, 0, family), p...)
	if _, err := t.f.Write(t.wbuf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *darwinTun) Close() error { return t.f.Close() }
