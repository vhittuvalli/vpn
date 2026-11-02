package tun

import (
	"fmt"
	"sync"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// AdapterName is what the interface is called in Windows' network settings.
const AdapterName = "VPN"

// Windows has no built-in TUN device; Wintun (wintun.dll, which must sit
// next to the executable) provides one. WireGuard's tun package drives it.
type windowsTun struct {
	dev  wgtun.Device
	name string

	readMu  sync.Mutex
	readBuf [][]byte
	sizes   []int
	writeMu sync.Mutex
}

// Create makes a new Wintun adapter.
func Create() (Device, error) {
	dev, err := wgtun.CreateTUN(AdapterName, 1420)
	if err != nil {
		return nil, fmt.Errorf("creating the network adapter (is wintun.dll next to the program?): %w", err)
	}
	name, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, err
	}
	return &windowsTun{dev: dev, name: name, readBuf: make([][]byte, 1), sizes: make([]int, 1)}, nil
}

// LUID identifies the adapter to Windows' IP Helper and firewall APIs.
func LUID(d Device) (uint64, bool) {
	w, ok := d.(*windowsTun)
	if !ok {
		return 0, false
	}
	native, ok := w.dev.(*wgtun.NativeTun)
	if !ok {
		return 0, false
	}
	return native.LUID(), true
}

func (t *windowsTun) Name() string { return t.name }

func (t *windowsTun) Read(packet []byte) (int, error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()
	t.readBuf[0] = packet
	if _, err := t.dev.Read(t.readBuf, t.sizes, 0); err != nil {
		return 0, err
	}
	return t.sizes[0], nil
}

func (t *windowsTun) Write(packet []byte) (int, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if _, err := t.dev.Write([][]byte{packet}, 0); err != nil {
		return 0, err
	}
	return len(packet), nil
}

func (t *windowsTun) Close() error { return t.dev.Close() }
