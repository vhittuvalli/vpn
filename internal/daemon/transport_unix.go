//go:build darwin || linux

package daemon

import (
	"net"
	"os"
	"strconv"
	"time"
)

const SocketPath = "/var/run/vpn.sock"

func stateDir() string { return defaultStateDir }

func prepareStateDir(dir string) error { return os.MkdirAll(dir, 0o700) }

// listen opens the socket. Anyone may connect; allowed checks who it is.
func listen(owner string) (net.Listener, error) {
	os.Remove(SocketPath)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: SocketPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(SocketPath, 0o666); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func closeListener() { os.Remove(SocketPath) }

// allowed lets in root and the owner, as reported by the kernel.
func allowed(conn net.Conn, owner string) bool {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	uid, err := peerUID(uc)
	return err == nil && (uid == 0 || strconv.Itoa(uid) == owner)
}

func dial(timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", SocketPath, timeout)
}
