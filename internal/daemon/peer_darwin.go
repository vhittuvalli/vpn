package daemon

import (
	"net"

	"golang.org/x/sys/unix"
)

const stateDir = "/Library/Application Support/vpn"

// peerUID returns the user ID of the process on the other end of conn.
func peerUID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	uid := -1
	var credErr error
	err = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			credErr = err
			return
		}
		uid = int(cred.Uid)
	})
	if err == nil {
		err = credErr
	}
	return uid, err
}
