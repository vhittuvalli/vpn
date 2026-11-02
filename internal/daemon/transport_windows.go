package daemon

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// PipeName is where the service listens.
const PipeName = `\\.\pipe\vpn-service`

func stateDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "VPN")
}

// prepareStateDir creates the folder that holds the access key, readable
// only by SYSTEM and administrators (ProgramData is readable by all users,
// so the inherited permissions are replaced).
func prepareStateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// listen opens the named pipe. Its permissions do the checking: SYSTEM and
// administrators get full access, the owning user read and write, nobody
// else anything.
func listen(owner string) (net.Listener, error) {
	sddl := "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
	if owner != "" {
		// Only a well-formed SID goes into the descriptor.
		sid, err := windows.StringToSid(owner)
		if err != nil {
			return nil, fmt.Errorf("owner %q is not a Windows user SID: %w", owner, err)
		}
		sddl += "(A;;GRGW;;;" + sid.String() + ")"
	}
	return winio.ListenPipe(PipeName, &winio.PipeConfig{SecurityDescriptor: sddl, InputBufferSize: 4096, OutputBufferSize: 4096})
}

func closeListener() {}

// allowed is always true: the pipe's permissions already kept everyone
// else out.
func allowed(conn net.Conn, owner string) bool { return true }

func dial(timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return winio.DialPipeContext(ctx, PipeName)
}
