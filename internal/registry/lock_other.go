//go:build !unix

package registry

// lockFile is a no-op where flock isn't available; the in-process mutex
// still serializes writers within one process.
func lockFile(path string) (func(), error) { return func() {}, nil }
