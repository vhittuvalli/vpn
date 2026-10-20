//go:build !darwin

package netid

// Current is only implemented on macOS, where the app offers trusted
// networks.
func Current() (Network, error) { return Network{}, ErrUnknown }
