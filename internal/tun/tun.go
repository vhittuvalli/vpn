// Package tun creates virtual network interfaces. Packets the OS routes to
// the interface come out of Read; packets passed to Write are delivered to
// the OS as if they arrived from a network.
package tun

// Device is a TUN interface carrying raw IP packets.
type Device interface {
	Name() string
	Read(packet []byte) (int, error)
	Write(packet []byte) (int, error)
	Close() error
}
