package vpn

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"time"

	"github.com/vhittuvalli/vpn/internal/protocol"
)

// PeerStats is what the server knows about one device. Byte counts are
// totals across server restarts: Rx is what the device sent (uploaded), Tx
// what it was sent (downloaded).
type PeerStats struct {
	Name        string    `json:"name"`
	PublicKey   string    `json:"public_key"`
	Address     string    `json:"address"`
	Online      bool      `json:"online"`
	From        string    `json:"from,omitempty"` // address:port of the latest connection
	ConnectedAt time.Time `json:"connected_at,omitzero"`
	LastSeen    time.Time `json:"last_seen,omitzero"`
	RxBytes     uint64    `json:"rx_bytes"`
	TxBytes     uint64    `json:"tx_bytes"`
}

// StatusFile is the server's status.json, which `vpn devices` reads.
type StatusFile struct {
	Updated time.Time   `json:"updated"`
	Peers   []PeerStats `json:"peers"`
}

// PeerStats reports every current peer, sorted by name.
func (s *Server) PeerStats(now time.Time) []PeerStats {
	var out []PeerStats
	for _, p := range s.allPeers() {
		p.mu.Lock()
		st := PeerStats{
			Name:      p.name,
			PublicKey: p.publicKey.String(),
			Address:   p.ip.String(),
			Online:    !p.lastSeen.IsZero() && now.Sub(p.lastSeen) <= onlineWindow,
			From:      p.lastFrom,
			LastSeen:  p.lastSeen,
			RxBytes:   p.carried.RxBytes + p.rxBytes.Load(),
			TxBytes:   p.carried.TxBytes + p.txBytes.Load(),
		}
		if st.Online {
			st.ConnectedAt = p.connectedAt
		}
		if st.LastSeen.IsZero() {
			st.LastSeen = p.carried.LastSeen
		}
		if st.From == "" {
			st.From = p.carried.From
		}
		p.mu.Unlock()
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// WriteStatus saves PeerStats to path atomically.
func (s *Server) WriteStatus(path string) error {
	data, err := json.MarshalIndent(StatusFile{Updated: time.Now().UTC(), Peers: s.PeerStats(time.Now())}, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadStatus reads a status file written by WriteStatus.
func ReadStatus(path string) (*StatusFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f StatusFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

// LoadStatus carries totals and last-seen times from an earlier run's
// status file over to the matching peers (by public key). A missing file
// is fine.
func (s *Server) LoadStatus(path string) error {
	f, err := ReadStatus(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	carried := map[protocol.PublicKey]PeerStats{}
	for _, st := range f.Peers {
		if k, err := protocol.ParsePublicKey(st.PublicKey); err == nil {
			st.Online, st.ConnectedAt = false, time.Time{}
			carried[k] = st
		}
	}
	s.peersMu.Lock()
	s.carried = carried
	peers := make([]*serverPeer, 0, len(s.peersByKey))
	for _, p := range s.peersByKey {
		peers = append(peers, p)
	}
	s.peersMu.Unlock()
	for _, p := range peers {
		p.mu.Lock()
		p.carried = carried[p.publicKey]
		p.mu.Unlock()
	}
	return nil
}
