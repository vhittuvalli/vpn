# vpn

[![ci](https://github.com/vhittuvalli/vpn/actions/workflows/ci.yml/badge.svg)](https://github.com/vhittuvalli/vpn/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/vhittuvalli/vpn)](https://github.com/vhittuvalli/vpn/releases)

A **post-quantum VPN** written from scratch in Go. Its design is close to
WireGuard's, with three additions:

- **Post-quantum cryptography end to end.** The handshake combines X25519 with
  ML-KEM-768 (FIPS 203) for key exchange, and both sides sign it with
  ML-DSA-44 (FIPS 204). Breaking X25519, for example with a future quantum
  computer, is not enough to read or impersonate traffic, now or later.
- **An HTTPS disguise.** As an option, the tunnel can run inside HTTP/3 on
  port 443, using the MASQUE CONNECT-IP framing behind Apple's iCloud Private
  Relay. To the network it looks like web browsing.
- **Leak protection.** A firewall kill switch, IPv6 blocking, and DNS that goes
  through the tunnel.

```bash
curl -fsSL https://raw.githubusercontent.com/vhittuvalli/vpn/main/install.sh | sh
```

> **This is a learning project.** No one has audited it. If you need real
> privacy, use WireGuard.

## How it works

```
 laptop                                               server (Linux VPS)
┌────────────────────────┐   UDP :51820, or HTTP/3   ┌─────────────────────────┐
│ app → utun3 (10.8.0.2) │   on :443 (looks like     │ tun0 (10.8.0.1) → NAT → │ internet
│        │               │   ordinary web traffic)   │   ▲                     │
│        └─► vpn client ─┼──────────────────────────►┼─ vpn server             │
└────────────────────────┘                           └─────────────────────────┘
```

### 1. Virtual network interface

[internal/tun](internal/tun) creates a TUN interface. The OS hands the program
every IP packet routed to that interface, and anything the program writes back
is treated as if it arrived from the network. The code talks to the OS
directly: `utun` kernel-control sockets on macOS, and `/dev/net/tun` on Linux.

### 2. Identities

Each machine has a single 32-byte private key. Two key pairs are derived from
it ([keys.go](internal/protocol/keys.go)):

- an **X25519** key pair for the Noise key exchange,
- an **ML-DSA-44** key pair for post-quantum signatures.

The public key you share is 64 bytes: the X25519 public key, followed by a hash
of the 1,312-byte ML-DSA public key. The full ML-DSA key travels, encrypted,
inside the handshake, and is checked against that hash.

### 3. The handshake

[handshake.go](internal/protocol/handshake.go) follows the
[Noise](https://noiseprotocol.org/) IK pattern, the same one WireGuard uses,
with post-quantum parts layered on top:

| step | client → server (initiation, 5 KB) | server → client (response, 4.8 KB) |
| --- | --- | --- |
| key exchange | fresh X25519 key and a fresh **ML-KEM-768** public key | fresh X25519 key and an **ML-KEM ciphertext** |
| identity | its public keys, encrypted so onlookers can't see who is connecting | — |
| authentication | an **ML-DSA signature** over the whole transcript | an **ML-DSA signature** over the whole transcript |
| replay protection | an encrypted timestamp | — |

The session keys mix together four X25519 results and the ML-KEM secret, so an
attacker has to break **both** X25519 and ML-KEM to decrypt traffic. That
protects against "harvest now, decrypt later": someone recording traffic today
and decrypting it once quantum computers exist. The signatures mean that even
an attacker who can break X25519 can't impersonate either side. Fresh keys for
every handshake give **forward secrecy**: stealing a long-term key later doesn't
reveal earlier traffic.

A handshake message is too big for one packet, so the protocol splits it into
1 KB fragments itself ([fragment.go](internal/protocol/fragment.go)). Many
networks drop IP-level fragments, which is why it doesn't rely on those.

### 4. Flood protection

Post-quantum handshakes take real CPU time, so the server protects them in two
layers, the same way WireGuard does ([cookie.go](internal/protocol/cookie.go)):

- **mac1.** Every handshake carries a MAC keyed by the server's public key. It
  costs one HMAC to check, and it means random internet scanners never trigger
  the expensive work.
- **Cookies.** Above 50 handshakes a second, the server stops processing
  handshakes and replies with an encrypted cookie bound to the sender's IP
  address. Only clients that really receive traffic at that address can
  retry, so floods from spoofed addresses get nowhere. Each source address is
  also rate-limited.

The server's reply is always smaller than the client's message, so the server
can't be used to amplify an attack against someone else.

### 5. Data

[session.go](internal/protocol/session.go) encrypts each packet with
ChaCha20-Poly1305. A per-packet counter serves as the nonce, and a 2048-packet
sliding window rejects replayed or very old packets. The client redoes the
handshake every 2 minutes, so keys are short-lived.

### 6. Transports

[transport.go](internal/vpn/transport.go) and [https.go](internal/vpn/https.go):

- **UDP** is fast and simple. The server replies from whichever of its
  addresses the client contacted, so it works on cloud VMs that have several.
- **HTTPS (HTTP/3).** The client opens a QUIC connection to port 443 and sends
  an Extended CONNECT request for `connect-ip`, as defined in MASQUE
  ([RFC 9484](https://www.rfc-editor.org/rfc/rfc9484)). VPN messages then
  travel as HTTP/3 datagrams ([RFC 9297](https://www.rfc-editor.org/rfc/rfc9297)).
  The request path contains a token derived from the server's key, so scanners
  can't find the VPN endpoint. Anyone who opens the server in a browser sees an
  ordinary "It works!" page. If the QUIC connection drops, the client
  reconnects automatically.

### 7. Leak protection

[internal/netcfg](internal/netcfg):

- **Kill switch.** It is installed *before* the first packet is sent. On macOS
  it uses a pf anchor, and on Linux an iptables chain. It blocks all outgoing
  traffic except through the tunnel and to the VPN server itself, and blocks
  IPv6 completely, since the tunnel doesn't carry it. If the tunnel drops,
  nothing leaks.
- **DNS.** Lookups go to resolvers you choose, through the tunnel, so your
  local network can't see which sites you look up. Your original DNS settings
  are saved and restored on exit.
- **Full-tunnel routing.** Routes are added as `0.0.0.0/1` plus `128.0.0.0/1`,
  so your normal default route is never touched.

All of this is undone on Ctrl-C. If the client is killed without a chance to
clean up, `sudo vpn reset` restores your normal settings.

## Setup

You need a Linux server with a public IP address, such as a small VPS, and a
client, such as a Mac or Linux machine.

### 1. Install

On both machines:

```bash
curl -fsSL https://raw.githubusercontent.com/vhittuvalli/vpn/main/install.sh | sh
```

The script downloads the right binary from
[Releases](https://github.com/vhittuvalli/vpn/releases), checks its SHA-256
checksum, and installs it to `/usr/local/bin`. To build from source instead,
run `go install github.com/vhittuvalli/vpn/cmd/vpn@latest`.

### 2. Make keys

On each machine:

```bash
vpn genkey > private.key
vpn pubkey < private.key      # share this public key with the other side
```

### 3. Configure

Copy [server.example.json](server.example.json) to `server.json` on the
server, and [client.example.json](client.example.json) to `client.json` on the
client. Fill in each machine's own private key, plus the other machine's
public key.

| setting | where | meaning |
| --- | --- | --- |
| `nat_interface` | server | The internet-facing interface (see `ip route`). Lets clients reach the internet through the server. Private, link-local and CGNAT addresses (such as a cloud provider's internal network and metadata service) stay blocked. |
| `https_port` | server | Also accept the HTTPS transport on this port. Usually 443. |
| `server_name`, `tls_cert`, `tls_key` | server | The name in the self-signed certificate, or a real certificate if you have one. |
| `transport` | client | `"udp"` (fast) or `"https"` (looks like web traffic; set `server` to port 443). |
| `route_all_traffic` | client | Send all IPv4 traffic through the VPN. |
| `kill_switch` | client | Block anything that would bypass the VPN. Requires `route_all_traffic`. |
| `dns` | client | Resolvers to use through the tunnel, e.g. `["1.1.1.1"]`. |

Every client gets its own entry in `peers`, with a unique address. Files named
`*.json` are gitignored, so configs with real keys won't be committed.

### 4. Run

```bash
# server: open UDP 51820 (and UDP 443 for https) in the firewall
sudo vpn server -c server.json

# or as a service (the unit file is in packaging/vpn.service)
sudo mkdir -p /etc/vpn && sudo cp server.json /etc/vpn/
sudo cp packaging/vpn.service /etc/systemd/system/ && sudo systemctl enable --now vpn

# client
sudo vpn client -c client.json
```

To check that it works, run `ping 10.8.0.1`. Then `curl -4 ifconfig.me`
should print the server's IP address.

## Tests

```bash
go test -race ./...
```

The tests run without root and cover:

- the handshake, including tampering with any field and impostor servers and
  clients
- forged ML-DSA signatures from an attacker who holds the X25519 key
- replay and reordering
- the cookie exchange under load
- fragment reassembly, including memory bounds
- the decoy web page
- a real server and client end to end over both UDP and HTTP/3 on localhost,
  using fake TUN devices

## Releasing

Pushing a version tag builds binaries for macOS and Linux (amd64 and arm64)
and publishes a GitHub release:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

## Limitations

- IPv4 only inside the tunnel. IPv6 is blocked by the kill switch rather than
  carried.
- The HTTPS disguise hides the protocol from passive observers. A determined
  censor that actively probes servers could still notice a self-signed
  certificate; use `tls_cert` with a real domain to avoid that.
- If the server restarts, UDP clients take up to 2 minutes to reconnect: they
  only notice at the next scheduled handshake. HTTPS clients reconnect within
  seconds.
- Each packet costs one system call. That's fine for normal use but slower
  than kernel WireGuard.
- Runs on macOS and Linux.
