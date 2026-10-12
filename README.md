# vpn

A small VPN written from scratch in Go. Its design is close to WireGuard's,
but the whole thing is about 1,700 lines, so you can read all of it.

> **This is a learning project.** No one has audited it. If you need real
> privacy, use WireGuard.

## How it works

```
 laptop                                              server (Linux VPS)
┌────────────────────────┐                          ┌─────────────────────────┐
│ app → utun3 (10.8.0.2) │                          │ tun0 (10.8.0.1) → NAT → │ internet
│        │               │   encrypted UDP :51820   │   ▲                     │
│        └─► vpn client ─┼─────────────────────────►┼─ vpn server             │
└────────────────────────┘                          └─────────────────────────┘
```

1. **TUN device** ([internal/tun](internal/tun)). The program creates a virtual
   network interface. The OS hands every IP packet routed to that interface to
   the program, and anything the program writes back is treated as if it came
   in from the network.
2. **Handshake** ([internal/protocol/handshake.go](internal/protocol/handshake.go)).
   Each side has an X25519 key pair. The client sends one message and the
   server replies with one. This exchange:
   - proves the client's identity to the server and the server's to the client,
   - hides the client's public key from anyone watching,
   - uses throwaway (ephemeral) keys on both sides for *forward secrecy*, so a
     stolen key cannot decrypt traffic recorded earlier,
   - includes a timestamp, so a recorded handshake cannot be replayed later.

   It follows the [Noise](https://noiseprotocol.org/) IK pattern, the same one
   WireGuard uses.
3. **Data** ([internal/protocol/session.go](internal/protocol/session.go)). Each
   packet is encrypted with ChaCha20-Poly1305. A message counter serves as the
   nonce, and a sliding window rejects replayed or very old packets.
4. **Server and client** ([internal/vpn](internal/vpn)). These copy packets
   between the TUN device and the UDP socket. The client redoes the handshake
   every 2 minutes so keys stay short-lived. It also sends a keepalive when the
   tunnel is idle, so home routers keep the connection open. The server
   remembers where each client last sent from, so a laptop can switch networks
   (Wi-Fi to phone hotspot, for example) without reconnecting. The server drops
   any packet whose source address isn't that client's tunnel address.

Wire format:

| message    | bytes | layout                                                                         |
| ---------- | ----- | ------------------------------------------------------------------------------ |
| initiation | 116   | type, sender index, ephemeral key, encrypted static key, encrypted timestamp   |
| response   | 60    | type, sender index, receiver index, ephemeral key, empty authenticated payload |
| data       | 32+n  | type, receiver index, counter, encrypted IP packet + 16-byte tag               |

## Setup

You need a server with a public IP address, such as a $5/month Linux VPS, and
a client, such as your Mac.

### 1. Build

```bash
go build -o vpn ./cmd/vpn                                  # for this Mac
GOOS=linux GOARCH=amd64 go build -o vpn-linux ./cmd/vpn    # for the server
scp vpn-linux root@YOUR_SERVER:/usr/local/bin/vpn
```

### 2. Make keys

On each machine:

```bash
vpn genkey > private.key
vpn pubkey < private.key      # share this public key with the other side
```

### 3. Configure

Copy `server.example.json` to `server.json` on the server, and
`client.example.json` to `client.json` on the client. Fill in the keys:
each machine's own private key, plus the other machine's public key.

- `nat_interface` is the server's internet-facing interface. Run `ip route` and
  look at the `default ... dev eth0` line. If you leave it out, clients can
  reach the server but not the internet through it.
- `route_all_traffic: true` sends all of the client's IPv4 traffic through the
  VPN. Set it to `false` if you only want to reach the server's tunnel
  address (10.8.0.1).
- Each client needs its own entry in `peers`, with its own unique address.

`*.json` is in `.gitignore`, so files with real keys won't get committed.

### 4. Run

```bash
# server: also open UDP port 51820 in the VPS firewall
sudo vpn server -c server.json

# client
sudo vpn client -c client.json
```

To check that it works, run `ping 10.8.0.1` from the client. With
`route_all_traffic` on, `curl ifconfig.me` should print the server's IP address.
Press Ctrl-C to disconnect; your routes are restored.

## Tests

```bash
go test -race ./...
```

The tests cover the handshake, encryption, replay and tampering rejection, and
impostor servers and clients. They also run a server and client end to end
over localhost UDP, using fake TUN devices so no root access is needed.

## Limitations (compared to WireGuard)

- IPv4 only inside the tunnel. With `route_all_traffic`, IPv6 traffic still
  bypasses the VPN, so turn IPv6 off on the client if that matters to you.
- **DNS isn't changed.** DNS lookups still go to your local network's
  resolver, so that network can see which sites you look up.
- There's no protection against floods of handshake messages. WireGuard uses
  "cookies" for this.
- If the server restarts, clients take up to 2 minutes to reconnect, because
  they only notice at the next scheduled handshake.
- Each packet costs one system call. That's fine for normal use but slower
  than kernel WireGuard.
- Runs on macOS and Linux.
