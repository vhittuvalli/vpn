#!/usr/bin/env bash
# Builds the Windows app: dist/VPN-<version>-windows-x64.zip and
# dist/VPN-<version>-windows-arm64.zip, each holding a VPN folder with
# VPN.exe, wintun.dll and its license, and a short README.
# Usage: scripts/winapp.sh v0.3.0
set -euo pipefail

version=${1:?usage: scripts/winapp.sh VERSION}
cd "$(dirname "$0")/.."

# Wintun, WireGuard's TUN driver for Windows. The DLLs are signed by
# WireGuard LLC and may be shipped unmodified alongside programs that use
# them only through its API; the pinned checksum guards the download.
wintun_url=https://www.wintun.net/builds/wintun-0.14.1.zip
wintun_sha256=07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51

work=$(mktemp -d)
trap 'rm -rf "$work" cmd/vpn/rsrc_windows_*.syso' EXIT
mkdir -p dist

curl -fsSL -o "$work/wintun.zip" "$wintun_url"
echo "$wintun_sha256  $work/wintun.zip" | shasum -a 256 -c -
unzip -q "$work/wintun.zip" -d "$work"

# Icon, version info and a manifest (DPI-aware, modern controls) for VPN.exe.
numeric=${version#v}
numeric=${numeric%%-*}
go run ./scripts/appicon "$work/icon.iconset"
go run github.com/tc-hib/go-winres@v0.3.3 simply --arch amd64,arm64 --out cmd/vpn/rsrc \
	--icon "$work/icon.iconset/icon_256x256.png" --manifest gui \
	--product-name VPN --file-description VPN \
	--product-version "$numeric" --file-version "$numeric"

for arch in amd64 arm64; do
	label=$arch
	[ "$arch" = amd64 ] && label=x64
	dir="$work/$arch/VPN"
	mkdir -p "$dir"
	# windowsgui: no console window when it's double-clicked or run as a service.
	CGO_ENABLED=0 GOOS=windows GOARCH=$arch go build -trimpath \
		-ldflags "-s -w -H windowsgui -X main.version=$version" -o "$dir/VPN.exe" ./cmd/vpn
	cp "$work/wintun/bin/$arch/wintun.dll" "$dir/"
	cp "$work/wintun/LICENSE.txt" "$dir/wintun-LICENSE.txt"
	cat > "$dir/README.txt" <<TXT
VPN ${version} for Windows

1. Keep VPN.exe and wintun.dll together in this folder.
2. Double-click VPN.exe. If Windows SmartScreen says it protected your PC,
   click "More info" and then "Run anyway" (the app isn't code-signed).
3. Allow the prompt asking to make changes: VPN installs a small background
   service that manages the connection.
4. Paste your access key, or click "Get a Free Key" to try the demo server.
   The VPN then lives in the system tray, next to the clock.

To remove it, run "VPN.exe uninstall" from an administrator terminal.
More: https://vhittuvalli.github.io/vpn/
TXT
	(cd "$work/$arch" && zip -qr - VPN) > "dist/VPN-${version#v}-windows-$label.zip"
done
ls -lh dist/VPN-${version#v}-windows-*.zip
