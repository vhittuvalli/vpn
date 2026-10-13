#!/bin/sh
# Installs the latest vpn release.
#
#   curl -fsSL https://raw.githubusercontent.com/vhittuvalli/vpn/main/install.sh | sh
#
# Set VPN_VERSION=v0.1.0 to pick a version, or INSTALL_DIR to change where
# the binary goes (default /usr/local/bin).
set -eu

repo="vhittuvalli/vpn"
install_dir="${INSTALL_DIR:-/usr/local/bin}"

case "$(uname -s)" in
	Darwin) os=darwin ;;
	Linux) os=linux ;;
	*) echo "unsupported OS: $(uname -s) (macOS and Linux only)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
	x86_64 | amd64) arch=amd64 ;;
	arm64 | aarch64) arch=arm64 ;;
	*) echo "unsupported CPU: $(uname -m)" >&2; exit 1 ;;
esac

version="${VPN_VERSION:-}"
if [ -z "$version" ]; then
	version=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" |
		sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
	[ -n "$version" ] || { echo "could not find the latest release" >&2; exit 1; }
fi

archive="vpn_${version#v}_${os}_${arch}.tar.gz"
base="https://github.com/$repo/releases/download/$version"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "downloading vpn $version for $os/$arch"
curl -fsSL -o "$tmp/$archive" "$base/$archive"
curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt"

expected=$(grep " $archive\$" "$tmp/checksums.txt" | cut -d' ' -f1)
if command -v sha256sum >/dev/null 2>&1; then
	actual=$(sha256sum "$tmp/$archive" | cut -d' ' -f1)
else
	actual=$(shasum -a 256 "$tmp/$archive" | cut -d' ' -f1)
fi
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
	echo "checksum mismatch for $archive" >&2
	exit 1
fi

tar -C "$tmp" -xzf "$tmp/$archive"
src="$tmp/${archive%.tar.gz}/vpn"
if [ -w "$install_dir" ]; then
	install -m 755 "$src" "$install_dir/vpn"
else
	echo "installing to $install_dir (needs sudo)"
	sudo install -m 755 "$src" "$install_dir/vpn"
fi

"$install_dir/vpn" version
echo "run 'vpn' for usage, or see https://github.com/$repo#setup"
