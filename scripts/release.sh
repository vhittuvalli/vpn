#!/usr/bin/env bash
# Builds release archives for every supported platform into dist/.
# Usage: scripts/release.sh v0.1.0
set -euo pipefail

version=${1:?usage: scripts/release.sh VERSION}
cd "$(dirname "$0")/.."
rm -rf dist && mkdir -p dist

for target in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64; do
	os=${target%/*} arch=${target#*/}
	name="vpn_${version#v}_${os}_${arch}"
	mkdir -p "dist/$name"
	CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
		-ldflags "-s -w -X main.version=$version" -o "dist/$name/vpn" ./cmd/vpn
	cp README.md LICENSE server.example.json client.example.json packaging/vpn.service "dist/$name/"
	tar -C dist -czf "dist/$name.tar.gz" "$name"
	rm -rf "dist/$name"
done

(cd dist && shasum -a 256 *.tar.gz > checksums.txt)
ls -lh dist
