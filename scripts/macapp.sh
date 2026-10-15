#!/usr/bin/env bash
# Builds VPN.app (Apple silicon + Intel in one) and wraps it in a disk image
# with a shortcut to Applications. Runs on macOS; needs Xcode command line
# tools for cgo, lipo, iconutil and codesign.
# Usage: scripts/macapp.sh v0.2.0   -> dist/VPN-0.2.0.dmg
set -euo pipefail

version=${1:?usage: scripts/macapp.sh VERSION}
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
app="$work/staging/VPN.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources" dist

for arch in arm64 amd64; do
	CGO_ENABLED=1 GOOS=darwin GOARCH=$arch go build -trimpath \
		-ldflags "-s -w -X main.version=$version" -o "$work/vpn-$arch" ./cmd/vpn
done
lipo -create -output "$app/Contents/MacOS/VPN" "$work/vpn-arm64" "$work/vpn-amd64"

go run ./scripts/appicon "$work/AppIcon.iconset"
iconutil -c icns -o "$app/Contents/Resources/AppIcon.icns" "$work/AppIcon.iconset"

cat > "$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key><string>VPN</string>
	<key>CFBundleDisplayName</key><string>VPN</string>
	<key>CFBundleIdentifier</key><string>com.vhittuvalli.vpn.app</string>
	<key>CFBundleExecutable</key><string>VPN</string>
	<key>CFBundleIconFile</key><string>AppIcon</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleShortVersionString</key><string>${version#v}</string>
	<key>CFBundleVersion</key><string>${version#v}</string>
	<key>LSMinimumSystemVersion</key><string>12.0</string>
	<key>LSUIElement</key><true/>
	<key>NSHighResolutionCapable</key><true/>
	<key>NSHumanReadableCopyright</key><string>MIT licensed</string>
</dict>
</plist>
EOF

# Not signed by an Apple Developer ID: an ad-hoc signature keeps the bundle
# intact, and users approve it once in System Settings.
codesign --force --deep --sign - "$app"

ln -s /Applications "$work/staging/Applications"
dmg="dist/VPN-${version#v}.dmg"
rm -f "$dmg"
hdiutil create -volname "VPN ${version#v}" -srcfolder "$work/staging" -ov -format UDZO "$dmg" >/dev/null
ls -lh "$dmg"
