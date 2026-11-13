#!/usr/bin/env bash
# Builds a PORTAL .deb package from this checkout. Needs no root (dpkg-deb --root-owner-group).
#   ./build-deb.sh            -> dist/portal-osint_<version>_all.deb
# Install it with:  sudo apt install ./dist/portal-osint_*_all.deb
# (apt, not dpkg -i, so it pulls in python3-flask etc. automatically)
set -euo pipefail
cd "$(dirname "$0")"
# Only ever use a tag that looks like a real version (v1.2.3, 1.2.3, ...) -- the CI release
# workflow also creates/moves a "latest" tag for the rolling release, and that one is not a
# version number, so --match keeps it from ever being picked up here.
if git describe --tags --always --match 'v[0-9]*' --match '[0-9]*' >/dev/null 2>&1 \
   && git describe --tags --match 'v[0-9]*' --match '[0-9]*' >/dev/null 2>&1; then
  VER="$(git describe --tags --dirty --match 'v[0-9]*' --match '[0-9]*' 2>/dev/null | sed 's/^v//; s/-/./g')"
else
  VER="0~$(date +%Y%m%d).$(git rev-parse --short=8 HEAD 2>/dev/null || echo 0)"
fi
PKG=packaging/debian
APP="$PKG/usr/share/portal"

rm -rf "$APP" dist
mkdir -p "$APP" dist
cp -r server.py portal_lib static "$APP/"
find "$APP" -name __pycache__ -prune -exec rm -rf {} +
find "$PKG" -name "*.orig" -delete

sed "s/__VERSION__/$VER/" packaging/control.in > "$PKG/DEBIAN/control" 2>/dev/null || \
  sed -i "s/^Version: .*/Version: $VER/" "$PKG/DEBIAN/control"

SIZE_KB=$(du -sk "$PKG" --exclude=DEBIAN | awk '{print $1}')
grep -q '^Installed-Size:' "$PKG/DEBIAN/control" && sed -i "s/^Installed-Size:.*/Installed-Size: $SIZE_KB/" "$PKG/DEBIAN/control" \
  || sed -i "/^Priority:/a Installed-Size: $SIZE_KB" "$PKG/DEBIAN/control"

dpkg-deb --build --root-owner-group "$PKG" "dist/portal-osint_${VER}_all.deb"
echo "Built dist/portal-osint_${VER}_all.deb"
