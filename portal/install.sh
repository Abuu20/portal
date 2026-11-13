#!/usr/bin/env bash
# PORTAL installer / updater.
#
# Fetches the latest .deb from this repo's GitHub Releases ("latest" rolling
# build) and installs it with apt. Safe to re-run any time you want to
# update -- it's the exact same command for install and update.
#
#   curl -fsSL https://raw.githubusercontent.com/Abuu20/portal/main/portal/install.sh | sudo bash
#
# Or download it first and read it before running, which is always a
# reasonable thing to do with a script piped into a shell:
#
#   curl -fsSLO https://raw.githubusercontent.com/Abuu20/portal/main/portal/install.sh
#   less install.sh
#   sudo bash install.sh
set -euo pipefail

REPO="Abuu20/portal"
API="https://api.github.com/repos/$REPO/releases/tags/latest"

if [ "$(id -u)" -ne 0 ]; then
  echo "This installs a system package, so it needs root. Re-run with sudo:" >&2
  echo "  curl -fsSL https://raw.githubusercontent.com/$REPO/main/portal/install.sh | sudo bash" >&2
  exit 1
fi

for c in curl apt; do
  command -v "$c" >/dev/null 2>&1 || { echo "Missing required command: $c" >&2; exit 1; }
done

echo "+ Looking up the latest PORTAL build..."
DEB_URL=$(curl -fsSL "$API" \
  | grep -o '"browser_download_url": *"[^"]*\.deb"' \
  | cut -d'"' -f4 | head -1)

if [ -z "$DEB_URL" ]; then
  echo "Could not find a .deb in the 'latest' release of $REPO. Check:" >&2
  echo "  https://github.com/$REPO/releases/tag/latest" >&2
  exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
echo "+ Downloading $DEB_URL"
curl -fsSL "$DEB_URL" -o "$TMP/portal.deb"

echo "+ Installing with apt (pulls in python3-flask etc.)"
apt install -y "$TMP/portal.deb"

echo
echo "Done. Run 'portal' to open it (also in your application launcher)."
echo "Your history/notes/scope list live in ~/.local/share/portal and are never touched by this."
echo "Want the recon/CTF command-line tools too (nmap, whois, rustscan, dalfox, ...)? Run: portal --install-tools"
