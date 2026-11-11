#!/usr/bin/env bash
# Installs PORTAL for the current user on Kali/KDE Plasma:
#   - background service (systemd --user), starts at login, bound to 127.0.0.1 only
#   - "PORTAL" entry in the application launcher (right-click: Restart / Stop), pinnable to panel/desktop
#   - `portal` command that starts the service if needed and opens the window
# No root needed. Re-run after updating PORTAL. Remove with ./install-kde.sh --uninstall
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
APP="$HOME/.local/opt/portal"
BIN="$HOME/.local/bin"
UNIT="$HOME/.config/systemd/user/portal.service"
DESK="$HOME/.local/share/applications/portal.desktop"
ICON="$HOME/.local/share/icons/hicolor/scalable/apps/portal.svg"
PORT="${PORTAL_PORT:-8137}"

if [[ "${1:-}" == "--uninstall" ]]; then
  systemctl --user disable --now portal.service 2>/dev/null || true
  rm -f "$UNIT" "$DESK" "$ICON" "$BIN/portal"
  rm -rf "$APP"
  systemctl --user daemon-reload 2>/dev/null || true
  command -v kbuildsycoca6 >/dev/null && kbuildsycoca6 >/dev/null 2>&1 || true
  echo "Removed. Your saved history in ~/.local/share/portal and API key file were left alone."
  exit 0
fi

command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }
python3 -c "import flask" 2>/dev/null || { echo "Flask missing. Run: sudo apt install python3-flask"; exit 1; }

mkdir -p "$APP" "$BIN" "$(dirname "$UNIT")" "$(dirname "$DESK")" "$(dirname "$ICON")"
rm -rf "$APP/static" "$APP/portal_lib"
cp -r "$SRC/server.py" "$SRC/portal_lib" "$SRC/static" "$APP/"
find "$APP" -name __pycache__ -prune -exec rm -rf {} +
cp "$SRC/kde/portal.svg" "$ICON"

cat > "$UNIT" <<UNITEOF
[Unit]
Description=PORTAL local lookup dashboard (127.0.0.1 only)

[Service]
Type=simple
ExecStart=/usr/bin/env python3 $APP/server.py --port $PORT
Environment=PYTHONUNBUFFERED=1
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%h/.local/share/portal
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
UNITEOF
# The optional API key comes from the environment or ~/.config/portal/ai.env (read by the server itself).
mkdir -p "$HOME/.local/share/portal"; chmod 700 "$HOME/.local/share/portal"
cat >> "$UNIT" <<'UNITEOF'

[Install]
WantedBy=default.target
UNITEOF

cat > "$BIN/portal" <<LAUNCHEOF
#!/usr/bin/env bash
# One click: start the background service if it is not running, wait for it, open the window.
URL="http://127.0.0.1:$PORT/"
systemctl --user start portal.service
for _ in \$(seq 1 50); do
  (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break
  sleep 0.1
done
for b in chromium chromium-browser google-chrome; do
  if command -v "\$b" >/dev/null; then exec "\$b" --app="\$URL" --class=portal; fi
done
exec xdg-open "\$URL"
LAUNCHEOF
chmod +x "$BIN/portal"

cat > "$DESK" <<DESKEOF
[Desktop Entry]
Type=Application
Name=PORTAL
GenericName=Lookup dashboard
Comment=One search box for IPs, domains, files, places and more
Exec=$BIN/portal
Icon=portal
Terminal=false
Categories=Network;Security;
StartupWMClass=portal
Actions=Restart;Stop;

[Desktop Action Restart]
Name=Restart service
Exec=systemctl --user restart portal.service

[Desktop Action Stop]
Name=Stop service
Exec=systemctl --user stop portal.service
DESKEOF

systemctl --user daemon-reload
systemctl --user enable --now portal.service
command -v kbuildsycoca6 >/dev/null && kbuildsycoca6 >/dev/null 2>&1 || true

echo "Installed. Open the application launcher and search 'PORTAL' (right-click it to pin to the panel), or run: portal"
echo "Optional AI button: put ANTHROPIC_API_KEY=... in ~/.config/portal/ai.env (chmod 600), then: systemctl --user restart portal"
echo
echo "Optional OSINT modules (checked, not installed for you):"
if command -v sherlock >/dev/null || command -v sherlock-project >/dev/null; then
  echo "  [ok]  Sherlock      — @username scans work"
else
  echo "  [..]  Sherlock      — install: pipx install sherlock-project"
fi
if command -v maigret >/dev/null; then
  echo "  [ok]  Maigret       — deep @username scans work"
else
  echo "  [..]  Maigret       — install: pipx install maigret"
fi
if python3 -c "import phonenumbers" 2>/dev/null; then
  echo "  [ok]  phonenumbers  — phone lookups work"
else
  echo "  [..]  phonenumbers  — install: pip install phonenumbers"
fi
case ":$PATH:" in *":$BIN:"*) ;; *) echo "Note: add $BIN to your PATH to use the 'portal' command in a terminal.";; esac
