#!/usr/bin/env bash
# Starts PORTAL on 127.0.0.1 and opens it in your browser.
cd "$(dirname "$0")"
exec python3 server.py --port "${PORTAL_PORT:-8137}" --open
