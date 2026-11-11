#!/usr/bin/env python3
"""PORTAL - local, single-user lookup dashboard.

Type one thing (IP, domain, email, URL, coordinates, place, barcode, CVE, hash,
@username, phone) or drop a file, and every relevant module runs in parallel,
each result in its own window. Binds to 127.0.0.1 only.

This file is only the entry point. The code lives in portal_lib/, one module per
concern (core, net, intel, web, geo, files, headers, accounts, lookups, tools,
surface, store, ai, routes).
"""
from __future__ import annotations

import argparse
import os
import socket
import threading
import webbrowser

from portal_lib.core import app
# importing these modules registers their /api routes on the Flask app
from portal_lib import accounts, ai, correlate, files, headers, lookups, routes, store, surface, tools  # noqa: F401

def main():
    ap = argparse.ArgumentParser(description="PORTAL local lookup dashboard")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORTAL_PORT", 8137)))
    ap.add_argument("--open", action="store_true", help="open the dashboard in your browser")
    ap.add_argument("--no-open-if-running", action="store_true",
                    help="if PORTAL already answers on the port, just open the browser and exit")
    a = ap.parse_args()
    if a.no_open_if_running:
        try:
            socket.create_connection(("127.0.0.1", a.port), timeout=0.5).close()
            webbrowser.open(f"http://127.0.0.1:{a.port}/")
            return
        except OSError:
            pass
    if a.open:
        threading.Timer(1.0, lambda: webbrowser.open(f"http://127.0.0.1:{a.port}/")).start()
    print(f"PORTAL running at http://127.0.0.1:{a.port}/  (Ctrl+C to stop)")
    app.run(host="127.0.0.1", port=a.port, threaded=True)

if __name__ == "__main__":
    main()
