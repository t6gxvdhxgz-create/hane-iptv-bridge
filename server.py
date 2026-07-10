#!/usr/bin/env python3
"""
HaNe IPTV bridge – Render.com / Railway deployment wrapper.
Converts the raw BaseHTTPServer proxy into a proper WSGI-compatible app
that Render can run. All proxy logic stays in proxy.py; this file just
provides the server entry-point that reads $PORT from the environment.
"""
import os
import sys

# Make sure proxy.py (in the same directory) is importable
sys.path.insert(0, os.path.dirname(__file__))

# Override the PORT env var before proxy.py sets its default
PORT = int(os.environ.get("PORT", 8899))

from http.server import ThreadingHTTPServer
import proxy  # imports the proxy module from the same folder

# Patch PORT in the proxy module so it uses the platform's port
proxy.PORT = PORT

if __name__ == "__main__":
    addr = ("0.0.0.0", PORT)
    httpd = ThreadingHTTPServer(addr, proxy.Proxy)
    print(f"HaNe IPTV bridge listening on port {PORT}", flush=True)
    httpd.serve_forever()

