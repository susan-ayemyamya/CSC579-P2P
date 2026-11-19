"""
New file: live web view of the simulation.

Run:   python -m simulation.server        then open http://127.0.0.1:8080

The page starts and stops simulations (simulation/engine.py) and shows
the overlay live: honest peers, attackers, quarantined peers, delivered
routes, trust scores, alerts and the delivery rate over time. Only the
Python standard library is used, so nothing extra has to be installed.
"""

import argparse
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from simulation.engine import Simulation

WEB_DIR = os.path.join(os.path.dirname(__file__), "web")

_current = None
_current_lock = threading.Lock()


# Replace the running simulation (if any) with a new one.
def start_simulation(settings):
    global _current
    with _current_lock:
        if _current is not None:
            _current.stop()
        _current = None
        simulation = Simulation(**settings)
        simulation.start()
        _current = simulation
    return simulation


def stop_simulation():
    with _current_lock:
        if _current is not None:
            _current.stop()


# Serves the page and a small JSON API.
class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            with open(os.path.join(WEB_DIR, "index.html"), "rb") as file:
                self._send(200, file.read(), "text/html; charset=utf-8")
        elif self.path == "/api/state":
            state = _current.state() if _current is not None else {"running": False, "phase": "idle"}
            self._json(200, state)
        elif self.path == "/api/timeline.csv":
            text = _current.timeline_csv() if _current is not None else ""
            self._send(200, text.encode("utf-8"), "text/csv",
                       {"Content-Disposition": "attachment; filename=timeline.csv"})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/api/start":
            length = int(self.headers.get("Content-Length") or 0)
            try:
                settings = json.loads(self.rfile.read(length) or b"{}")
                start_simulation(settings)
                self._json(200, {"status": "started"})
            except (ValueError, TypeError) as error:
                self._json(400, {"error": str(error)})
        elif self.path == "/api/stop":
            threading.Thread(target=stop_simulation, daemon=True).start()
            self._json(200, {"status": "stopping"})
        else:
            self._json(404, {"error": "not found"})

    def _json(self, code, data):
        self._send(code, json.dumps(data).encode("utf-8"), "application/json")

    def _send(self, code, body, content_type, headers=None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main(argv=None):
    parser = argparse.ArgumentParser(description="Live web view of the P2P simulation")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Simulation page: http://127.0.0.1:{args.port}   (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_simulation()
        server.server_close()


if __name__ == "__main__":
    main()
