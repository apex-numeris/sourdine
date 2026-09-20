#!/usr/bin/env python3
"""Sourdine : sink webhook de la cible éphémère (stdlib uniquement).

Reçoit les notifications d'Alertmanager (POST /) et les mémorise. C'est l'organe
d'observation fidèle : « l'alarme est levée » = sa notification est arrivée ici
(donc NON inhibée, NON silencée, bien routée).

  POST /          webhook Alertmanager
  GET  /received  {"alerts":[{"labels":{...}}, ...]}  (alertes firing reçues)
  POST /reset     vide le registre
  GET  /healthz
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RECEIVED: list[dict] = []


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _ok(self, body="ok", ctype="text/plain"):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        if self.path == "/received":
            self._ok(json.dumps({"alerts": RECEIVED}), "application/json")
        elif self.path == "/healthz":
            self._ok()
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        if self.path == "/reset":
            RECEIVED.clear()
            self._ok()
            return
        n = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            payload = {}
        for a in payload.get("alerts", []):
            if a.get("status", "firing") == "firing":
                RECEIVED.append({"labels": a.get("labels", {})})
        self._ok()


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9099), H).serve_forever()
