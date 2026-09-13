#!/usr/bin/env python3
"""Sourdine — exporter synthétique de la cible éphémère (stdlib uniquement).

Sert /metrics au format Prometheus à partir d'un état pilotable par le runner :
  POST /set   {"metric","labels","value"}   upsert d'une série
  POST /del   {"metric","labels"}           retire une série (simule une métrique absente)
  POST /reset {}                            remet l'état par défaut (tout "up")
  GET  /metrics                             exposition Prometheus
  GET  /healthz

Les métriques portent des labels job/instance synthétiques (honor_labels côté
Prometheus). Aucune donnée réelle : tout est fabriqué en laboratoire.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE: dict[str, dict[tuple, float]] = {}


def _defaults():
    STATE.clear()
    STATE["inst_up"] = {
        (("instance", "fw-1"), ("job", "firewall")): 1.0,
        (("instance", "pg-1"), ("job", "postgresql")): 1.0,
    }
    STATE["fw_up"] = {(("job", "firewall"),): 1.0}
    STATE["pg_up"] = {(("job", "postgresql"),): 1.0}
    # heartbeat watchdog (dead man's switch) : toujours vivant (1) tant que la chaine
    # d'alerte l'emet. Le vecteur watchdog_suppression le met a 0 (chaine morte).
    STATE["watchdog"] = {(): 1.0}
    # nombre d'echantillons du dernier scrape (modele de scrape_samples_scraped) : bas au
    # repos. Le vecteur cardinality_flood le fait exploser (bombe de series -> sample_limit).
    STATE["scrape_samples"] = {(): 50.0}


def _key(labels: dict) -> tuple:
    return tuple(sorted(labels.items()))


def _render() -> str:
    lines = []
    for metric, series in STATE.items():
        for lblkey, value in series.items():
            labels = ",".join(f'{k}="{v}"' for k, v in lblkey)
            lines.append(f"{metric}{{{labels}}} {value}")
    return "\n".join(lines) + "\n"


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silencieux
        pass

    def _json(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n) or b"{}")

    def _ok(self, body="ok", ctype="text/plain"):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        if self.path == "/metrics":
            self._ok(_render(), "text/plain; version=0.0.4")
        elif self.path == "/healthz":
            self._ok()
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        if self.path == "/set":
            d = self._json()
            STATE.setdefault(d["metric"], {})[_key(d.get("labels", {}))] = float(d["value"])
            self._ok()
        elif self.path == "/del":
            d = self._json()
            STATE.get(d["metric"], {}).pop(_key(d.get("labels", {})), None)
            self._ok()
        elif self.path == "/reset":
            _defaults()
            self._ok()
        else:
            self.send_response(404); self.end_headers()


if __name__ == "__main__":
    _defaults()
    ThreadingHTTPServer(("0.0.0.0", 8000), H).serve_forever()
