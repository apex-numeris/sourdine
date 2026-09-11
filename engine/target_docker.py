"""Sourdine — cible éphémère en conteneurs (fidélité : vrais Prometheus + Alertmanager).

Le banc monte SA PROPRE cible jetable (projet compose `sourdine`, ports liés à
127.0.0.1) et la détruit lui-même. Il ne vise JAMAIS l'Alertmanager/Prometheus de
production et ne modifie aucune config existante : toutes les manipulations
(injection d'alerte, silence, coupure d'exporter) se font sur cette instance
isolée et jetable.

Observation fidèle : « l'alarme est levée » = la notification atteint le sink
webhook (post-inhibition, post-silence, post-routage) — pas seulement l'état
interne d'Alertmanager.

NB : la cible sim (`target_sim`) reste la référence déterministe. La cible docker
dépend du temps réel (intervalles de scrape/évaluation, group_wait) ; certains
vecteurs à fenêtre longue (low-and-slow, repeat_interval) exigent un temps de
décantation et sont donc moins déterministes ici. Le détecteur, lui, est identique.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any, Optional

from engine import model
from engine.target_base import Target
from engine.types import (
    Alert, RawResult, Scenario, Silence, SupervisionState, Trace,
    VEC_FIREWALL_DOWN_SPOOF, VEC_INSTANCE_DOWN_SPOOF, VEC_POSTGRES_DOWN_SPOOF,
    VEC_LOW_AND_SLOW, VEC_SILENCE_ABUSE, VEC_SILENCE_SHARED_LABEL,
    VEC_GROUPING_REPEAT_ABUSE, VEC_EXPORTER_CUTOFF, VEC_THRESHOLD_FLAPPING,
)

_HERE = os.path.dirname(os.path.abspath(__file__))
_COMPOSE = os.path.normpath(os.path.join(_HERE, "..", "target", "docker-compose.yml"))
_PROJECT = "sourdine"

PROM = "http://127.0.0.1:39090"
AM = "http://127.0.0.1:39093"
EXP = "http://127.0.0.1:39080"
SINK = "http://127.0.0.1:39099"

STEP = 2                  # pas de scrape/éval (s) — doit matcher prometheus.yml
SETTLE = 12               # décantation par défaut (s)
SETTLE_LONG = 44          # décantation pour low-and-slow (accumulation)
# map nom de métrique exporter -> nom de signal attendu par le détecteur
_SIGNAL_REMAP = {"inst_up": "up"}


def _http(url: str, method: str = "GET", payload: Any = None, timeout: float = 5.0):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read().decode()
    if not body.strip():
        return None
    try:
        return json.loads(body)          # réponses JSON (AM, Prometheus, sink /received)
    except json.JSONDecodeError:
        return body                       # réponses texte (exporter/sink : "ok")


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts)) + "Z"


class DockerTarget(Target):
    name = "docker"

    def __init__(self) -> None:
        # alertes injectées via l'API AM (spoof, flood) à résoudre entre scénarios,
        # sinon leur endsAt lointain contaminerait les scénarios suivants.
        self._injected: list[tuple[str, dict]] = []

    def setup(self) -> None:
        subprocess.run(["docker", "compose", "-p", _PROJECT, "-f", _COMPOSE, "up", "-d"],
                       check=True)
        self._wait_ready()

    def teardown(self) -> None:
        subprocess.run(["docker", "compose", "-p", _PROJECT, "-f", _COMPOSE,
                        "down", "-v", "-t", "3"], check=False)

    # -- attente de disponibilité --------------------------------------------
    def _wait_ready(self, timeout: float = 90.0) -> None:
        deadline = time.time() + timeout
        checks = [f"{PROM}/-/ready", f"{AM}/-/ready", f"{SINK}/healthz", f"{EXP}/healthz"]
        pending = set(checks)
        while time.time() < deadline and pending:
            for url in list(pending):
                try:
                    urllib.request.urlopen(url, timeout=2)
                    pending.discard(url)
                except Exception:
                    pass
            if pending:
                time.sleep(2)
        if pending:
            raise SystemExit(f"Cible docker non prête : {pending}")

    # -- primitives de contrôle ----------------------------------------------
    def _reset(self) -> None:
        _http(f"{EXP}/reset", "POST", {})
        _http(f"{SINK}/reset", "POST", {})
        # résoudre les alertes injectées au scénario précédent (endsAt dans le passé)
        past = time.time()
        for name, labels in self._injected:
            try:
                _http(f"{AM}/api/v2/alerts", "POST",
                      [{"labels": {"alertname": name, **labels},
                        "startsAt": _iso(past - 600), "endsAt": _iso(past)}])
            except Exception:
                pass
        self._injected.clear()
        for s in (_http(f"{AM}/api/v2/silences") or []):
            sid = s.get("id")
            if sid and s.get("status", {}).get("state") == "active":
                try:
                    _http(f"{AM}/api/v2/silence/{sid}", "DELETE")
                except urllib.error.HTTPError:
                    pass
        # laisser les alertes (règles + injectées résolues) se vider côté AM
        time.sleep(STEP * 4)

    def _set_metric(self, metric: str, labels: dict, value: float) -> None:
        _http(f"{EXP}/set", "POST", {"metric": metric, "labels": labels, "value": value})

    def _del_metric(self, metric: str, labels: dict) -> None:
        _http(f"{EXP}/del", "POST", {"metric": metric, "labels": labels})

    def _post_alert(self, name: str, labels: dict) -> None:
        now = time.time()
        body = [{"labels": {"alertname": name, **labels},
                 "startsAt": _iso(now), "endsAt": _iso(now + 600)}]
        _http(f"{AM}/api/v2/alerts", "POST", body)
        self._injected.append((name, labels))

    def _post_silence(self, matchers: dict, broad: bool) -> None:
        now = time.time()
        ms = []
        for k, v in matchers.items():
            is_re = v.startswith("~")
            ms.append({"name": k, "value": v[1:] if is_re else v, "isRegex": is_re, "isEqual": True})
        _http(f"{AM}/api/v2/silences", "POST", {
            "matchers": ms, "startsAt": _iso(now), "endsAt": _iso(now + 600),
            "createdBy": "sourdine-bench", "comment": "broad" if broad else "narrow",
        })

    # -- exécution ------------------------------------------------------------
    def execute(self, sc: Scenario) -> tuple[RawResult, SupervisionState, Trace]:
        self._reset()
        t0 = time.time()   # début de fenêtre PROPRE au scénario : évite le bleed TSDB
                           # (Prometheus retient l'historique ; sans borne basse, les
                           # samples du scénario précédent pollueraient les heuristiques)
        gt = sc.ground_truth
        labels = dict(gt.labels) if gt.labels else {}
        job = labels.get("job", "firewall")
        instance = labels.get("instance", "fw-1")
        expected_signal = model.ALERT_RULES.get(gt.expected_alert or "", {}).get("signal")
        expected_thr = model.ALERT_RULES.get(gt.expected_alert or "", {}).get("threshold", 0.0)
        trace = Trace()
        settle = SETTLE

        if sc.event.get("make_fire") and expected_signal:
            self._set_metric(expected_signal, labels or {"job": job, "instance": instance},
                             expected_thr + max(70.0, expected_thr))
            trace.add(0, "event_injected", alert=gt.expected_alert)

        v = sc.vector
        params = sc.masking.get("params", {}) if sc.masking else {}

        if v in (VEC_FIREWALL_DOWN_SPOOF, VEC_INSTANCE_DOWN_SPOOF, VEC_POSTGRES_DOWN_SPOOF):
            src = {
                VEC_FIREWALL_DOWN_SPOOF: ("FirewallDown", {"job": job}),
                VEC_INSTANCE_DOWN_SPOOF: ("InstanceDown", {"instance": instance, "job": job}),
                VEC_POSTGRES_DOWN_SPOOF: ("PostgreSQLDown", {"job": labels.get("job", "postgresql")}),
            }[v]
            self._post_alert(src[0], src[1])
            trace.add(2, "inhibitor_alert_appeared", alertname=src[0])
        elif v == VEC_LOW_AND_SLOW:
            self._set_metric("attack_rate", {"job": job, "instance": instance}, params.get("rate", 30.0))
            settle = SETTLE_LONG
        elif v == VEC_THRESHOLD_FLAPPING:
            # oscillation autour du seuil : chaque phase haute dure moins que le `for:`
            # (6 s), l'alerte reste pending puis retombe -> ne fire jamais. On produit
            # assez de franchissements pour que la baseline puisse rattraper (catchable).
            sig = expected_signal or "attack_rate"
            lset = labels or {"job": job, "instance": instance}
            high = float(params.get("high", expected_thr + 20.0))
            low = float(params.get("low", 10.0))
            n_spikes = params.get("spikes")
            if n_spikes:  # variante FURTIVE : peu de franchissements -> résiduel
                self._set_metric(sig, lset, low)
                for _ in range(int(n_spikes)):
                    time.sleep(STEP * 2)
                    self._set_metric(sig, lset, high)
                    time.sleep(STEP)          # bref (< for:)
                    self._set_metric(sig, lset, low)
            else:        # rattrapable : oscillation soutenue
                for _ in range(int(params.get("cycles", 7))):
                    self._set_metric(sig, lset, high)
                    time.sleep(STEP + 1)      # < for: (6 s)
                    self._set_metric(sig, lset, low)
                    time.sleep(STEP + 1)
            settle = STEP * 2
            trace.add(1, "threshold_flapping", high=high, low=low, spikes=n_spikes)
        elif v == VEC_SILENCE_ABUSE:
            broad = bool(params.get("broad", False))
            # AM refuse un matcher qui matche la chaîne vide (garde-fou « tout silencer ») ;
            # ~.+ reste abusivement large (toute instance non vide) mais est accepté.
            matchers = {"instance": "~.+"} if broad else {"alertname": gt.expected_alert or "~.+", "job": job}
            self._post_silence(matchers, broad)
        elif v == VEC_SILENCE_SHARED_LABEL:
            # silence par label PARTAGÉ (job) sans matcher alertname : balaie toute la
            # classe d'alertes du job sous couvert de maintenance de service.
            label = params.get("label", "job")
            value = params.get("value", job if label == "job" else instance)
            self._post_silence({label: value}, broad=False)
        elif v == VEC_GROUPING_REPEAT_ABUSE:
            for i in range(int(params.get("count", 20))):
                self._post_alert(gt.expected_alert or "HighAttackRate", {"job": job, "instance": f"flood-{i}"})
        elif v == VEC_EXPORTER_CUTOFF:
            self._set_metric(expected_signal or "attack_rate",
                             labels or {"job": job, "instance": instance}, expected_thr + 80.0)
            time.sleep(STEP * 3)
            # coupure : l'instance tombe (inst_up=0) et la métrique d'attaque disparaît
            self._set_metric("inst_up", {"job": job, "instance": instance}, 0.0)
            self._del_metric(expected_signal or "attack_rate", labels or {"job": job, "instance": instance})
            trace.add(3, "scrape_gap_start", instance=instance)
        elif v == "none":
            bk = sc.masking.get("type") if sc.masking else None
            if bk == "benign_silence":
                broad = bool(params.get("broad", False))
                matchers = {"instance": "~.+"} if broad else {"alertname": params.get("alertname", "DiskSpaceLow"), "instance": instance}
                self._post_silence(matchers, broad)
                if params.get("minor_activity"):
                    self._set_metric("attack_rate", {"job": job, "instance": instance}, params["minor_activity"])
            elif bk == "benign_exporter_restart":
                self._set_metric("inst_up", {"job": job, "instance": instance}, 0.0)
            elif bk == "benign_spike":
                self._set_metric("attack_rate", {"job": job, "instance": instance}, params.get("rate", 30.0))
                settle = SETTLE_LONG
            elif bk == "benign_jitter":
                # trafic licite sous le seuil : aucun franchissement, somme intégrée
                # basse -> ni flapping ni low-and-slow. Vrai négatif.
                avg = (float(params.get("high", 35.0)) + float(params.get("low", 5.0))) / 2.0
                self._set_metric("attack_rate", {"job": job, "instance": instance}, avg)
            elif bk == "benign_brief_spike":
                # un unique pic licite trop bref pour firer (< for:) : un seul franchissement.
                # Retomber à une ligne de base NON nulle (pas 0) pour ne pas simuler un
                # trou de collecte (qui déclencherait exporter_cutoff -> faux positif).
                self._set_metric("attack_rate", {"job": job, "instance": instance},
                                 float(params.get("spike", 65.0)))
                time.sleep(STEP)
                self._set_metric("attack_rate", {"job": job, "instance": instance},
                                 float(params.get("baseline", 5.0)))

        time.sleep(settle)

        state = self._snapshot(trace, t0)
        notified = self._sink_notified()
        alarm_raised = False
        if gt.alarm_expected and gt.expected_alert:
            alarm_raised = any(n["name"] == gt.expected_alert and
                               all(n["labels"].get(k) == vv for k, vv in labels.items())
                               for n in notified)
        raw = RawResult(alarm_raised=alarm_raised, notified_alerts=notified,
                        fired_alerts=[{"name": a.name, "labels": a.labels,
                                       "inhibited_by": a.inhibited_by, "silenced_by": a.silenced_by}
                                      for a in state.alerts])
        return raw, state, trace

    # -- observation ----------------------------------------------------------
    def _sink_notified(self) -> list[dict]:
        data = _http(f"{SINK}/received") or {"alerts": []}
        out = []
        for a in data.get("alerts", []):
            lbls = dict(a.get("labels", {}))
            name = lbls.pop("alertname", "")
            out.append({"name": name, "labels": lbls})
        return out

    def _snapshot(self, trace: Trace, start: float) -> SupervisionState:
        # alertes Alertmanager (avec résolution fingerprint -> nom pour inhibitedBy)
        amalerts = _http(f"{AM}/api/v2/alerts") or []
        fp_to_name = {a.get("fingerprint"): a.get("labels", {}).get("alertname", "") for a in amalerts}
        alerts: list[Alert] = []
        for a in amalerts:
            lbls = dict(a.get("labels", {}))
            name = lbls.pop("alertname", "")
            st = a.get("status", {})
            alerts.append(Alert(
                name=name, labels=lbls,
                inhibited_by=[fp_to_name.get(fp, fp) for fp in st.get("inhibitedBy", [])],
                silenced_by=list(st.get("silencedBy", [])),
            ))
        # silences
        silences: list[Silence] = []
        for s in (_http(f"{AM}/api/v2/silences") or []):
            if s.get("status", {}).get("state") != "active":
                continue
            matchers = {m["name"]: ("~" + m["value"] if m.get("isRegex") else m["value"]) for m in s.get("matchers", [])}
            broad = any(m.get("isRegex") and m["name"] == "instance" for m in s.get("matchers", []))
            silences.append(Silence(id=s.get("id", ""), matchers=matchers, created_tick=0,
                                    comment=s.get("comment", ""), broad=broad))
        # historique métrique (query_range -> ticks)
        metric_history = self._metric_history(start)
        return SupervisionState(alerts=alerts, silences=silences,
                                metric_history=metric_history, horizon=model.HORIZON)

    def _metric_history(self, start: float) -> dict[str, list[Optional[float]]]:
        end = time.time()   # fenêtre [début du scénario ; maintenant] — pas de bleed
        out: dict[str, list[Optional[float]]] = {}
        for metric in ("attack_rate", "jailbreak_rate", "critical_attacks", "pg_conns",
                       "inst_up", "fw_up", "pg_up"):
            try:
                res = _http(f"{PROM}/api/v1/query_range?query={metric}&start={start:.0f}"
                            f"&end={end:.0f}&step={STEP}s")
            except Exception:
                continue
            for series in (res or {}).get("data", {}).get("result", []):
                lbls = {k: v for k, v in series.get("metric", {}).items()
                        if k in ("job", "instance")}
                signal = _SIGNAL_REMAP.get(metric, metric)
                out[model.series_key(signal, lbls)] = [float(v) for _t, v in series.get("values", [])]
        return out
