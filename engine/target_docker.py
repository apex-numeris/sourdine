"""Sourdine : cible éphémère en conteneurs (fidélité : vrais Prometheus + Alertmanager).

Le banc monte SA PROPRE cible jetable (projet compose `sourdine`, ports liés à
127.0.0.1) et la détruit lui-même. Il ne vise JAMAIS l'Alertmanager/Prometheus de
production et ne modifie aucune config existante : toutes les manipulations
(injection d'alerte, silence, coupure d'exporter) se font sur cette instance
isolée et jetable.

Observation fidèle : « l'alarme est levée » = la notification atteint le sink
webhook (post-inhibition, post-silence, post-routage) : pas seulement l'état
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
    VEC_SILENCE_REGEX_ALERTNAME, VEC_GROUPING_REPEAT_ABUSE, VEC_EXPORTER_CUTOFF,
    VEC_SELECTIVE_METRIC_DROP, VEC_THRESHOLD_FLAPPING, VEC_FALSE_RESOLVED,
    VEC_STALE_REPLAY, VEC_STATISTICAL_REPLAY, VEC_CONSTRAINED_REPLAY,
    VEC_ROUTE_BLACKHOLE, VEC_WATCHDOG_SUPPRESSION, VEC_CARDINALITY_FLOOD,
    VEC_ROGUE_INHIBITOR, VEC_GUARD_OUTAGE_COVER, VEC_INHIBITION_SCOPE_CREEP,
    VEC_PRELOADED_SILENCE,
)

# Label de routage qui envoie une alerte vers le récepteur « trou noir » (route baked
# dans alertmanager.yml). Représente la route qu'un attaquant avec accès au routage
# ajoute pour avaler une classe d'alertes (T1562.006). Le détecteur ne lit pas ce label
# mais `Alert.route_muted`, que `_snapshot` en dérive (résolution de la route observée).
_BLACKHOLE_LABEL = ("route_target", "blackhole")

# Déviations déterministes (bruit réaliste) pour les signaux à distribution préservée
# (statistical_replay, benign_noise) : posées point par point sur l'exporter.
_NOISE = [3.0, -4.0, 6.0, -2.0, 5.0, -6.0, 8.0, -1.0, -3.0, 4.0]

_HERE = os.path.dirname(os.path.abspath(__file__))
_COMPOSE = os.path.normpath(os.path.join(_HERE, "..", "target", "docker-compose.yml"))
_PROJECT = "sourdine"

PROM = "http://127.0.0.1:39090"
AM = "http://127.0.0.1:39093"
EXP = "http://127.0.0.1:39080"
SINK = "http://127.0.0.1:39099"

STEP = 2                  # pas de scrape/éval (s) : doit matcher prometheus.yml
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
        # startsAt dans le passé : le silence est actif dès sa création (pas de fenêtre
        # d'ambiguïté d'activation), ce qui fiabilise son application aux alertes à venir.
        _http(f"{AM}/api/v2/silences", "POST", {
            "matchers": ms, "startsAt": _iso(now - 60), "endsAt": _iso(now + 600),
            "createdBy": "sourdine-bench", "comment": "broad" if broad else "narrow",
        })

    # -- confirmation d'activation d'un masquage préventif --------------------
    # Robustesse : un masquage préventif (inhibition/silence) doit être ACTIF dans
    # AM avant que l'alerte cible fire, sinon l'alerte peut être notifiée au premier
    # flush avant qu'AM applique le muting (course de timing observée). Ces sondes
    # confirment l'enregistrement ; l'appelant stabilise ensuite (> group_interval).
    def _await_alert_active(self, name: str, timeout: float = 10.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                for a in (_http(f"{AM}/api/v2/alerts") or []):
                    if (a.get("labels", {}).get("alertname") == name
                            and a.get("status", {}).get("state") == "active"):
                        return True
            except Exception:
                pass
            time.sleep(0.5)
        return False

    def _await_silence_active(self, timeout: float = 10.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                for s in (_http(f"{AM}/api/v2/silences") or []):
                    if s.get("status", {}).get("state") == "active":
                        return True
            except Exception:
                pass
            time.sleep(0.5)
        return False

    # -- exécution (retry déterministe pour les masquages préventifs) ----------
    _PREVENTIVE = (VEC_FIREWALL_DOWN_SPOOF, VEC_INSTANCE_DOWN_SPOOF, VEC_POSTGRES_DOWN_SPOOF,
                   VEC_SILENCE_ABUSE, VEC_SILENCE_SHARED_LABEL, VEC_SILENCE_REGEX_ALERTNAME,
                   VEC_ROGUE_INHIBITOR, VEC_GUARD_OUTAGE_COVER,
                   VEC_INHIBITION_SCOPE_CREEP, VEC_PRELOADED_SILENCE)

    def execute(self, sc: Scenario) -> tuple[RawResult, SupervisionState, Trace]:
        # Un masquage préventif (inhibition/silence) DOIT masquer (vecteur STRONG). Une
        # fuite résiduelle = course de démarrage d'Alertmanager (le silence à matcher
        # REGEX sur alertname est le plus tenace) : le masquage est actif mais pas encore
        # appliqué au 1er flush de l'alerte. On re-tente alors le scénario complet (reset
        # inclus) ; la course étant rare et ré-indépendante, 4 tentatives ramènent la
        # proba de fuite à ~(1/4)^4 < 0,5 %. Les vecteurs NON préventifs ne sont jamais
        # re-tentés : leur résultat (dont false_resolved masked=False en docker) est voulu.
        attempts = 4 if (sc.vector in self._PREVENTIVE and sc.ground_truth.alarm_expected) else 1
        raw, state, trace = self._execute_once(sc)
        for _ in range(attempts - 1):
            if not (sc.ground_truth.alarm_expected and raw.alarm_raised):
                break                      # masqué -> succès, on garde cette exécution
            raw, state, trace = self._execute_once(sc)
        return raw, state, trace

    def _execute_once(self, sc: Scenario) -> tuple[RawResult, SupervisionState, Trace]:
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

        v = sc.vector
        params = sc.masking.get("params", {}) if sc.masking else {}

        def _fire_event():
            if sc.event.get("make_fire") and expected_signal:
                self._set_metric(expected_signal, labels or {"job": job, "instance": instance},
                                 expected_thr + max(70.0, expected_thr))
                trace.add(0, "event_injected", alert=gt.expected_alert)

        # === Masquages PRÉVENTIFS (inhibition / silence) : établis et CONFIRMÉS actifs,
        #     puis stabilisés (> group_interval), AVANT de faire firer l'alerte cible.
        #     ROBUSTESSE : sinon l'alerte peut être notifiée au premier flush AVANT qu'AM
        #     applique le muting (course de timing observée, ~1 run/3, à charge nulle :
        #     l'inhibiteur/silence était pourtant actif). Poser le masquage d'abord et le
        #     confirmer garantit qu'il est dans le muting index d'AM quand l'alerte fire,
        #     rendant le masquage DÉTERMINISTE sans toucher aux seuils ni au `for:`. ===
        # SOURCE UNIQUE : la même liste pilotait le retry (`_PREVENTIVE`) et ce test, en
        # deux exemplaires : un vecteur ajouté à l'un et oublié dans l'autre aurait été
        # établi sans stabilisation, ou stabilisé sans retry, en silence.
        preventive = v in self._PREVENTIVE
        if v in (VEC_FIREWALL_DOWN_SPOOF, VEC_INSTANCE_DOWN_SPOOF, VEC_POSTGRES_DOWN_SPOOF):
            src = {
                VEC_FIREWALL_DOWN_SPOOF: ("FirewallDown", {"job": job}),
                VEC_INSTANCE_DOWN_SPOOF: ("InstanceDown", {"instance": instance, "job": job}),
                VEC_POSTGRES_DOWN_SPOOF: ("PostgreSQLDown", {"job": labels.get("job", "postgresql")}),
            }[v]
            self._post_alert(src[0], src[1])
            self._await_alert_active(src[0])            # confirmé enregistré actif dans AM
            trace.add(2, "inhibitor_alert_appeared", alertname=src[0])
        elif v == VEC_SILENCE_ABUSE:
            broad = bool(params.get("broad", False))
            # AM refuse un matcher qui matche la chaîne vide (garde-fou « tout silencer ») ;
            # ~.+ reste abusivement large (toute instance non vide) mais est accepté.
            matchers = {"instance": "~.+"} if broad else {"alertname": gt.expected_alert or "~.+", "job": job}
            self._post_silence(matchers, broad)
            self._await_silence_active()
        elif v == VEC_SILENCE_SHARED_LABEL:
            # silence par label PARTAGÉ (job) sans matcher alertname : balaie toute la
            # classe d'alertes du job sous couvert de maintenance de service.
            label = params.get("label", "job")
            value = params.get("value", job if label == "job" else instance)
            self._post_silence({label: value}, broad=False)
            self._await_silence_active()
        elif v == VEC_SILENCE_REGEX_ALERTNAME:
            # silence dont le matcher alertname est un regex (~.+) : matcher présent
            # mais non littéral, il balaie toutes les alertes de l'instance.
            self._post_silence({"alertname": "~.+", "instance": instance}, broad=False)
            self._await_silence_active()
        elif v == VEC_ROGUE_INHIBITOR:
            # T1562.001 : regle d'inhibition ROGUE (source non sanctionnee). On poste la source
            # RogueMuter (job=firewall) ; la regle baked dans alertmanager.yml (RogueMuter ->
            # classe securite, equal job) inhibe alors HighAttackRate quand elle fire. Preventif :
            # la source doit etre active AVANT que l'alerte cible fire.
            self._post_alert("RogueMuter", {"job": job})
            self._await_alert_active("RogueMuter")
            trace.add(2, "rogue_inhibit_rule", source="RogueMuter")
        elif v == VEC_GUARD_OUTAGE_COVER:
            # T1562.001 : panne RÉELLE du garde, établie AVANT l'attaque. On coupe fw_up :
            # le firewall est hors service pour de bon : et la règle FirewallDown
            # (`fw_up == 0`, for: 6s) fire D'ELLE-MÊME : rien n'est posté à l'API AM, rien
            # n'est ajouté à la config. La chaîne est prise TELLE QU'ELLE EST, et c'est ce
            # qui fait de ce vecteur un vrai trou plutôt qu'un artifice : l'inhibition
            # sanctionnée `FirewallDown -> classe sécurité` (equal: job) étouffera
            # HighAttackRate quand l'attaque suivra. Préventif par nature, pas par
            # commodité de test : l'ordre « garde d'abord, attaque ensuite » EST la manœuvre.
            self._set_metric("fw_up", {"job": job}, 0.0)
            self._await_alert_active("FirewallDown", timeout=25.0)
            trace.add(0, "guard_disabled", signal="fw_up", job=job)
        elif v == VEC_INHIBITION_SCOPE_CREEP:
            # T1562.001 : la regle d'inhibition dont `equal` a ete RETIRE est baked dans
            # alertmanager.yml, et reste INERTE tant qu'aucune InstanceDown sur stg-9
            # n'existe. On fait tomber POUR DE BON l'instance de recette anodine
            # (inst_up{stg-9}=0) : la vraie regle InstanceDown fire d'elle-meme, source
            # reelle et sanctionnee : et la regle non bornee etouffe alors la classe
            # securite de fw-1, sans aucun rapport. Preventif : l'inhibition doit etre
            # active avant que la cible fire.
            self._set_metric("inst_up", {"job": params.get("decoy_job", "staging"),
                                         "instance": params.get("decoy_instance", "stg-9")}, 0.0)
            self._await_alert_active("InstanceDown", timeout=25.0)
            trace.add(0, "decoy_instance_down", instance=params.get("decoy_instance", "stg-9"))
        elif v == VEC_PRELOADED_SILENCE:
            # T1562.001 : silence PRE-POSITIONNE. Etroit, `alertname` litteral, perimetre
            # irreprochable : au moment de sa pose il est indiscernable d'une maintenance
            # planifiee, et aucune activite ne l'entoure. C'est le DECALAGE dans le temps
            # entre la pose et l'usage qui fait le masquage : l'attaque ne vient qu'ensuite,
            # dans la fenetre ainsi ouverte. Preventif par nature (le silence doit etre actif
            # avant que l'alerte cible fire), comme les autres suppressions preventives.
            self._post_silence({"alertname": gt.expected_alert or "HighAttackRate", "job": job},
                               broad=False)
            self._await_silence_active()
            # FIDELITE (constat du smoke round 13) : sans cette ligne, docker rattrapait le
            # vecteur par `silence_abuse` au lieu de `silenced_under_threat`. Motif : `_snapshot`
            # rapporte TOUT silence avec `created_tick=0`, et la serie `attack_rate` ne COMMENCE
            # qu'au moment ou `_fire_event` la pose : deja a 120. La fenetre inspectee autour de
            # la creation ne contenait donc que des valeurs hautes, et le silence paraissait pose
            # « pendant une montee d'activite ». Le DECALAGE temporel, qui est tout le vecteur,
            # n'etait pas represente. On pose donc explicitement le trafic de fond calme qui
            # regne au moment de la pose, comme le fait la cible sim.
            self._set_metric(expected_signal or "attack_rate",
                             labels or {"job": job, "instance": instance},
                             float(params.get("calm", 3.0)))
            trace.add(0, "silence_preloaded", alertname=gt.expected_alert)

        if preventive:
            # stabilisation ample (> 2× group_interval de 5 s) : laisse AM indexer le
            # masquage : en particulier les silences à matcher REGEX (~.+), plus lents à
            # indexer que les matchers exacts : avant que l'alerte cible fire.
            time.sleep(STEP * 6)
        _fire_event()              # l'événement APRÈS l'établissement du masquage préventif

        # === Masquages NON préventifs (basés métrique / post-événement) ===
        if v == VEC_LOW_AND_SLOW:
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
        elif v == VEC_SELECTIVE_METRIC_DROP:
            # signal d'attaque bref PUIS retiré, mais l'instance reste UP (inst_up=1) :
            # aucune InstanceDown ne trahit la panne -> plus furtif que exporter_cutoff.
            sig = expected_signal or "attack_rate"
            lset = labels or {"job": job, "instance": instance}
            self._set_metric("inst_up", {"job": job, "instance": instance}, 1.0)
            self._set_metric(sig, lset, expected_thr + 80.0)
            time.sleep(STEP * 2)          # activité visible, < for: (6 s) -> ne fire pas
            self._del_metric(sig, lset)    # le signal disparaît, inst_up reste 1
            trace.add(2, "signal_blackout", instance=instance)
        elif v == VEC_FALSE_RESOLVED:
            # T1562.011 Spoof Security Alerting : faux « all-clear » via l'API AM. La
            # menace est réelle : la métrique est (re)montée au-dessus du seuil ;
            # l'attaquant POST un resolved (endsAt dans le passé) pour l'alerte de sécurité.
            #   ⚠️ Fidélité : contrairement au sim (état figé -> masque), un VRAI Prometheus
            #   ré-affirme l'alerte au cycle d'évaluation suivant (endsAt futur). Le faux
            #   resolved NE TIENT donc PAS : l'alarme ressort en docker (masked=False,
            #   déterministe). Écart assumé et mesuré (constat de fidélité 4) ; le vecteur
            #   est classé TIMING_SENSITIVE (pas STRONG_MASK) pour cette raison.
            sig = expected_signal or "attack_rate"
            lset = labels or {"job": job, "instance": instance}
            self._set_metric(sig, lset, expected_thr + 70.0)
            time.sleep(STEP * 4)          # laisser la règle fire (for:) et notifier
            now = time.time()
            _http(f"{AM}/api/v2/alerts", "POST",
                  [{"labels": {"alertname": gt.expected_alert, **lset},
                    "startsAt": _iso(now - 600), "endsAt": _iso(now)}])  # faux resolved
            trace.add(2, "am_force_resolved", alert=gt.expected_alert)
        elif v == VEC_STALE_REPLAY:
            # ACSAC 2022 concealment (rejeu/gel) : l'attaque franchit brièvement le seuil,
            # puis l'attaquant fige la métrique a un palier intermediaire (sous le seuil)
            # au lieu de la retirer. Metrique presente et plausible -> plus furtif qu'un
            # trou. Rattrapage docker non garanti (visibilite du pic bref) -> TIMING_SENSITIVE.
            sig = expected_signal or "attack_rate"
            lset = labels or {"job": job, "instance": instance}
            self._set_metric(sig, lset, float(params.get("spike", expected_thr + 30.0)))
            time.sleep(STEP * 2)          # franchissement visible mais bref (< for: 6 s)
            self._set_metric(sig, lset, float(params.get("frozen", 20.0)))  # fige au palier
            settle = STEP * 8             # assez de points figes pour la queue constante
            trace.add(2, "stale_replay_injected")
        elif v == VEC_STATISTICAL_REPLAY:
            # full/distribution-preserving replay : signal bruite sous le seuil (distribution
            # normale preservee). Indetectable par la baseline marginale -> residuel.
            sig = expected_signal or "attack_rate"
            lset = labels or {"job": job, "instance": instance}
            mean = float(params.get("mean", 21.0))
            for dev in _NOISE:
                self._set_metric(sig, lset, max(0.0, mean + dev))
                time.sleep(STEP)          # chaque point bruite est scrape
            settle = STEP * 2
            trace.add(0, "statistical_replay_injected")
        elif v == VEC_CONSTRAINED_REPLAY:
            # ACSAC 2022 constrained replay : attack_rate rejoue bas (masque), blocked_rate
            # NON masque (attaque bloquee, reste eleve) -> incoherence spatiale detectable.
            sig = expected_signal or "attack_rate"
            lset = labels or {"job": job, "instance": instance}
            attack_lo = float(params.get("attack", 20.0))
            blocked_hi = float(params.get("blocked", 80.0))
            self._set_metric("blocked_rate", lset, blocked_hi)
            for dev in _NOISE:
                self._set_metric(sig, lset, max(0.0, attack_lo + dev))
                time.sleep(STEP)
            settle = STEP * 2
            trace.add(0, "constrained_replay_injected")
        elif v == VEC_ROUTE_BLACKHOLE:
            # T1562.006 Indicator Blocking. L'alerte de sécurité fire (menace réelle,
            # signal soutenu au-dessus du seuil) mais l'attaquant a reroutré sa classe
            # d'alertes vers un récepteur « trou noir » : le firing porte le label de
            # routage `route_target=blackhole` -> AM l'envoie au receiver `blackhole`
            # (sans webhook), la notification n'atteint JAMAIS le sink -> masquée, SANS
            # silence ni inhibiteur. Déterministe : le routage ne dépend pas du timing (le
            # récepteur trou-noir est baked dans alertmanager.yml, actif dès le démarrage).
            sig = expected_signal or "attack_rate"
            lset = dict(labels or {"job": job, "instance": instance})
            lset[_BLACKHOLE_LABEL[0]] = _BLACKHOLE_LABEL[1]
            self._set_metric(sig, lset, expected_thr + max(70.0, expected_thr))
            settle = STEP * 8          # laisser l'alerte firer (for: 6s) et rester active
            trace.add(2, "route_blackholed", alert=gt.expected_alert, receiver="blackhole")
        elif v == VEC_WATCHDOG_SUPPRESSION:
            # T1562 Impair Defenses : l'attaquant desactive la chaine d'alerte et aveugle
            # le signal d'attaque -> rien de la menace n'est observable (aucune alerte,
            # aucune metrique d'attaque). Seul tell : le heartbeat watchdog s'eteint. On
            # met watchdog a 0 (chaine morte) ; l'alarme attendue n'est jamais firee ni
            # livree (masquee). Seul watchdog_gap la rattrape. Deterministe (watchdog=0 tenu).
            self._set_metric("watchdog", {}, 0.0)
            settle = STEP * 8          # assez de scrapes a 0 pour la queue silencieuse
            trace.add(0, "watchdog_silent", reason="alerting_pipeline_down")
        elif v == VEC_CARDINALITY_FLOOD:
            # MITRE Impair Defenses via epuisement de ressources (bombe de cardinalite).
            # Le scrape depasse sample_limit -> up=0 (comme une panne) et le vrai signal
            # n'est pas ingere ; scrape_samples explose (le tell). Modele : on met
            # scrape_samples tres haut et inst_up=0 (scrape rejete), sans firer l'attaque.
            # Seul cardinality_flood rattrape ; l'alarme attendue n'est jamais livree (masquee).
            self._set_metric("scrape_samples", {}, float(params.get("samples", 50000.0)))
            self._set_metric("inst_up", {"job": job, "instance": instance}, 0.0)
            settle = STEP * 8          # laisser InstanceDown firer + scraper le pic de cardinalite
            trace.add(0, "cardinality_flood", scrape_samples=params.get("samples", 50000.0))
        elif v == VEC_GUARD_OUTAGE_COVER:
            # la panne du garde est déjà établie (bloc préventif) et l'attaque vient d'être
            # posée par `_fire_event`. Il faut assez de scrapes APRÈS le fire pour que la
            # menace soit SOUTENUE au-dessus du seuil dans la fenêtre récente : c'est la
            # corroboration qu'exige `guard_down_under_threat`, sans laquelle le rattrapage
            # serait impossible alors même que le masquage a réussi.
            settle = STEP * 8
        elif v == VEC_INHIBITION_SCOPE_CREEP:
            # meme raison qu'au vecteur precedent : la menace doit etre SOUTENUE au-dessus du
            # seuil dans la fenetre recente pour que le rattrapage soit possible.
            settle = STEP * 8
        elif v == VEC_PRELOADED_SILENCE:
            # la menace doit etre SOUTENUE au-dessus du seuil dans la fenetre recente pour que
            # `silenced_under_threat` puisse la corroborer : assez de scrapes apres le fire.
            settle = STEP * 8
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
            elif bk == "benign_signal_gap":
                # signal exporté à bas régime PUIS retiré, en période calme (pas
                # d'activité élevée avant) : vrai négatif du blackout sélectif.
                self._set_metric("inst_up", {"job": job, "instance": instance}, 1.0)
                self._set_metric("attack_rate", {"job": job, "instance": instance},
                                 float(params.get("low", 8.0)))
                time.sleep(STEP * 2)
                self._del_metric("attack_rate", {"job": job, "instance": instance})
            elif bk == "benign_resolve":
                # all-clear LÉGITIME (pendant sain de false_resolved) : la métrique
                # franchit le seuil (l'alerte fire et notifie), PUIS retombe RÉELLEMENT
                # et durablement sous le seuil -> resolved légitime. La décantation
                # longue laisse Prometheus résoudre l'alerte et remplit la fenêtre
                # récente de valeurs basses : phantom_clear ne doit pas crier. Vrai négatif.
                self._set_metric("attack_rate", {"job": job, "instance": instance},
                                 float(params.get("high", model.ATTACK_RATE_THRESHOLD + 70.0)))
                time.sleep(STEP * 4)   # l'alerte fire et se notifie une 1re fois
                self._set_metric("attack_rate", {"job": job, "instance": instance},
                                 float(params.get("low", 8.0)))   # retombe durablement
                settle = STEP * 10     # laisser résoudre + la fenêtre récente devenir basse
            elif bk == "benign_settle":
                # activite licite elevee mais SOUS le seuil, puis palier : jamais de
                # franchissement -> frozen_replay ne doit pas crier. Vrai negatif de stale_replay.
                self._set_metric("attack_rate", {"job": job, "instance": instance},
                                 float(params.get("high", 40.0)))
                time.sleep(STEP * 2)
                self._set_metric("attack_rate", {"job": job, "instance": instance},
                                 float(params.get("frozen", 20.0)))
                settle = STEP * 8      # assez de points figes pour eprouver frozen_replay (doit rester muet)
            elif bk == "benign_noise":
                # trafic licite bruite sous le seuil (meme allure qu'une attaque diluee) :
                # la baseline ne doit pas le flaguer. Vrai negatif.
                mean = float(params.get("mean", 16.0))
                for dev in _NOISE:
                    self._set_metric("attack_rate", {"job": job, "instance": instance},
                                     max(0.0, mean + dev))
                    time.sleep(STEP)
                settle = STEP * 2
            elif bk == "benign_correlated":
                # attack_rate et blocked_rate coherents (correles, bas) : pas d'incoherence
                # spatiale -> spatial_incoherence doit rester muet. Vrai negatif.
                lvl = float(params.get("level", 18.0))
                self._set_metric("blocked_rate", {"job": job, "instance": instance}, lvl)
                for dev in _NOISE:
                    self._set_metric("attack_rate", {"job": job, "instance": instance},
                                     max(0.0, lvl + dev))
                    time.sleep(STEP)
                settle = STEP * 2
            elif bk == "benign_route_mute":
                # maintenance legitime : PostgreSQLHighConnections (NON-securite) routee vers
                # le trou noir pendant une maintenance de la base. Reellement non delivree
                # mais pas une menace de securite -> notification_blackhole doit rester muet
                # (garde de classe securite). Vrai negatif de route_blackhole.
                self._set_metric("pg_conns",
                                 {"job": "postgresql", "instance": instance,
                                  _BLACKHOLE_LABEL[0]: _BLACKHOLE_LABEL[1]},
                                 float(params.get("pg_conns", model.PG_CONN_THRESHOLD + 60.0)))
                settle = STEP * 8
            elif bk == "benign_watchdog_blip":
                # rate TRANSITOIRE du heartbeat watchdog qui se retablit : chaine saine.
                # On coupe brievement (0) puis on retablit (1) -> la queue de la fenetre
                # est a 1 -> watchdog_gap doit rester muet (exige un silence SOUTENU).
                # Vrai negatif du dead man's switch (anti alert-fatigue sur jitter de scrape).
                self._set_metric("watchdog", {}, 0.0)
                time.sleep(STEP * 2)       # bref (< WATCHDOG_MIN_SILENCE scrapes)
                self._set_metric("watchdog", {}, 1.0)   # retabli, tient jusqu'a la fin
                settle = STEP * 6          # la queue redevient 1 -> pas de silence soutenu
            elif bk == "benign_cardinality_bump":
                # croissance de cardinalite LEGITIME (deploiement) : scrape_samples monte
                # modestement mais reste sous sample_limit, up reste 1. cardinality_flood
                # ne doit PAS crier (seuil loin au-dessus). Vrai negatif de la bombe.
                self._set_metric("scrape_samples", {}, float(params.get("samples", 400.0)))
                settle = STEP * 4
            elif bk == "benign_maintenance_inhibition":
                # inhibition de MAINTENANCE legitime : source NON sanctionnee (DBMaintenance) inhibe
                # une alerte OPERATIONNELLE (PostgreSQLHighConnections) pendant une maintenance. Une
                # source non sanctionnee n'est rogue que si elle etouffe une alerte de SECURITE.
                # rogue_inhibitor doit rester muet (cible non-securite). La regle DBMaintenance ->
                # PostgreSQL.* est baked dans alertmanager.yml (inerte sans DBMaintenance). Preventif :
                # poser la source avant que la cible fire.
                self._post_alert("DBMaintenance", {"job": "postgresql"})
                self._await_alert_active("DBMaintenance")
                time.sleep(STEP * 6)
                self._set_metric("pg_conns", {"job": "postgresql", "instance": instance},
                                 float(params.get("pg_conns", model.PG_CONN_THRESHOLD + 60.0)))
                settle = STEP * 8   # laisser PostgreSQLHighConnections firer et l'inhibition maintenance s'appliquer
            elif bk == "benign_guard_maintenance":
                # maintenance PLANIFIÉE : le firewall est réellement arrêté (fw_up=0), donc la
                # règle FirewallDown fire légitimement et inhibe la classe sécurité : panne
                # IDENTIQUE à celle de guard_outage_cover. Mais AUCUNE menace ne court :
                # `guard_down_under_threat` doit rester muet (son discriminant est la
                # concomitance d'une menace réelle, pas la panne elle-même) et
                # `exporter_cutoff` aussi (aucune activité avant le trou). Vrai négatif :
                # sans ce garde, toute maintenance de firewall serait criée comme masquage.
                self._set_metric("fw_up", {"job": job}, 0.0)
                settle = STEP * 8
            elif bk == "benign_scoped_inhibition":
                # inhibition NOMINALE bornee : pg-1 tombe reellement (inst_up=0 -> InstanceDown)
                # et inhibe PostgreSQLHighConnections sur la MEME instance (equal: instance,
                # pg-1 des deux cotes). Aucune frontiere franchie -> inhibition_scope_creep
                # doit rester muet, inhibitor_isolation aussi (panne corroboree). Vrai negatif.
                self._set_metric("inst_up", {"job": job, "instance": instance}, 0.0)
                self._set_metric("pg_conns", {"job": job, "instance": instance},
                                 float(params.get("pg_conns", model.PG_CONN_THRESHOLD + 60.0)))
                settle = STEP * 8
            elif bk == "benign_maintenance_silence_op":
                # maintenance de base planifiee : silence etroit et exactement cible sur
                # PostgreSQLHighConnections pendant que les connexions sont REELLEMENT elevees.
                # Meme effet observable que preloaded_silence (une alerte justifiee etouffee),
                # ne differant QUE par la classe de la cible -> silenced_under_threat doit
                # rester muet. Vrai negatif : sans le garde de classe, toute maintenance serait
                # criee comme masquage.
                self._post_silence({"alertname": "PostgreSQLHighConnections", "job": job}, broad=False)
                self._await_silence_active()
                self._set_metric("pg_conns", {"job": job, "instance": instance},
                                 float(params.get("pg_conns", model.PG_CONN_THRESHOLD + 60.0)))
                settle = STEP * 8

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
                                       "inhibited_by": a.inhibited_by, "silenced_by": a.silenced_by,
                                       "route_muted": a.route_muted}
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
            # route_muted : l'alerte porte le label de routage qui l'envoie au récepteur
            # trou-noir -> sa notification est avalée (résolution de la route observée, ce
            # qu'une plateforme d'observabilité lit dans la config AM). On retire le label
            # des labels rapportés pour rester aligné avec la cible sim.
            route_muted = lbls.pop(_BLACKHOLE_LABEL[0], None) == _BLACKHOLE_LABEL[1]
            st = a.get("status", {})
            alerts.append(Alert(
                name=name, labels=lbls,
                inhibited_by=[fp_to_name.get(fp, fp) for fp in st.get("inhibitedBy", [])],
                silenced_by=list(st.get("silencedBy", [])),
                route_muted=route_muted,
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
        end = time.time()   # fenêtre [début du scénario ; maintenant] : pas de bleed
        out: dict[str, list[Optional[float]]] = {}
        for metric in ("attack_rate", "jailbreak_rate", "critical_attacks", "pg_conns",
                       "inst_up", "fw_up", "pg_up", "blocked_rate", "watchdog", "scrape_samples"):
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
