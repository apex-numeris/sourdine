"""Non-régression du backend docker (fidélité : vrais Prometheus + Alertmanager).

Contrairement au sim (déterministe → égalité stricte, cf. `test_sim_regression`),
le backend docker dépend du temps réel (scrape, `group_wait`, décantation). Les
vecteurs à fenêtre longue (`low_and_slow`, `grouping_repeat_abuse`) peuvent donc
varier d'un run à l'autre. Une égalité stricte serait *flaky* et donc désactivée
tôt ou tard — ici on garde plutôt :

  - des INVARIANTS DURS, vrais quel que soit le timing (cohérence à 100 %, les
    masqueurs déterministes toujours masqués+rattrapés, contrôles de cohérence
    jamais signalés, comptes de scénarios) ;
  - des garde-fous DIRECTIONNELS à tolérance autour de l'échantillon docker gelé
    (doc 07 §6 : plancher de rattrapage, plancher de suppression, plafond de FP).

Deux classes :
  - `DockerCheckLogic`      — RAPIDE, sans docker : valide la logique de contrôle
    ET l'échantillon gelé, et prouve PAR MUTATION que les contrôles savent
    échouer. Tourne dans `make test`.
  - `DockerLiveRegression`  — lance une VRAIE campagne docker (~6-8 min) puis lui
    applique les mêmes contrôles. Opt-in : `SOURDINE_DOCKER_TEST=1` + docker
    disponible. Tourne via `make test-docker`.

Stdlib uniquement (`unittest`, `subprocess`, `shutil`, `copy`).
"""
from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)  # sourdine/
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from engine.detector import BaselineDetector  # noqa: E402
from engine.scenarios import load_scenarios    # noqa: E402
from run_campaign import build_report          # noqa: E402

SAMPLE_DOCKER = os.path.join(_ROOT, "samples", "example-0.11.0-docker.json")
SCENARIOS = os.path.join(_ROOT, "scenarios")

BASELINE_NAME = BaselineDetector.name

# Masqueurs déterministes : leur mécanisme (inhibition, silence large, coupure)
# ne dépend pas de la fenêtre temporelle → doivent TOUJOURS masquer ET être rattrapés.
STRONG_MASK_VECTORS = {
    "firewall_down_spoof", "instance_down_spoof", "postgres_down_spoof",
    "exporter_cutoff", "silence_abuse", "silence_shared_label",
    "silence_regex_alertname", "route_blackhole", "watchdog_suppression",
    "cardinality_flood", "rogue_inhibitor",
}
# Vecteurs dont le RATTRAPAGE ou même le MASQUAGE peut varier ou différer en docker —
# fenêtre longue, ou écart de fidélité sim/docker. `selective_metric_drop` : un vrai
# Prometheus représente une métrique supprimée par une série qui s'arrête (pas par des
# trous None), donc le détecteur de gap le voit en sim mais le rate en docker.
# `false_resolved` : le faux resolved posté à l'API AM masque en sim (état figé), mais
# une vraie règle Prometheus ré-affirme l'alerte au cycle suivant en docker (l'alarme
# ressort) — donc ni masqué ni rattrapé garanti en docker. Écarts assumés et mesurés.
TIMING_SENSITIVE_VECTORS = {"low_and_slow", "grouping_repeat_abuse",
                            "threshold_flapping", "selective_metric_drop",
                            "false_resolved", "stale_replay", "constrained_replay"}

TOL = 0.15  # tolérance directionnelle (~1 scénario sur 8) autour de l'échantillon gelé


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def invariant_problems(report: dict) -> list[str]:
    """Renvoie la liste des invariants durs violés (vide = OK). Indépendant du timing."""
    p: list[str] = []
    agg = report.get("aggregate", {})

    if report.get("target_backend") != "docker":
        p.append(f"target_backend = {report.get('target_backend')!r}, attendu 'docker'")
    if report.get("detector") != BASELINE_NAME:
        p.append(f"detector = {report.get('detector')!r}, attendu {BASELINE_NAME!r}")
    if (agg.get("n_scenarios"), agg.get("n_attaques"), agg.get("n_sains")) != (41, 23, 18):
        p.append(f"comptes = {agg.get('n_scenarios')}/{agg.get('n_attaques')}/{agg.get('n_sains')}, "
                 f"attendu 41/23/18")
    if agg.get("controle_coherence") != 1.0:
        p.append(f"controle_coherence = {agg.get('controle_coherence')}, attendu 1.0 (cible cassée ?)")

    for s in report.get("scenarios", []):
        vec = s.get("vector")
        masked = s.get("raw_result", {}).get("masked")
        flagged = s.get("detector_verdict", {}).get("masking_suspected")
        if vec in STRONG_MASK_VECTORS:
            if not masked:
                p.append(f"{s.get('id')} ({vec}) : masqueur déterministe NON masqué")
            if not flagged:
                p.append(f"{s.get('id')} ({vec}) : masqueur déterministe NON rattrapé")
        if s.get("coherence_control") and flagged:
            p.append(f"{s.get('id')} (contrôle de cohérence) signalé masquage à tort")
    return p


def tolerance_problems(report: dict, sample: dict, tol: float = TOL) -> list[str]:
    """Garde-fous directionnels autour de l'échantillon gelé (vide = OK)."""
    p: list[str] = []
    a, b = report.get("aggregate", {}), sample.get("aggregate", {})
    if a.get("taux_suppression_reussie", 0.0) < b["taux_suppression_reussie"] - tol:
        p.append(f"suppression {a.get('taux_suppression_reussie'):.3f} < "
                 f"{b['taux_suppression_reussie']:.3f} - {tol} (la cible masque moins)")
    if a.get("taux_rattrapage", 0.0) < b["taux_rattrapage"] - tol:
        p.append(f"rattrapage {a.get('taux_rattrapage'):.3f} < "
                 f"{b['taux_rattrapage']:.3f} - {tol} (régression détecteur)")
    if a.get("taux_faux_positifs", 1.0) > b["taux_faux_positifs"] + tol:
        p.append(f"faux positifs {a.get('taux_faux_positifs'):.3f} > "
                 f"{b['taux_faux_positifs']:.3f} + {tol} (plafond FP dépassé)")
    return p


class DockerCheckLogic(unittest.TestCase):
    """Rapide, sans docker : la logique de contrôle + l'échantillon gelé + mutation."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.sample = _load(SAMPLE_DOCKER)

    def setUp(self) -> None:
        self.maxDiff = None

    # -- l'échantillon docker gelé est lui-même conforme ----------------------
    def test_frozen_sample_satisfies_invariants(self) -> None:
        probs = invariant_problems(self.sample)
        self.assertEqual(probs, [], "l'échantillon docker gelé viole ses propres invariants :\n"
                         + "\n".join(probs))

    def test_frozen_sample_within_tolerance_of_itself(self) -> None:
        self.assertEqual(tolerance_problems(self.sample, self.sample), [])

    def test_frozen_sample_wellformed(self) -> None:
        a = self.sample["aggregate"]
        self.assertEqual((a["n_scenarios"], a["n_attaques"], a["n_sains"]), (41, 23, 18))
        self.assertEqual(self.sample["target_backend"], "docker")

    # -- preuve par mutation : les contrôles doivent SAVOIR échouer -----------
    def test_mutation_broken_coherence_is_caught(self) -> None:
        bad = copy.deepcopy(self.sample)
        bad["aggregate"]["controle_coherence"] = 0.5
        self.assertNotEqual(invariant_problems(bad), [], "cohérence cassée non détectée")

    def test_mutation_unmasked_deterministic_spoof_is_caught(self) -> None:
        bad = copy.deepcopy(self.sample)
        for s in bad["scenarios"]:
            if s["vector"] == "firewall_down_spoof":
                s["raw_result"]["masked"] = False
        self.assertNotEqual(invariant_problems(bad), [], "spoof déterministe non masqué non détecté")

    def test_mutation_coherence_control_flagged_is_caught(self) -> None:
        bad = copy.deepcopy(self.sample)
        for s in bad["scenarios"]:
            if s.get("coherence_control"):
                s["detector_verdict"]["masking_suspected"] = True
        self.assertNotEqual(invariant_problems(bad), [], "faux positif sur contrôle de cohérence non détecté")

    def test_mutation_rattrapage_drop_is_caught(self) -> None:
        bad = copy.deepcopy(self.sample)
        bad["aggregate"]["taux_rattrapage"] = bad["aggregate"]["taux_rattrapage"] - 0.5
        self.assertNotEqual(tolerance_problems(bad, self.sample), [], "chute de rattrapage non détectée")

    def test_mutation_fp_spike_is_caught(self) -> None:
        bad = copy.deepcopy(self.sample)
        bad["aggregate"]["taux_faux_positifs"] = bad["aggregate"]["taux_faux_positifs"] + 0.5
        self.assertNotEqual(tolerance_problems(bad, self.sample), [], "pic de faux positifs non détecté")


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        r = subprocess.run(["docker", "compose", "version"],
                           capture_output=True, timeout=15)
        return r.returncode == 0
    except Exception:
        return False


_OPT_IN = os.environ.get("SOURDINE_DOCKER_TEST") == "1"


@unittest.skipUnless(
    _OPT_IN and _docker_available(),
    "test docker opt-in : `make test-docker` (SOURDINE_DOCKER_TEST=1) sur un hôte avec docker",
)
class DockerLiveRegression(unittest.TestCase):
    """Lance une VRAIE campagne docker (~6-8 min) et lui applique les mêmes contrôles."""

    @classmethod
    def setUpClass(cls) -> None:
        # build_report garantit le teardown de la cible même en cas d'échec (try/finally).
        cls.report = build_report(backend="docker", scenarios_root=SCENARIOS)
        cls.sample = _load(SAMPLE_DOCKER)

    def setUp(self) -> None:
        self.maxDiff = None

    def test_invariants_hold(self) -> None:
        probs = invariant_problems(self.report)
        self.assertEqual(probs, [], "invariants docker violés :\n" + "\n".join(probs))

    def test_within_tolerance_of_frozen_sample(self) -> None:
        probs = tolerance_problems(self.report, self.sample)
        self.assertEqual(probs, [], "hors tolérance vs échantillon docker gelé :\n" + "\n".join(probs))

    def test_scenario_count_matches_files(self) -> None:
        self.assertEqual(self.report["aggregate"]["n_scenarios"], len(load_scenarios(SCENARIOS)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
