"""Non-régression du run sim.

Garde-fou : le backend sim (déterministe, hermétique) doit reproduire l'échantillon
gelé `samples/example-0.1.0.json`. Tant que ce test est vert, les taux publiés du
run de référence n'ont pas bougé sous l'effet d'une modification du moteur, du
modèle sémantique, du détecteur baseline ou du jeu de scénarios.

Ce que le test compare (le comportement) :
  - l'agrégat (les 4 taux + cohérence + ventilation) ;
  - chaque scénario (vérité terrain, résultat brut passe 1, verdict détecteur passe 2) ;
  - l'identité productrice (cible + détecteur) dont dépendent les chiffres.
Ce qu'il ignore : les horodatages (`generated_at`, `timestamp`), volatils par nature.

Si un changement de comportement est VOULU, re-geler l'échantillon d'un geste
délibéré : `make regen-sample` (puis relire le diff). Aucune dépendance tierce :
stdlib `unittest` uniquement.
"""
from __future__ import annotations

import json
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)  # sourdine/
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from engine.report import REPORT_FORMAT_VERSION  # noqa: E402
from engine.scenarios import load_scenarios       # noqa: E402
from run_campaign import build_report             # noqa: E402

SAMPLE = os.path.join(_ROOT, "samples", "example-0.3.0.json")
SCENARIOS = os.path.join(_ROOT, "scenarios")


def _strip_timestamps(report: dict) -> dict:
    """Retire les champs d'horodatage volatils, seuls écarts légitimes entre 2 runs."""
    r = dict(report)
    r.pop("generated_at", None)
    r["scenarios"] = [{k: v for k, v in s.items() if k != "timestamp"}
                      for s in r.get("scenarios", [])]
    return r


def _version_file() -> str:
    with open(os.path.join(_ROOT, "VERSION"), encoding="utf-8") as f:
        return f.read().strip()


class SimRegression(unittest.TestCase):
    """Le run sim reproduit-il l'échantillon gelé ?"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = build_report(backend="sim", scenarios_root=SCENARIOS)
        with open(SAMPLE, encoding="utf-8") as f:
            cls.sample = json.load(f)

    def setUp(self) -> None:
        self.maxDiff = None  # diffs complets en cas d'échec

    def test_producer_identity(self) -> None:
        # les taux ne valent que pour CE couple (cible, détecteur) : le figer aussi.
        self.assertEqual(self.report["target_backend"], self.sample["target_backend"])
        self.assertEqual(self.report["detector"], self.sample["detector"])

    def test_aggregate_matches_frozen_sample(self) -> None:
        self.assertEqual(
            self.report["aggregate"], self.sample["aggregate"],
            "l'agrégat (taux/cohérence/ventilation) diffère de l'échantillon gelé — "
            "régression, ou changement voulu à re-geler via `make regen-sample`.",
        )

    def test_each_scenario_matches_frozen_sample(self) -> None:
        got = {s["id"]: s for s in _strip_timestamps(self.report)["scenarios"]}
        ref = {s["id"]: s for s in _strip_timestamps(self.sample)["scenarios"]}
        self.assertEqual(set(got), set(ref),
                         "le jeu de scénarios diffère de l'échantillon (ajout/retrait ?).")
        for sid in sorted(ref):
            self.assertEqual(got[sid], ref[sid],
                             f"le scénario {sid} diffère de l'échantillon gelé.")

    def test_run_is_deterministic(self) -> None:
        again = build_report(backend="sim", scenarios_root=SCENARIOS)
        self.assertEqual(_strip_timestamps(again), _strip_timestamps(self.report),
                         "deux runs sim consécutifs divergent : la cible sim n'est plus déterministe.")

    def test_coherence_control_total(self) -> None:
        # garde-fou de la doc §6 (manuel admin) : une cible cassée fait chuter la cohérence.
        self.assertEqual(self.report["aggregate"]["controle_coherence"], 1.0,
                         "contrôle de cohérence < 100 % : la cible ne lève plus l'alarme attendue.")

    def test_scenario_count_matches_files(self) -> None:
        n_files = len(load_scenarios(SCENARIOS))
        self.assertEqual(self.report["aggregate"]["n_scenarios"], n_files,
                         "un fichier de scénario a été ignoré silencieusement.")

    def test_sample_metadata_in_sync(self) -> None:
        # un bump de VERSION ou de format sans re-geler l'échantillon = échantillon périmé.
        self.assertEqual(
            self.sample["sourdine_report_version"], REPORT_FORMAT_VERSION,
            "format de rapport changé : re-geler `samples/example-0.1.0.json` (make regen-sample).",
        )
        self.assertEqual(
            self.sample["bench_version"], _version_file(),
            "VERSION du banc changée : re-geler `samples/example-0.1.0.json` (make regen-sample).",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
