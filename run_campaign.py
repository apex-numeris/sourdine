#!/usr/bin/env python3
"""Sourdine — lancer une campagne du banc de masquage d'alarme.

Exemples :
    python run_campaign.py                      # cible sim (défaut), détecteur baseline
    python run_campaign.py --backend docker     # vraie cible éphémère (Prometheus+Alertmanager)
    python run_campaign.py --out reports/run.json

Périmètre : le banc monte sa PROPRE cible jetable. Il ne vise jamais
l'Alertmanager/Prometheus de production et ne modifie aucune config existante.

`build_report()` est la fabrique de rapport réutilisable (sans I/O ni impression) :
la CLI ci-dessous et le test de non-régression (`tests/test_sim_regression.py`)
l'appellent tous deux, pour que le test exerce EXACTEMENT le chemin de production.
"""
from __future__ import annotations

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # rendre le paquet `engine` importable en exécution directe

from engine import metrics as metrics_mod  # noqa: E402
from engine import report as report_mod     # noqa: E402
from engine.detector import BaselineDetector, MaskingDetector  # noqa: E402
from engine.runner import _now, run_campaign  # noqa: E402
from engine.scenarios import load_scenarios    # noqa: E402


def _bench_version() -> str:
    try:
        with open(os.path.join(HERE, "VERSION"), encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return "0.0.0"


def _make_target(backend: str):
    if backend == "sim":
        from engine.target_sim import SimTarget
        return SimTarget()
    if backend == "docker":
        from engine.target_docker import DockerTarget
        return DockerTarget()
    raise SystemExit(f"backend inconnu : {backend!r} (sim|docker)")


def build_report(backend: str = "sim", scenarios_root: str | None = None,
                 detector: MaskingDetector | None = None,
                 generated_at: str | None = None) -> dict:
    """Joue une campagne et renvoie le rapport (dict), sans écrire de fichier.

    C'est le point d'entrée programmatique unique : `main()` (CLI) et le test de
    non-régression s'appuient dessus, de sorte qu'aucun des deux ne reproduit
    l'orchestration de l'autre (sinon le test pourrait diverger du run réel).
    """
    scenarios = load_scenarios(scenarios_root or os.path.join(HERE, "scenarios"))
    detector = detector or BaselineDetector()
    target = _make_target(backend)
    try:
        target.setup()
        results = run_campaign(target, detector, scenarios)
    finally:
        target.teardown()
    aggregate = metrics_mod.compute_metrics(results)
    return report_mod.build_report(
        results, aggregate,
        target_name=target.name, detector_name=detector.name,
        bench_version=_bench_version(), generated_at=generated_at or _now(),
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Banc Sourdine — masquage d'alarme")
    p.add_argument("--backend", default="sim", choices=["sim", "docker"],
                   help="cible éphémère : sim (défaut, hermétique) ou docker (vrais conteneurs)")
    p.add_argument("--scenarios", default=os.path.join(HERE, "scenarios"),
                   help="racine du jeu de scénarios")
    p.add_argument("--out", default=None, help="chemin du rapport JSON (défaut: reports/report-<ts>.json)")
    p.add_argument("--quiet", action="store_true", help="ne pas imprimer le résumé lisible")
    args = p.parse_args(argv)

    report = build_report(backend=args.backend, scenarios_root=args.scenarios)

    reports_dir = os.path.join(HERE, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    out = args.out or os.path.join(
        reports_dir, f"report-{report['generated_at'].replace(':', '').replace('-', '')}.json")
    report_mod.write_report(report, out)
    report_mod.write_report(report, os.path.join(reports_dir, "latest.json"))

    if not args.quiet:
        print(report_mod.human_summary(report))
        print(f"\nRapport JSON : {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
