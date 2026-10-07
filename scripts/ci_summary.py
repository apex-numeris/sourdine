#!/usr/bin/env python3
"""Sourdine : résumé lisible d'une campagne docker jouée en CI.

Écrit dans le résumé du run GitHub (GITHUB_STEP_SUMMARY) les agrégats comparés à
l'échantillon docker gelé, les contrôles en échec et les scénarios qui s'écartent de
l'échantillon, puis émet chaque contrôle en échec en annotation `::error::`. Le
diagnostic se lit ainsi sur la page du run, sans ouvrir les logs (que GitHub réserve
aux comptes connectés). Stdlib uniquement ; réutilise les contrôles exacts du test.

Usage : python3 scripts/ci_summary.py [reports/docker-ci.json]
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tests.test_docker_regression import (  # noqa: E402
    SAMPLE_DOCKER, _load, invariant_problems, tolerance_problems,
)

METRICS = ("taux_suppression_reussie", "taux_rattrapage", "taux_faux_positifs", "controle_coherence")


def _outcome(s: dict) -> tuple:
    return (s["raw_result"]["alarm_raised"], s["raw_result"]["masked"],
            s["detector_verdict"]["masking_suspected"])


def _fmt(o: tuple) -> str:
    return ", ".join(f"{k} {'oui' if v else 'non'}" for k, v in zip(("levée", "masquée", "signalée"), o))


def summarize(path: str) -> tuple[list[str], list[str]]:
    lines = ["## Sourdine : campagne docker", ""]
    if not os.path.exists(path):
        msg = "aucun rapport : la campagne s'est interrompue avant la fin (voir les logs)"
        return lines + [f"**{msg}**"], [msg]
    rep, ref = _load(path), _load(SAMPLE_DOCKER)
    a, b = rep["aggregate"], ref["aggregate"]
    lines += ["| Métrique | Ce run | Échantillon gelé |", "|---|---|---|"]
    lines += [f"| {k} | {a.get(k, float('nan')):.3f} | {b[k]:.3f} |" for k in METRICS]
    problems = invariant_problems(rep) + tolerance_problems(rep, ref)
    lines += ["", "**Contrôles en échec :**" if problems else "**Tous les contrôles passent.**"]
    lines += [f"- {p}" for p in problems]

    frozen = {s["id"]: s for s in ref["scenarios"]}
    diffs = [(s, frozen[s["id"]]) for s in sorted(rep["scenarios"], key=lambda x: x["id"])
             if s["id"] in frozen and _outcome(s) != _outcome(frozen[s["id"]])]
    lines += ["", f"**Scénarios qui s'écartent de l'échantillon gelé : {len(diffs)}**"]
    if diffs:
        lines += ["", "| Scénario | Vecteur | Ce run | Échantillon gelé |", "|---|---|---|---|"]
        for s, f in diffs:
            lines.append(f"| {s['id']} | {s['vector']} | {_fmt(_outcome(s))} | {_fmt(_outcome(f))} |")
    return lines, problems


def main(argv: list[str]) -> int:
    path = argv[1] if len(argv) > 1 else os.path.join("reports", "docker-ci.json")
    lines, problems = summarize(path)
    for p in problems:
        print(f"::error title=Sourdine docker::{p}")
    text = "\n".join(lines) + "\n"
    out = os.environ.get("GITHUB_STEP_SUMMARY")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.write(text)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
