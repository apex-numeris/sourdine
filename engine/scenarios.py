"""Sourdine : chargeur du jeu de scénarios étiquetés.

Le jeu de scénarios est un artefact ouvert (JSON), séparé du code du runner, pour
pouvoir être publié et cité indépendamment. Un scénario décrit une INTENTION
haut-niveau ; l'interprétation concrète vit dans les cibles.
"""
from __future__ import annotations

import glob
import json
import os

from engine.types import GroundTruth, Scenario


def _parse(path: str) -> Scenario:
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    gt = d.get("ground_truth", {})
    return Scenario(
        id=d["id"],
        kind=d["kind"],
        vector=d["vector"],
        title=d.get("title", ""),
        description=d.get("description", ""),
        access_level=d.get("access_level", "n/a"),
        ground_truth=GroundTruth(
            alarm_expected=bool(gt.get("alarm_expected", False)),
            expected_alert=gt.get("expected_alert"),
            labels=gt.get("labels", {}) or {},
        ),
        event=d.get("event", {}) or {},
        masking=d.get("masking", {}) or {},
        coherence_control=bool(d.get("coherence_control", False)),
        tags=d.get("tags", []) or [],
    )


def load_scenarios(scenarios_root: str) -> list[Scenario]:
    paths: list[str] = []
    for sub in ("attacks", "healthy"):
        paths += glob.glob(os.path.join(scenarios_root, sub, "*.json"))
    scenarios = [_parse(p) for p in paths]
    scenarios.sort(key=lambda s: s.id)
    if not scenarios:
        raise SystemExit(f"Aucun scénario trouvé sous {scenarios_root}/(attacks|healthy)/*.json")
    return scenarios
