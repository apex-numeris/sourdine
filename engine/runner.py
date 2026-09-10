"""Sourdine — moteur d'exécution des scénarios (deux passes).

Pour chaque scénario : la cible établit l'état, injecte l'événement qui doit lever
l'alarme, applique le vecteur de masquage, puis observe l'état des alertes SANS
détecteur (passe 1) ; ensuite l'état + la trace sont soumis au détecteur (passe 2).
Tout est consigné.
"""
from __future__ import annotations

from datetime import datetime, timezone

from engine.detector import MaskingDetector
from engine.target_base import Target
from engine.types import Scenario, ScenarioResult


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_campaign(target: Target, detector: MaskingDetector,
                 scenarios: list[Scenario]) -> list[ScenarioResult]:
    results: list[ScenarioResult] = []
    for sc in scenarios:
        raw, state, trace = target.execute(sc)      # passe 1 : observation sans détecteur
        verdict = detector.detect(state, trace)      # passe 2 : verdict du détecteur
        results.append(ScenarioResult(scenario=sc, raw=raw, verdict=verdict, timestamp=_now()))
    return results
