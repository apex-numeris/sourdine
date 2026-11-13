"""Sourdine : moteur d'exécution des scénarios (deux passes).

Pour chaque scénario : la cible établit l'état, injecte l'événement qui doit lever
l'alarme, applique le vecteur de masquage, puis observe l'état des alertes SANS
détecteur (passe 1) ; ensuite l'état et une trace OBSERVABLE sont soumis au détecteur
(passe 2). Tout est consigné.

Étanchéité de l'interface : la cible rend aussi un récit de la manœuvre (événements
nommés par le scénario : « rejeu injecté », « pic licite », etc.). Ce récit sert au
diagnostic et ne va JAMAIS au détecteur, qui le lirait comme un corrigé. Le détecteur
reçoit `observable_trace(state)` : une vue chronologique calculée à partir de l'état
seul, donc sans rien que la chaîne d'alerte ne montre déjà.
"""
from __future__ import annotations

from datetime import datetime, timezone

from engine.detector import MaskingDetector
from engine.target_base import Target
from engine.types import Scenario, ScenarioResult, SupervisionState, Trace

# Événements que la trace remise au détecteur peut porter, et leurs champs. Liste blanche :
# tout ajout doit rester une fonction de l'état observable (cf. tests/test_interface_leak.py).
OBSERVABLE_EVENTS = {"silence_created": ("matchers",)}


def observable_trace(state: SupervisionState) -> Trace:
    """Trace remise au détecteur : fonction PURE de l'état observable. Elle n'apporte
    aucune information que l'état ne contienne déjà (elle range les créations de silence
    dans l'ordre du temps) ; elle existe pour que l'interface `detect(state, trace)` reste
    stable et pour accueillir, plus tard, d'autres événements réellement observables."""
    trace = Trace()
    for sil in sorted(state.silences, key=lambda s: (s.created_tick, sorted(s.matchers.items()))):
        trace.add(sil.created_tick, "silence_created", matchers=dict(sil.matchers))
    return trace


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_campaign(target: Target, detector: MaskingDetector,
                 scenarios: list[Scenario]) -> list[ScenarioResult]:
    results: list[ScenarioResult] = []
    for sc in scenarios:
        raw, state, _narrative = target.execute(sc)                 # passe 1 : sans détecteur
        verdict = detector.detect(state, observable_trace(state))  # passe 2 : jamais le récit
        results.append(ScenarioResult(scenario=sc, raw=raw, verdict=verdict, timestamp=_now()))
    return results
