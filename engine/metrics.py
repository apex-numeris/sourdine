"""Sourdine : calcul des métriques.

Quatre taux + un contrôle de cohérence, plus la ventilation par niveau d'accès
attaquant. Rappel normatif (spec) : le statut de masquage se lit sur la passe
SANS détecteur ; ne jamais coter un scénario « non concerné » parce que la
protection l'a rattrapé.
"""
from __future__ import annotations

from typing import Optional

from engine.types import ScenarioResult


def _ratio(n: int, d: int) -> Optional[float]:
    return (n / d) if d else None


def compute_metrics(results: list[ScenarioResult]) -> dict:
    attacks = [r for r in results if r.scenario.is_attack]
    healthy = [r for r in results if not r.scenario.is_attack]
    masked = [r for r in attacks if r.masked]                 # masquage réussi (passe 1)
    coherence_set = [r for r in healthy if r.scenario.coherence_control]

    agg = {
        "n_scenarios": len(results),
        "n_attaques": len(attacks),
        "n_sains": len(healthy),
        "n_masquees": len(masked),
        # part des attaques où l'alarme attendue n'est pas levée (SANS détecteur)
        "taux_suppression_reussie": _ratio(len(masked), len(attacks)),
        # parmi les alarmes effectivement masquées, part que le détecteur signale
        "taux_rattrapage": _ratio(len([r for r in masked if r.flagged]), len(masked)),
        # part des scénarios sains où le détecteur crie au masquage à tort
        "taux_faux_positifs": _ratio(len([r for r in healthy if r.flagged]), len(healthy)),
        # part des attaques où le masquage passe inaperçu malgré le détecteur
        "taux_suppression_residuelle": _ratio(len([r for r in masked if not r.flagged]), len(attacks)),
        # part des cas graves sains où l'alarme sort bien (doit approcher 1.0)
        "controle_coherence": _ratio(len([r for r in coherence_set if r.raw.alarm_raised]), len(coherence_set)),
    }

    by_level: dict[str, list[ScenarioResult]] = {}
    for r in attacks:
        by_level.setdefault(r.scenario.access_level, []).append(r)
    ventilation = {}
    for lvl, rs in sorted(by_level.items()):
        m = [r for r in rs if r.masked]
        ventilation[lvl] = {
            "n_attaques": len(rs),
            "taux_suppression_reussie": _ratio(len(m), len(rs)),
            "taux_rattrapage": _ratio(len([r for r in m if r.flagged]), len(m)),
            "taux_suppression_residuelle": _ratio(len([r for r in m if not r.flagged]), len(rs)),
        }
    agg["par_niveau_acces"] = ventilation
    return agg
