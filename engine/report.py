"""Sourdine — format de sortie versionné (JSON machine + résumé lisible)."""
from __future__ import annotations

import json
from typing import Optional

from engine.types import ScenarioResult

REPORT_FORMAT_VERSION = "1.0"


def build_report(results: list[ScenarioResult], aggregate: dict, *,
                 target_name: str, detector_name: str, bench_version: str,
                 generated_at: str) -> dict:
    return {
        "sourdine_report_version": REPORT_FORMAT_VERSION,
        "bench_version": bench_version,
        "generated_at": generated_at,
        "target_backend": target_name,
        "detector": detector_name,
        "note": ("Le banc évalue une baseline, PAS le produit SentinelleIA. "
                 "Aucun résultat n'est celui de SentinelleIA tant que le vrai "
                 "détecteur n'est pas branché derrière la même interface."),
        "aggregate": aggregate,
        "scenarios": [r.to_dict() for r in results],
    }


def write_report(report: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
        f.write("\n")


def _pct(x: Optional[float]) -> str:
    return "   n/a" if x is None else f"{x * 100:5.1f}%"


def human_summary(report: dict) -> str:
    a = report["aggregate"]
    lines = []
    lines.append("=" * 74)
    lines.append(f"  SOURDINE — banc de masquage d'alarme   (format v{report['sourdine_report_version']})")
    lines.append(f"  cible={report['target_backend']}   détecteur={report['detector']}"
                 f"   scénarios={a['n_scenarios']} ({a['n_attaques']} attaques / {a['n_sains']} sains)")
    lines.append("=" * 74)
    lines.append("  Taux                         valeur   sous-ensemble / preuve")
    lines.append("  " + "-" * 70)
    lines.append(f"  Suppression réussie         {_pct(a['taux_suppression_reussie'])}   attaques sans détecteur — danger client")
    lines.append(f"  Rattrapage                  {_pct(a['taux_rattrapage'])}   parmi masquées — valeur produit")
    lines.append(f"  Faux positifs               {_pct(a['taux_faux_positifs'])}   scénarios sains — coût opérationnel")
    lines.append(f"  Suppression résiduelle      {_pct(a['taux_suppression_residuelle'])}   attaques non rattrapées — honnêteté")
    lines.append(f"  Contrôle de cohérence       {_pct(a['controle_coherence'])}   cas graves sains — doit approcher 100%")
    lines.append("")
    lines.append("  Ventilation par niveau d'accès attaquant (attaques)")
    lines.append("  " + "-" * 70)
    lines.append(f"  {'niveau':<26}{'n':>3}  {'suppr.':>7} {'rattr.':>7} {'résid.':>7}")
    for lvl, m in a["par_niveau_acces"].items():
        lines.append(f"  {lvl:<26}{m['n_attaques']:>3}  {_pct(m['taux_suppression_reussie'])} "
                     f"{_pct(m['taux_rattrapage'])} {_pct(m['taux_suppression_residuelle'])}")
    lines.append("")
    lines.append("  Détail par scénario")
    lines.append("  " + "-" * 70)
    lines.append(f"  {'id':<34}{'masquée':>8}{'rattrap.':>9}")
    for s in report["scenarios"]:
        masked = "oui" if s["raw_result"]["masked"] else "—"
        flagged = s["detector_verdict"]["masking_suspected"]
        if s["kind"] == "healthy":
            catch = "FP" if flagged else "ok"          # sain : flaguer = faux positif
        else:
            catch = "oui" if flagged else "NON"        # attaque : flaguer = rattrapage
        lines.append(f"  {s['id']:<34}{masked:>8}{catch:>9}")
    lines.append("=" * 74)
    return "\n".join(lines)
