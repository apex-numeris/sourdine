"""Sourdine — détecteur de masquage (interface stable + baseline heuristique).

Le détecteur ne regarde PAS le contenu de l'attaque : il cherche le silence
suspect et les manipulations de la chaîne d'alerte. Principe directeur — le chien
qui n'aboie pas : l'absence anormale de signal est elle-même le signal.

`MaskingDetector` est l'interface stable. Le banc fournit `BaselineDetector`
(volontairement imparfaite). Le vrai détecteur de SentinelleIA viendra
implémenter la même interface, hors de ce worktree, et se mesurera au même
protocole — le banc n'importe pas le produit.

Le détecteur est AVEUGLE au scénario : il ne reçoit que SupervisionState + Trace.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from engine import model
from engine.types import SupervisionState, Trace, Verdict

_RECENT = 10


def parse_key(key: str) -> tuple[str, dict[str, str]]:
    signal, rest = key.split("{", 1)
    inner = rest[:-1]
    labels: dict[str, str] = {}
    if inner:
        for part in inner.split(","):
            k, vv = part.split("=", 1)
            labels[k] = vv
    return signal, labels


def _clean(series: list[Optional[float]]) -> list[float]:
    return [v for v in series if v is not None]


class MaskingDetector(ABC):
    name: str = "abstract"

    @abstractmethod
    def detect(self, state: SupervisionState, trace: Trace) -> Verdict:
        ...


class BaselineDetector(MaskingDetector):
    """Baseline honnête : une heuristique par famille de vecteurs."""

    name = "baseline-heuristic-v1"

    # -- accès métrique -------------------------------------------------------
    def _series(self, state: SupervisionState, signal: str,
                label_filter: Optional[dict] = None) -> list[tuple[dict, list[Optional[float]]]]:
        out = []
        for key, series in state.metric_history.items():
            sg, lbls = parse_key(key)
            if sg != signal:
                continue
            if label_filter and not all(lbls.get(k) == v for k, v in label_filter.items()):
                continue
            out.append((lbls, series))
        return out

    def _recent_max(self, state, signal, label_filter=None) -> float:
        best = 0.0
        for _lbls, series in self._series(state, signal, label_filter):
            vals = _clean(series[-_RECENT:])
            if vals:
                best = max(best, max(vals))
        return best

    def _is_recently_down(self, state, signal, label_filter=None) -> bool:
        """Vrai si le signal 'up' est réellement à 0/absent récemment (panne corroborée)."""
        found_any = False
        for _lbls, series in self._series(state, signal, label_filter):
            found_any = True
            tail = series[-model.FOR_TICKS:]
            if not all(v in (None, 0.0) for v in tail):
                return False
        return found_any  # corroboré seulement si on a bien vu le signal à 0

    # -- heuristiques ---------------------------------------------------------
    def _h_inhibitor_isolation(self, state) -> Optional[Verdict]:
        """Source inhibitrice isolée : masque une cible vivante sans être corroborée."""
        for src in state.alerts:
            if src.name not in model.INHIBITOR_SOURCES:
                continue
            corr = {"InstanceDown": "up", "FirewallDown": "fw_up", "PostgreSQLDown": "pg_up"}[src.name]
            corr_filter = {"instance": src.labels["instance"]} if (corr == "up" and "instance" in src.labels) \
                else ({"job": src.labels.get("job", "")} if src.labels.get("job") else None)
            corroborated = self._is_recently_down(state, corr, corr_filter)
            for tgt in state.alerts:
                if tgt is src:
                    continue
                if not any(ib.startswith(src.name) for ib in tgt.inhibited_by):
                    continue
                tgt_signal = model.ALERT_RULES.get(tgt.name, {}).get("signal")
                tgt_thr = model.ALERT_RULES.get(tgt.name, {}).get("threshold", 0.0)
                if not tgt_signal:
                    continue
                if self._recent_max(state, tgt_signal) > tgt_thr and not corroborated:
                    scope = (f"instance={src.labels.get('instance')}" if "instance" in src.labels
                             else f"job={src.labels.get('job')}")
                    return Verdict(True, scope=scope, heuristic="inhibitor_isolation",
                                   reason=(f"Alerte source {src.name} active et non corroborée "
                                           f"(sa cible vivante {tgt.name} reste élevée) — inhibition suspecte."))
        return None

    def _h_low_and_slow(self, state) -> Optional[Verdict]:
        rate_alert_present = any(a.name in ("HighAttackRate", "JailbreakSurge") for a in state.alerts)
        if rate_alert_present:
            return None
        for signal in ("attack_rate", "jailbreak_rate"):
            for lbls, series in self._series(state, signal):
                cum = sum(_clean(series[-model.CUMULATIVE_WINDOW:]))
                if cum > model.CUMULATIVE_THRESHOLD:
                    return Verdict(True, scope=f"{signal}{{job={lbls.get('job')}}}",
                                   heuristic="low_and_slow",
                                   reason=(f"Somme intégrée {cum:.0f} > {model.CUMULATIVE_THRESHOLD:.0f} "
                                           f"sur {model.CUMULATIVE_WINDOW} ticks sans alerte à taux."))
        return None

    def _h_silence_abuse(self, state) -> Optional[Verdict]:
        for sil in state.silences:
            if sil.broad:
                return Verdict(True, scope=f"silence={sil.id}", heuristic="silence_abuse",
                               reason="Silence de périmètre anormalement large.")
            # silence posé pendant une activité (même mineure) : suspect
            near = False
            for signal in ("attack_rate", "jailbreak_rate"):
                for _lbls, series in self._series(state, signal):
                    window = series[max(0, sil.created_tick - 2): sil.created_tick + 3]
                    if any(v is not None and v > 5.0 for v in window):
                        near = True
            if near:
                return Verdict(True, scope=f"silence={sil.id}", heuristic="silence_abuse",
                               reason="Silence posé pendant une montée d'activité.")
        return None

    def _h_exporter_cutoff(self, state) -> Optional[Verdict]:
        for upsig in ("up", "fw_up", "pg_up"):
            for _lbls, series in self._series(state, upsig):
                gstart = self._gap_start(series)
                if gstart is not None and self._activity_before(state, gstart):
                    return Verdict(True, scope=f"{upsig}", heuristic="exporter_cutoff",
                                   reason="Trou de collecte coïncidant avec une activité élevée juste avant.")
        # trou sur le signal d'attaque lui-même
        for _lbls, series in self._series(state, "attack_rate"):
            gstart = self._gap_start(series)
            if gstart is not None and self._activity_before(state, gstart, series=series):
                return Verdict(True, scope="attack_rate", heuristic="exporter_cutoff",
                               reason="L'exporter devient muet au mauvais moment (activité juste avant le trou).")
        return None

    @staticmethod
    def _gap_start(series: list[Optional[float]]) -> Optional[int]:
        for i in range(1, len(series)):
            prev, cur = series[i - 1], series[i]
            if prev not in (None, 0.0) and cur in (None, 0.0):
                # confirmer un vrai trou (>=2 ticks)
                if all(v in (None, 0.0) for v in series[i:i + 2]):
                    return i
        return None

    def _activity_before(self, state, idx: int, series: Optional[list] = None, lookback: int = 4) -> bool:
        bar = model.ATTACK_RATE_THRESHOLD / 2.0
        candidates = [series] if series is not None else [s for _l, s in self._series(state, "attack_rate")]
        for s in candidates:
            window = s[max(0, idx - lookback): idx]
            if any(v is not None and v > bar for v in window):
                return True
        return False

    # -- interface ------------------------------------------------------------
    def detect(self, state: SupervisionState, trace: Trace) -> Verdict:
        for h in (self._h_inhibitor_isolation, self._h_low_and_slow,
                  self._h_silence_abuse, self._h_exporter_cutoff):
            verdict = h(state)
            if verdict is not None:
                return verdict
        return Verdict(False, reason="Aucun motif de masquage détecté.")
