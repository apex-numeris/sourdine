"""Sourdine — types partagés du banc de masquage d'alarme.

Aucune dépendance tierce : stdlib uniquement (dataclasses, typing).
Ces types sont communs aux deux cibles (sim en process, docker éphémère) et au
détecteur, pour que le détecteur soit *aveugle au scénario* : il ne reçoit que
des données de supervision observables (alertes, silences, historique métrique,
trous de collecte), jamais le vecteur ni la vérité terrain.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional

# --- Niveaux d'accès attaquant (ventilation du rapport) ------------------------
ACCESS_METRIC_OR_AM_API = "metric_or_am_api"          # ingestion métrique / API Alertmanager
ACCESS_THRESHOLD_KNOWLEDGE = "threshold_knowledge"    # aucun accès superviseur, connaît les seuils
ACCESS_SILENCE_OR_ROUTING = "silence_or_routing_api"  # API silences / config de routage
ACCESS_EXPORTER_HOST_OR_NET = "exporter_host_or_network"  # hôte exporter / blocage réseau du scrape
ACCESS_NONE = "n/a"                                   # scénarios sains

# --- Vecteurs ------------------------------------------------------------------
VEC_FIREWALL_DOWN_SPOOF = "firewall_down_spoof"
VEC_INSTANCE_DOWN_SPOOF = "instance_down_spoof"
VEC_POSTGRES_DOWN_SPOOF = "postgres_down_spoof"
VEC_LOW_AND_SLOW = "low_and_slow"
VEC_SILENCE_ABUSE = "silence_abuse"
VEC_SILENCE_SHARED_LABEL = "silence_shared_label"
VEC_SILENCE_REGEX_ALERTNAME = "silence_regex_alertname"
VEC_GROUPING_REPEAT_ABUSE = "grouping_repeat_abuse"
VEC_EXPORTER_CUTOFF = "exporter_cutoff"
VEC_SELECTIVE_METRIC_DROP = "selective_metric_drop"
VEC_THRESHOLD_FLAPPING = "threshold_flapping"
VEC_FALSE_RESOLVED = "false_resolved"
VEC_STALE_REPLAY = "stale_replay"
VEC_NONE = "none"

ATTACK_VECTORS = {
    VEC_FIREWALL_DOWN_SPOOF, VEC_INSTANCE_DOWN_SPOOF, VEC_POSTGRES_DOWN_SPOOF,
    VEC_LOW_AND_SLOW, VEC_SILENCE_ABUSE, VEC_SILENCE_SHARED_LABEL,
    VEC_SILENCE_REGEX_ALERTNAME, VEC_GROUPING_REPEAT_ABUSE, VEC_EXPORTER_CUTOFF,
    VEC_SELECTIVE_METRIC_DROP, VEC_THRESHOLD_FLAPPING, VEC_FALSE_RESOLVED,
    VEC_STALE_REPLAY,
}


@dataclass
class GroundTruth:
    """Vérité terrain d'un scénario : une alarme était-elle attendue, laquelle."""
    alarm_expected: bool
    expected_alert: Optional[str] = None
    labels: dict[str, str] = field(default_factory=dict)


@dataclass
class Scenario:
    id: str
    kind: str                      # "attack" | "healthy"
    vector: str                    # VEC_*
    title: str
    description: str
    access_level: str              # ACCESS_*
    ground_truth: GroundTruth
    event: dict[str, Any] = field(default_factory=dict)     # l'événement qui devait lever l'alarme
    masking: dict[str, Any] = field(default_factory=dict)   # la manœuvre qui efface le signalement
    coherence_control: bool = False
    tags: list[str] = field(default_factory=list)

    @property
    def is_attack(self) -> bool:
        return self.kind == "attack"


@dataclass
class Alert:
    """Une alerte telle que vue dans Alertmanager."""
    name: str
    labels: dict[str, str] = field(default_factory=dict)
    inhibited_by: list[str] = field(default_factory=list)   # noms des alertes source inhibitrices
    silenced_by: list[str] = field(default_factory=list)    # ids de silence
    delayed: bool = False                                    # noyée par le groupement / repeat_interval

    @property
    def notified(self) -> bool:
        return not self.inhibited_by and not self.silenced_by and not self.delayed

    def matches(self, name: str, labels: dict[str, str]) -> bool:
        if self.name != name:
            return False
        return all(self.labels.get(k) == v for k, v in labels.items())


@dataclass
class Silence:
    id: str
    matchers: dict[str, str]       # label -> valeur (préfixe "~" = regex)
    created_tick: int
    comment: str = ""              # champ fourni par le créateur — NON fiable (peut être attaquant)
    broad: bool = False            # périmètre anormalement large (pas de matcher d'instance/alertname précis)


@dataclass
class SupervisionState:
    """Instantané observable de la supervision, fin de scénario."""
    alerts: list[Alert] = field(default_factory=list)
    silences: list[Silence] = field(default_factory=list)
    # historique métrique observable : "signal{k=v,...}" -> valeurs par tick (None = absent/trou)
    metric_history: dict[str, list[Optional[float]]] = field(default_factory=dict)
    horizon: int = 0


@dataclass
class Trace:
    """Journal observable des événements de supervision (ordonné)."""
    events: list[dict[str, Any]] = field(default_factory=list)

    def add(self, tick: int, kind: str, **detail: Any) -> None:
        self.events.append({"tick": tick, "kind": kind, **detail})


@dataclass
class RawResult:
    """Résultat de la passe 1 (SANS détecteur) : l'alarme attendue est-elle sortie ?"""
    alarm_raised: bool
    notified_alerts: list[dict[str, Any]] = field(default_factory=list)
    fired_alerts: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Verdict:
    """Sortie du détecteur de masquage (passe 2)."""
    masking_suspected: bool
    scope: Optional[str] = None        # ex. "instance=fw-1" / "alertname=HighAttackRate"
    reason: str = ""
    heuristic: Optional[str] = None    # famille d'heuristique ayant déclenché


@dataclass
class ScenarioResult:
    scenario: Scenario
    raw: RawResult                     # passe 1
    verdict: Verdict                   # passe 2
    timestamp: str = ""

    # --- Lectures normatives (cf. spec) ---------------------------------------
    @property
    def masked(self) -> bool:
        """Masquage réussi = une alarme était attendue et n'est PAS sortie (passe 1).

        Le statut se lit TOUJOURS sur la passe SANS détecteur : une alarme qui
        disparaît sans détecteur est un masquage réussi, même si le détecteur la
        rattrape ensuite.
        """
        return self.scenario.ground_truth.alarm_expected and not self.raw.alarm_raised

    @property
    def flagged(self) -> bool:
        return self.verdict.masking_suspected

    def to_dict(self) -> dict[str, Any]:
        gt = self.scenario.ground_truth
        return {
            "id": self.scenario.id,
            "kind": self.scenario.kind,
            "vector": self.scenario.vector,
            "access_level": self.scenario.access_level,
            "coherence_control": self.scenario.coherence_control,
            "ground_truth": {
                "alarm_expected": gt.alarm_expected,
                "expected_alert": gt.expected_alert,
                "labels": gt.labels,
            },
            "raw_result": {
                "alarm_raised": self.raw.alarm_raised,
                "masked": self.masked,
                "notified_alerts": self.raw.notified_alerts,
                "fired_alerts": self.raw.fired_alerts,
            },
            "detector_verdict": {
                "masking_suspected": self.verdict.masking_suspected,
                "scope": self.verdict.scope,
                "reason": self.verdict.reason,
                "heuristic": self.verdict.heuristic,
            },
            "timestamp": self.timestamp,
        }
