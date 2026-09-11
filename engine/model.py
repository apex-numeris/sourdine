"""Sourdine — modèle sémantique représentatif de la chaîne d'alerte.

Jeu de règles d'alerte + règles d'inhibition + paramètres de routage **recréés**
(jamais copiés depuis la production) mais représentatifs de ce qui a été observé :
  - inhibition InstanceDown → toutes les alertes de la même instance ;
  - inhibition FirewallDown → {HighAttackRate, CriticalAttacksDetected, JailbreakSurge} (même job) ;
  - inhibition PostgreSQLDown → PostgreSQL.* (même job).

Le même jeu logique est exprimé en YAML pour la cible docker (target/*.yml). Ici,
il sert la cible sim en process et fournit au détecteur les seuils de référence.

Stdlib uniquement.
"""
from __future__ import annotations

import re
from typing import Optional

from engine.types import Alert, Silence

# --- Paramètres de firing (cible sim) -----------------------------------------
FOR_TICKS = 3                 # durée `for:` en ticks avant qu'une règle ne fire
HORIZON = 30                  # ticks simulés par scénario

# --- Seuils ------------------------------------------------------------------
ATTACK_RATE_THRESHOLD = 50.0      # seuil instantané de HighAttackRate (req/s d'attaque)
JAILBREAK_RATE_THRESHOLD = 10.0   # seuil instantané de JailbreakSurge
PG_CONN_THRESHOLD = 180.0         # seuil de PostgreSQLHighConnections

# Seuil *intégré* (somme sur fenêtre longue) utilisé par le détecteur low-and-slow.
# Volontairement calé pour qu'une attaque qui reste juste sous le seuil instantané
# mais s'étale puisse être rattrapée — et qu'une qui reste sous l'intégré passe
# (suppression résiduelle non nulle), et qu'un pic licite puisse faux-positiver.
CUMULATIVE_WINDOW = 20            # ticks de la fenêtre d'intégration
CUMULATIVE_THRESHOLD = 540.0      # somme sur la fenêtre au-delà de laquelle c'est suspect

# --- Routage / groupement -----------------------------------------------------
GROUP_BY = ["alertname", "service", "severity"]
FLOOD_MIN = 12                    # nb d'alertes dans un groupe au-delà duquel la vraie alerte est noyée

# --- Flapping (réinitialisation du `for:`) ------------------------------------
# Nombre de franchissements montants du seuil instantané (sans qu'aucune alerte à
# taux ne soit active) au-delà duquel le détecteur soupçonne un flapping volontaire :
# l'attaquant fait osciller le signal autour du seuil pour que la durée `for:` ne
# se complète jamais, donc l'alerte ne se déclenche jamais.
FLAP_MIN_CROSSINGS = 5

# --- Familles d'alertes -------------------------------------------------------
# Métadonnées par alerte : signal déclencheur, type, sévérité, service.
ALERT_RULES: dict[str, dict] = {
    "HighAttackRate":          {"type": "threshold", "signal": "attack_rate",     "threshold": ATTACK_RATE_THRESHOLD, "severity": "warning",  "service": "firewall"},
    "CriticalAttacksDetected": {"type": "threshold", "signal": "critical_attacks", "threshold": 0.0,                   "severity": "critical", "service": "firewall"},
    "JailbreakSurge":          {"type": "threshold", "signal": "jailbreak_rate",   "threshold": JAILBREAK_RATE_THRESHOLD, "severity": "high",  "service": "firewall"},
    "InstanceDown":            {"type": "absence",   "signal": "up",               "severity": "critical", "service": "infrastructure"},
    "FirewallDown":            {"type": "absence",   "signal": "fw_up",            "severity": "critical", "service": "firewall"},
    "PostgreSQLDown":          {"type": "absence",   "signal": "pg_up",            "severity": "critical", "service": "postgresql"},
    "PostgreSQLHighConnections": {"type": "threshold", "signal": "pg_conns",       "threshold": PG_CONN_THRESHOLD, "severity": "warning", "service": "postgresql"},
    "GatewayDown":             {"type": "absence",   "signal": "gw_up",            "severity": "critical", "service": "gateway"},
}

# Alertes « source inhibitrice » : leur seule présence masque d'autres alertes.
INHIBITOR_SOURCES = {"InstanceDown", "FirewallDown", "PostgreSQLDown"}

# Règles d'inhibition (source masque les cibles si les labels `equal` coïncident).
INHIBIT_RULES: list[dict] = [
    {"source": "InstanceDown",   "target_re": r".+",                                              "equal": ["instance"]},
    {"source": "FirewallDown",   "target_re": r"^(HighAttackRate|CriticalAttacksDetected|JailbreakSurge)$", "equal": ["job"]},
    {"source": "PostgreSQLDown", "target_re": r"^PostgreSQL.*$",                                   "equal": ["job"]},
]

# Pour chaque source inhibitrice : quels noms de cible elle masque (pour la
# corrélation côté détecteur).
INHIBITOR_TARGET_RE = {r["source"]: re.compile(r["target_re"]) for r in INHIBIT_RULES}


def series_key(signal: str, labels: dict[str, str]) -> str:
    inner = ",".join(f"{k}={labels[k]}" for k in sorted(labels))
    return f"{signal}{{{inner}}}"


def _label_match(matcher_value: str, actual: Optional[str]) -> bool:
    if actual is None:
        return False
    if matcher_value.startswith("~"):
        return re.fullmatch(matcher_value[1:], actual) is not None
    return matcher_value == actual


def silence_matches(sil: Silence, alert: Alert) -> bool:
    """Un silence matche si tous ses matchers matchent les labels de l'alerte
    (alertname inclus comme label)."""
    labelset = {"alertname": alert.name, **alert.labels}
    return all(_label_match(v, labelset.get(k)) for k, v in sil.matchers.items())


def apply_inhibitions(alerts: list[Alert]) -> None:
    """Renseigne `inhibited_by` sur chaque alerte selon INHIBIT_RULES.

    Sémantique Alertmanager : une alerte source active masque une cible si les
    labels `equal` coïncident ; une alerte qui matche la source d'une règle n'est
    pas inhibée par cette même règle.
    """
    for target in alerts:
        for rule in INHIBIT_RULES:
            if target.name == rule["source"]:
                continue  # ne pas s'auto-inhiber via la même règle
            if not INHIBITOR_TARGET_RE[rule["source"]].match(target.name):
                continue
            for source in alerts:
                if source is target or source.name != rule["source"]:
                    continue
                if all(source.labels.get(l) == target.labels.get(l) for l in rule["equal"]):
                    tag = source.name + (f"[{series_key('', source.labels)[2:]}" if source.labels else "")
                    if tag not in target.inhibited_by:
                        target.inhibited_by.append(tag)


def apply_silences(alerts: list[Alert], silences: list[Silence]) -> None:
    for alert in alerts:
        for sil in silences:
            if silence_matches(sil, alert) and sil.id not in alert.silenced_by:
                alert.silenced_by.append(sil.id)


def group_key(alert: Alert) -> tuple:
    labelset = {"alertname": alert.name, **alert.labels}
    return tuple(labelset.get(k, "") for k in GROUP_BY)
