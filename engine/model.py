"""Sourdine : modèle sémantique représentatif de la chaîne d'alerte.

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
# mais s'étale puisse être rattrapée : et qu'une qui reste sous l'intégré passe
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

# --- Rejeu / gel (stale_replay) -----------------------------------------------
# Nombre de points consécutifs EXACTEMENT constants au-delà duquel une queue figée est
# jugée suspecte (rejeu/stale) : un vrai signal de trafic ne reste pas rigoureusement
# constant aussi longtemps. Combiné à un franchissement de seuil antérieur et à une
# valeur figée sous le seuil (zone grise), c'est la signature du concealment temporel.
STALE_FROZEN_MIN = 6

# --- Watchdog / dead man's switch (meta-monitoring) ---------------------------
# Heartbeat toujours émis (vector(1)) qui prouve que TOUTE la chaîne d'alerte
# (Prometheus -> Alertmanager -> livraison) est vivante. « Un système de supervision
# ne peut pas surveiller de façon fiable sa propre panne » : si la chaîne tombe, le
# heartbeat s'arrête et un veilleur INDÉPENDANT le remarque. Son silence SOUTENU est
# le signal (dead man's switch déclenché). Un raté transitoire (un scrape manqué) se
# rétablit tout seul : seule une absence d'au moins WATCHDOG_MIN_SILENCE ticks compte.
WATCHDOG_SIGNAL = "watchdog"
WATCHDOG_MIN_SILENCE = 4

# --- Cardinalité d'ingestion (bombe de séries) --------------------------------
# `scrape_samples` = nombre d'échantillons rendus par la cible au dernier scrape
# (métrique Prometheus `scrape_samples_scraped`). Un attaquant qui injecte un flot de
# séries à très haute cardinalité fait dépasser `sample_limit` : Prometheus REJETTE le
# scrape entier et met `up` à 0 « comme si la cible était tombée » : le vrai signal
# n'est jamais ingéré. Le pic de `scrape_samples` bien au-delà de toute croissance
# légitime (un déploiement n'ajoute que quelques dizaines de séries) est ce qui distingue
# la bombe de cardinalité d'une vraie panne (MITRE Impair Defenses via épuisement de
# ressources / T1499). Seuil calé loin au-dessus d'un bump licite, loin sous une bombe.
CARDINALITY_SIGNAL = "scrape_samples"
CARDINALITY_FLOOD_THRESHOLD = 5000.0

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

# Signal qui CORROBORE la panne annoncée par une source d'inhibition sanctionnée.
# SOURCE UNIQUE, partagée par deux heuristiques qui l'interrogent en sens opposés :
# `inhibitor_isolation` cherche la NON-corroboration (signature du spoof : la source
# prétend une panne que le signal dément), `guard_down_under_threat` exige au contraire
# la corroboration (signature de la panne réellement induite). Un seul motif, deux
# lectures : le dupliquer le ferait dériver d'un côté sans qu'on le voie de l'autre.
INHIBITOR_CORROBORATION = {"InstanceDown": "up", "FirewallDown": "fw_up",
                           "PostgreSQLDown": "pg_up"}

# Sources d'inhibition dont la panne AVEUGLE la défense elle-même (le « garde »).
# Leur inhibition de la classe sécurité est légitime PAR CONFIGURATION : c'est même sa
# raison d'être (ne pas crier au débordement quand le firewall est tombé). Mais une panne
# RÉELLE du garde CONCOMITANTE d'une menace RÉELLE est exactement le cas que cette règle
# de réduction de bruit rend invisible, et que l'attaquant provoque délibérément
# (MITRE T1562.001 : désactiver le contrôle de sécurité, puis opérer dans l'angle mort).
# Périmètre volontairement étroit : seul le garde du service qui porte SECURITY_RATE_ALERTS.
SECURITY_GUARD_SOURCES = {"FirewallDown"}

# Alertes de SÉCURITÉ (menace côté firewall) : leur non-livraison alors que la
# menace est réelle est un blocage d'indicateur (T1562.006), là où la non-livraison
# d'une alerte opérationnelle (ex. PostgreSQLHighConnections) peut être une
# maintenance légitime. Discriminant du détecteur `notification_blackhole`.
SECURITY_RATE_ALERTS = {"HighAttackRate", "CriticalAttacksDetected", "JailbreakSurge"}

# Règles d'inhibition (source masque les cibles si les labels `equal` coïncident).
INHIBIT_RULES: list[dict] = [
    {"source": "InstanceDown",   "target_re": r".+",                                              "equal": ["instance"]},
    {"source": "FirewallDown",   "target_re": r"^(HighAttackRate|CriticalAttacksDetected|JailbreakSurge)$", "equal": ["job"]},
    {"source": "PostgreSQLDown", "target_re": r"^PostgreSQL.*$",                                   "equal": ["job"]},
]

# Pour chaque source inhibitrice : quels noms de cible elle masque (pour la
# corrélation côté détecteur).
INHIBITOR_TARGET_RE = {r["source"]: re.compile(r["target_re"]) for r in INHIBIT_RULES}

# Labels `equal` SANCTIONNÉS de chaque règle : le périmètre dans lequel une source a le
# droit d'inhiber. DÉRIVÉ de INHIBIT_RULES (jamais recopié) : la baseline reste l'unique
# endroit où le périmètre est déclaré. La doc Alertmanager prévient que si les labels
# `equal` sont absents des DEUX alertes, la règle s'applique quand même : retirer `equal`
# transforme donc une inhibition ciblée en suppression GLOBALE, ce qu'exploite le vecteur
# `inhibition_scope_creep` (MITRE T1562.001, élargissement de périmètre).
INHIBITOR_EQUAL = {r["source"]: tuple(r["equal"]) for r in INHIBIT_RULES}


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
