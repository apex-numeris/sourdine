"""Sourdine — interface de cible.

Une *cible* est un environnement de supervision jetable que le banc monte et
détruit lui-même. Deux implémentations :
  - SimTarget      : modèle en process, déterministe, hermétique (aucun conteneur).
  - DockerTarget   : vrais conteneurs Prometheus + Alertmanager éphémères.

La cible exécute UN scénario et renvoie, pour la passe 1 (sans détecteur), le
résultat brut observé, plus l'état de supervision et la trace observables que la
passe 2 soumettra au détecteur. La cible ne connaît jamais le verdict attendu.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from engine.types import RawResult, Scenario, SupervisionState, Trace


class Target(ABC):
    name: str = "abstract"

    @abstractmethod
    def setup(self) -> None:
        """Monte la cible (idempotent)."""

    @abstractmethod
    def execute(self, scenario: Scenario) -> tuple[RawResult, SupervisionState, Trace]:
        """Joue un scénario sur un état frais et renvoie (brut, état, trace)."""

    @abstractmethod
    def teardown(self) -> None:
        """Détruit la cible et tout son état."""

    def __enter__(self) -> "Target":
        self.setup()
        return self

    def __exit__(self, *exc) -> None:
        self.teardown()
