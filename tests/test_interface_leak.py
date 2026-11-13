"""Étanchéité de l'interface du détecteur.

Le détecteur doit juger la CHAÎNE D'ALERTE, pas le scénario. Il ne reçoit donc que ce
qu'une plateforme d'observabilité verrait : des alertes, des silences, un historique
métrique, et une trace calculée à partir de ce seul état.

Jusqu'à la version 1.0.0, deux choses passaient en plus, et un détecteur pouvait y lire
le corrigé au lieu de la chaîne :
  - le RÉCIT que la cible tient de sa propre manœuvre (`statistical_replay_injected`,
    `licit_traffic_spike`, `rogue_inhibit_rule`, etc.), remis tel quel comme `trace`
  - des artefacts de rédaction dans l'état : un identifiant de silence choisi à la main
    par scénario (`sil-atk`, `sil-ops`), un commentaire de silence variable

La ligne de base ne lisait ni l'un ni l'autre, ses taux publiés n'en dépendaient pas. Un
détecteur tiers branché sur la même interface pouvait, lui, s'en servir.

Ce fichier ferme la porte et prouve PAR MUTATION qu'il sait la voir ouverte :
  - `InterfaceIsSealed`    : ce que le détecteur reçoit réellement, par le chemin de production
  - `ArtefactCheater`      : un tricheur parfait qui ne lit que les artefacts de rédaction ne
    sépare plus aucune attaque, alors que le même tricheur nourri du récit en sépare l'essentiel
  - `StateVocabulary`      : aucun nom que le banc invente dans l'état (alerte, label, matcher)
    ne décrit la manœuvre, et la liste des mots propres aux attaques est fermée et relue
  - `DockerSilencePayload` : la cible docker pose ses silences avec un commentaire constant

Rapide, sans docker, stdlib uniquement.
"""
from __future__ import annotations

import copy
import functools
import os
import re
import sys
import unittest
from dataclasses import asdict

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)  # sourdine/
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from engine import model                                         # noqa: E402
from engine.detector import BaselineDetector, MaskingDetector, parse_key  # noqa: E402
from engine.runner import OBSERVABLE_EVENTS, observable_trace, run_campaign  # noqa: E402
from engine.scenarios import load_scenarios                       # noqa: E402
from engine.target_docker import silence_payload                  # noqa: E402
from engine.target_sim import SimTarget                           # noqa: E402
from engine.types import Scenario, SupervisionState, Trace, Verdict  # noqa: E402

SCENARIOS = os.path.join(_ROOT, "scenarios")


class _Spy(MaskingDetector):
    """Détecteur espion : consigne ce que le moteur lui remet, ne juge rien."""

    name = "spy"

    def __init__(self) -> None:
        self.seen: list[tuple[SupervisionState, Trace]] = []

    def detect(self, state: SupervisionState, trace: Trace) -> Verdict:
        self.seen.append((copy.deepcopy(state), copy.deepcopy(trace)))
        return Verdict(False)


@functools.lru_cache(maxsize=1)
def _campaign() -> tuple[list[Scenario], dict, dict]:
    """Joue le catalogue une fois sur la cible sim et renvoie :
    les scénarios, ce que le détecteur a REÇU par le chemin de production (`run_campaign`),
    et le récit que la cible tient de chaque manœuvre (que le détecteur ne doit pas recevoir)."""
    scenarios = load_scenarios(SCENARIOS)
    spy = _Spy()
    with SimTarget() as target:
        run_campaign(target, spy, scenarios)
        narrative = {sc.id: target.execute(sc)[2] for sc in scenarios}
    seen = {sc.id: got for sc, got in zip(scenarios, spy.seen)}
    return scenarios, seen, narrative


def artefact_signature(state: SupervisionState, trace: Trace) -> tuple:
    """Tout ce qui, dans l'entrée du détecteur, peut porter la main du rédacteur du scénario
    plutôt que la chaîne d'alerte : types et noms de champs des événements de la trace,
    identifiants et commentaires de silence. Les valeurs observables (matchers, séries,
    alertes) n'en font pas partie : les lire est le travail du détecteur."""
    return (
        tuple(e["kind"] for e in trace.events),
        tuple(tuple(sorted(e)) for e in trace.events),
        tuple(s.id for s in state.silences),
        tuple(s.comment for s in state.silences),
    )


def separable_attacks(signatures: dict, scenarios: list[Scenario]) -> list[str]:
    """Attaques qu'un tricheur parfait signalerait SANS AUCUN faux positif en ne lisant que
    les artefacts : celles dont la signature n'est portée par aucun scénario sain."""
    healthy = {signatures[sc.id] for sc in scenarios if not sc.is_attack}
    return sorted(sc.id for sc in scenarios
                  if sc.is_attack and signatures[sc.id] not in healthy)


class InterfaceIsSealed(unittest.TestCase):
    """Ce que le détecteur reçoit, mesuré par un espion branché sur le chemin de production."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.scenarios, cls.seen, cls.narrative = _campaign()

    def test_every_scenario_was_observed(self) -> None:
        self.assertEqual(sorted(self.seen), sorted(sc.id for sc in self.scenarios))

    def test_trace_is_a_pure_function_of_the_state(self) -> None:
        for sid, (state, trace) in self.seen.items():
            self.assertEqual(
                trace.events, observable_trace(state).events,
                f"{sid} : la trace remise au détecteur n'est pas celle que l'état seul permet "
                f"de calculer. Le moteur lui passe autre chose (le récit de la cible ?).")

    def test_trace_events_are_allow_listed(self) -> None:
        for sid, (_state, trace) in self.seen.items():
            for ev in trace.events:
                self.assertIn(ev["kind"], OBSERVABLE_EVENTS,
                              f"{sid} : événement {ev['kind']!r} hors liste blanche.")
                allowed = {"tick", "kind", *OBSERVABLE_EVENTS[ev["kind"]]}
                self.assertEqual(set(ev), allowed,
                                 f"{sid} : champs inattendus dans {ev['kind']!r}.")

    def test_silences_carry_no_authoring_artefact(self) -> None:
        for sid, (state, _trace) in self.seen.items():
            for rank, sil in enumerate(state.silences, start=1):
                self.assertEqual(sil.id, f"sil-{rank}",
                                 f"{sid} : identifiant de silence non neutre ({sil.id!r}).")
                self.assertEqual(sil.comment, model.SILENCE_COMMENT,
                                 f"{sid} : commentaire de silence variable ({sil.comment!r}).")
                self.assertEqual(sil.broad, model.silence_is_broad(sil.matchers),
                                 f"{sid} : `broad` ne se déduit pas des matchers.")

    def test_baseline_verdicts_do_not_depend_on_the_trace(self) -> None:
        baseline = BaselineDetector()
        for sid, (state, trace) in self.seen.items():
            self.assertEqual(
                asdict(baseline.detect(state, trace)), asdict(baseline.detect(state, Trace())),
                f"{sid} : le verdict de la ligne de base change quand on lui retire la trace.")


class ArtefactCheater(unittest.TestCase):
    """Un tricheur qui ne lit que les artefacts de rédaction ne doit rien pouvoir séparer."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.scenarios, cls.seen, cls.narrative = _campaign()
        cls.n_attacks = sum(1 for sc in cls.scenarios if sc.is_attack)

    def test_cheater_separates_no_attack(self) -> None:
        sigs = {sid: artefact_signature(state, trace) for sid, (state, trace) in self.seen.items()}
        self.assertEqual(
            separable_attacks(sigs, self.scenarios), [],
            "des attaques se reconnaissent à un artefact de rédaction (type d'événement, nom de "
            "champ, identifiant ou commentaire de silence) qu'aucun scénario sain ne porte : "
            "l'interface livre le corrigé.")

    # -- preuve par mutation : le contrôle doit SAVOIR échouer ----------------
    def test_mutation_narrative_trace_is_seen_as_a_leak(self) -> None:
        # ce que la version 1.0.0 remettait au détecteur : le récit de la cible.
        sigs = {sid: artefact_signature(self.seen[sid][0], self.narrative[sid])
                for sid in self.seen}
        leaked = separable_attacks(sigs, self.scenarios)
        self.assertGreaterEqual(
            len(leaked), (3 * self.n_attacks) // 4,
            f"le récit ne sépare que {len(leaked)} attaques sur {self.n_attacks} : le contrôle "
            f"ne verrait pas la fuite qu'il est censé garder.")

    def test_mutation_named_silence_ids_are_seen_as_a_leak(self) -> None:
        # ce que la version 1.0.0 mettait dans l'état : un identifiant de silence par scénario.
        vector = {sc.id: sc.vector for sc in self.scenarios}
        sigs = {}
        for sid, (state, trace) in self.seen.items():
            mutated = copy.deepcopy(state)
            for sil in mutated.silences:
                sil.id = f"sil-{vector[sid]}"
            sigs[sid] = artefact_signature(mutated, trace)
        self.assertNotEqual(separable_attacks(sigs, self.scenarios), [],
                            "des identifiants de silence nommés par scénario ne sont pas vus.")


# Mots qui décriraient la manœuvre au lieu de la laisser observer. Aucun nom que le banc
# invente et que le détecteur lit dans l'état ne doit en contenir.
TELLING_WORDS = ("rogue", "flood", "spoof", "mute", "decoy", "fake", "evil", "malicious", "atk")

# Mots de l'état que seules des attaques portent, chiffres neutralisés (`fw-1` et `fw-7` se
# valent). Liste FERMÉE : chaque entrée est un fait observable de la manœuvre, jamais son
# étiquette. Un scénario qui en ajoute un fait échouer le test tant qu'il n'a pas été relu ici.
ATTACK_ONLY_WORDS = {
    # sources d'inhibition : l'alerte source et l'inhibition qu'elle produit
    "alerte:PostgreSQLDown",                       # aucune panne PostgreSQL chez les sains
    "inhibée par:FirewallDown[job=firewall]",
    "inhibée par:InstanceDown[instance=fw-N,job=firewall]",
    "inhibée par:PostgreSQLDown[job=postgresql]",
    "alerte:MaintenanceWindow",                    # source de la règle ajoutée, nom anodin
    "inhibée par:MaintenanceWindow",
    # périmètre d'inhibition élargi : l'instance leurre, une recette sans lien avec le pare-feu
    "label:instance=stg-N",
    "label:job=staging",
    "inhibée par:InstanceDown[instance=stg-N]",
    # silences : leur contenu EST la manœuvre
    "matcher:alertname=HighAttackRate",
    "matcher:alertname=~.+",
    "matcher:instance=~.+",
    "matcher:job=firewall",
}


def state_words(state: SupervisionState) -> set:
    """Le vocabulaire d'un état : noms d'alertes, labels, sources d'inhibition, matchers de
    silence, signaux. Les chiffres sont neutralisés."""
    words = set()
    for a in state.alerts:
        words.add(f"alerte:{a.name}")
        words.update(f"label:{k}={v}" for k, v in a.labels.items())
        words.update(f"inhibée par:{src}" for src in a.inhibited_by)
    for sil in state.silences:
        words.update(f"matcher:{k}={v}" for k, v in sil.matchers.items())
    for key in state.metric_history:
        signal, labels = parse_key(key)
        words.add(f"signal:{signal}")
        words.update(f"label:{k}={v}" for k, v in labels.items())
    return {re.sub(r"\d+", "N", w) for w in words}


class StateVocabulary(unittest.TestCase):
    """Les noms que le banc invente dans l'état ne doivent pas décrire la manœuvre. Jusqu'à la
    version 1.0.0, la source de la règle d'inhibition ajoutée s'appelait `RogueMuter` et les
    alertes sœurs de la noyade par groupement portaient les instances `flood-0` à `flood-19`."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.scenarios, cls.seen, _narrative = _campaign()
        cls.words = {sid: state_words(state) for sid, (state, _trace) in cls.seen.items()}

    def test_no_name_describes_the_manoeuvre(self) -> None:
        for sid, words in self.words.items():
            for word in sorted(words):
                for telling in TELLING_WORDS:
                    self.assertNotIn(telling, word.lower(),
                                     f"{sid} : le nom {word!r} décrit la manœuvre ({telling!r}).")

    def test_attack_only_words_are_a_closed_reviewed_list(self) -> None:
        in_attacks, in_healthy = set(), set()
        for sc in self.scenarios:
            (in_attacks if sc.is_attack else in_healthy).update(self.words[sc.id])
        found = in_attacks - in_healthy
        self.assertEqual(
            found, ATTACK_ONLY_WORDS,
            "le vocabulaire propre aux attaques a changé. Mots nouveaux, à relire : "
            f"{sorted(found - ATTACK_ONLY_WORDS)}. Entrées périmées : "
            f"{sorted(ATTACK_ONLY_WORDS - found)}.")

    def test_mutation_the_old_names_would_be_seen(self) -> None:
        # ce que la version 1.0.0 mettait dans l'état.
        for old in ("alerte:RogueMuter", "label:instance=flood-N"):
            self.assertTrue(any(telling in old.lower() for telling in TELLING_WORDS),
                            f"{old!r} passerait la garde.")

    def test_docker_config_names_the_same_added_source(self) -> None:
        path = os.path.join(_ROOT, "target", "alertmanager", "alertmanager.yml")
        with open(path, encoding="utf-8") as f:
            rules = [line for line in f
                     if "alertname" in line and not line.lstrip().startswith("#")]
        self.assertTrue(
            any(f'alertname="{model.ADDED_INHIBITOR_SOURCE}"' in line for line in rules),
            "la règle d'inhibition ajoutée n'a pas la même source en sim et en docker.")
        for line in rules:
            for telling in TELLING_WORDS:
                self.assertNotIn(telling, line.lower(),
                                 f"alertmanager.yml : {line.strip()!r} décrit la manœuvre.")


class DockerSilencePayload(unittest.TestCase):
    """La cible docker pose de vrais silences : leur auteur et leur commentaire, que le
    détecteur relit dans l'état, ne doivent rien dire du scénario."""

    def test_only_the_matchers_vary(self) -> None:
        broad = silence_payload({"instance": "~.+"}, 1000.0)
        narrow = silence_payload({"alertname": "HighAttackRate", "job": "firewall"}, 1000.0)
        for payload in (broad, narrow):
            self.assertEqual(payload["comment"], model.SILENCE_COMMENT)
        self.assertEqual({k: v for k, v in broad.items() if k != "matchers"},
                         {k: v for k, v in narrow.items() if k != "matchers"})

    def test_matchers_are_translated_faithfully(self) -> None:
        payload = silence_payload({"alertname": "~.+", "instance": "fw-1"}, 0.0)
        self.assertEqual(payload["matchers"], [
            {"name": "alertname", "value": ".+", "isRegex": True, "isEqual": True},
            {"name": "instance", "value": "fw-1", "isRegex": False, "isEqual": True},
        ])


if __name__ == "__main__":
    unittest.main(verbosity=2)
