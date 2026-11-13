"""Paires jumelles du catalogue.

Deux sortes de paires attaque / sain structurent la lecture des taux.

Les paires INDISCERNABLES : l'état observable de l'attaque et celui du scénario sain sont
strictement identiques. Aucun détecteur limité à la chaîne d'alerte ne peut rattraper
l'une sans signaler l'autre : chaque paire coûte une erreur, au choix du détecteur (un
faux positif, ou une suppression résiduelle). Le banc les garde exprès. Elles bornent ce
qu'on peut attendre d'un détecteur de ce type, et un détecteur qui prétendrait les séparer
lirait autre chose que la chaîne.

La paire DISCRIMINANTE : même geste (un silence étroit, à `alertname` littéral, posé
pendant une activité), sur une alerte de sécurité dans un cas, opérationnelle dans l'autre.
Un détecteur correct doit séparer les deux. Le dernier test en fait la démonstration sur
l'état du scénario sain lui-même : en ne changeant que l'alerte visée, le verdict bascule.

Rapide, sans docker, stdlib uniquement.
"""
from __future__ import annotations

import copy
import os
import sys
import unittest
from dataclasses import asdict

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)  # sourdine/
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from engine import model                         # noqa: E402
from engine.detector import BaselineDetector      # noqa: E402
from engine.runner import observable_trace        # noqa: E402
from engine.scenarios import load_scenarios       # noqa: E402
from engine.target_sim import SimTarget           # noqa: E402

SCENARIOS = os.path.join(_ROOT, "scenarios")

# (attaque, jumeau sain) : états observables strictement identiques.
INDISTINGUISHABLE = (
    ("ATT-LOW-SLOW-CATCHABLE-04", "HLT-BENIGN-SPIKE-05"),
    ("ATT-STATISTICAL-REPLAY-18", "HLT-BENIGN-NOISE-13"),
)
# (attaque, pendant sain) : même geste, classe de l'alerte visée différente.
DISCRIMINATING = ("ATT-SILENCE-NARROW-27", "HLT-BENIGN-SILENCE-03")


class TwinPairs(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        with SimTarget() as target:
            cls.state = {sc.id: target.execute(sc)[1] for sc in load_scenarios(SCENARIOS)}
        cls.baseline = BaselineDetector()

    def setUp(self) -> None:
        self.maxDiff = None

    def _verdict(self, state):
        return self.baseline.detect(state, observable_trace(state))

    # -- paires indiscernables -------------------------------------------------
    def test_indistinguishable_pairs_have_identical_states(self) -> None:
        for attack, healthy in INDISTINGUISHABLE:
            self.assertEqual(
                asdict(self.state[attack]), asdict(self.state[healthy]),
                f"{attack} et {healthy} ne sont plus indiscernables : leurs états diffèrent. "
                f"Les réaligner, ou retirer la paire de la documentation.")

    def test_each_indistinguishable_pair_costs_exactly_one_error(self) -> None:
        for attack, healthy in INDISTINGUISHABLE:
            on_attack = self._verdict(self.state[attack]).masking_suspected
            on_healthy = self._verdict(self.state[healthy]).masking_suspected
            self.assertEqual(
                on_attack, on_healthy,
                f"{attack} et {healthy} reçoivent deux verdicts pour un même état : le "
                f"détecteur lit autre chose que l'état observable.")

    # -- paire discriminante ---------------------------------------------------
    def test_discriminating_pair_is_separated(self) -> None:
        attack, healthy = DISCRIMINATING
        on_attack = self._verdict(self.state[attack])
        self.assertTrue(on_attack.masking_suspected, f"{attack} n'est pas rattrapé.")
        self.assertEqual(on_attack.heuristic, "silence_abuse")
        self.assertFalse(self._verdict(self.state[healthy]).masking_suspected,
                         f"{healthy} est signalé à tort : silencer une alerte opérationnelle "
                         f"pendant une activité licite n'est pas un masquage.")

    def test_the_discriminant_is_the_class_of_the_silenced_alert(self) -> None:
        # même silence, même activité : seule change l'alerte qu'il fait taire.
        _attack, healthy = DISCRIMINATING
        for security_alert in sorted(model.SECURITY_RATE_ALERTS):
            mutated = copy.deepcopy(self.state[healthy])
            self.assertEqual(len(mutated.silences), 1)
            self.assertNotIn(mutated.silences[0].matchers["alertname"], model.SECURITY_RATE_ALERTS)
            mutated.silences[0].matchers["alertname"] = security_alert
            verdict = self._verdict(mutated)
            self.assertTrue(verdict.masking_suspected,
                            f"le silence de {healthy}, pointé sur {security_alert}, passe inaperçu.")
            self.assertEqual(verdict.heuristic, "silence_abuse")


if __name__ == "__main__":
    unittest.main(verbosity=2)
