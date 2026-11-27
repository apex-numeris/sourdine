"""Cohérence de la page publiée sur sourdine.org avec la version courante.

Garde-fou : `site/index.html` est la page servie à la racine de sourdine.org. Elle
affiche un numéro de version, des comptages de scénarios et un tableau de résultats,
en français et en anglais. Tant que ce test est vert, ces valeurs sont celles du
fichier `VERSION` et des deux échantillons gelés de la version courante
(`samples/example-<VERSION>.json` et `samples/example-<VERSION>-docker.json`).

Ce que le test compare :
  - le numéro de version (en-tête du tableau de contenu, titre des résultats) ;
  - les comptages (scénarios, attaques, vecteurs, sains) ;
  - les deux lignes de résultats (sim, docker), taux et fractions, dans les deux langues.
Ce qu'il ignore : la prose de la page (filiation, note de lecture, mentions légales).

La preuve par mutation, en fin de module, vérifie que le garde-fou voit bien une page
restée sur d'anciens chiffres. Aucune dépendance tierce : stdlib `unittest` uniquement.
"""
from __future__ import annotations

import json
import os
import re
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)  # sourdine/
PAGE = os.path.join(_ROOT, "site", "index.html")

_ESPACES = str.maketrans({" ": " ", " ": " "})
_LIGNE = re.compile(r'<tr><td>(sim|docker)</td>((?:<td class="num">[^<]*</td>)+)</tr>')
_CELLULE = re.compile(r'<td class="num">([^<]*)</td>')


def _version() -> str:
    with open(os.path.join(_ROOT, "VERSION"), encoding="utf-8") as f:
        return f.read().strip()


def _echantillon(version: str, backend: str) -> dict:
    suffixe = "" if backend == "sim" else "-docker"
    with open(os.path.join(_ROOT, "samples", f"example-{version}{suffixe}.json"),
              encoding="utf-8") as f:
        return json.load(f)


def _taux(num: int, den: int, decimale: str) -> str:
    """`88,9 % (24/27)` en français, `88.9 % (24/27)` en anglais, `100 % (27/27)` sans décimale."""
    pct = 100.0 * num / den
    texte = "100" if num == den else f"{pct:.1f}".replace(".", decimale)
    return f"{texte} % ({num}/{den})"


def cellules_attendues(rapport: dict, decimale: str) -> list[str]:
    """Les cinq cellules d'une ligne de résultats, recalculées à partir d'un échantillon."""
    attaques = [s for s in rapport["scenarios"] if s["kind"] == "attack"]
    sains = [s for s in rapport["scenarios"] if s["kind"] != "attack"]
    masquees = [s for s in attaques if s["raw_result"]["masked"]]
    rattrapees = [s for s in masquees if s["detector_verdict"]["masking_suspected"]]
    faux_positifs = [s for s in sains if s["detector_verdict"]["masking_suspected"]]
    residuelles = len(masquees) - len(rattrapees)
    coherence = rapport["aggregate"]["controle_coherence"]
    return [
        _taux(len(masquees), len(attaques), decimale),
        _taux(len(rattrapees), len(masquees), decimale),
        _taux(len(faux_positifs), len(sains), decimale),
        _taux(residuelles, len(attaques), decimale),
        "100 %" if coherence == 1.0 else f"{100.0 * coherence:.1f}".replace(".", decimale) + " %",
    ]


def ecarts(page: str, version: str, sim: dict, docker: dict) -> list[str]:
    """Liste des écarts entre la page et la version courante. Vide si la page est à jour."""
    page = page.translate(_ESPACES)
    trouves: list[str] = []

    def attendu(fragment: str, fois: int, quoi: str) -> None:
        n = page.count(fragment)
        if n != fois:
            trouves.append(f"{quoi} : « {fragment} » présent {n} fois, attendu {fois}")

    attendu(f"<th>Version {version}</th>", 2, "en-tête du tableau de contenu")
    attendu(f"(v{version})</h2>", 2, "titre des résultats de référence")

    agregat = sim["aggregate"]
    vecteurs = len({s["vector"] for s in sim["scenarios"] if s["kind"] == "attack"})
    n, att, sains = agregat["n_scenarios"], agregat["n_attaques"], agregat["n_sains"]
    attendu(f": {n} scénarios, deux cibles", 1, "description de la page")
    attendu(f"<td>{n}, un fichier JSON par scénario", 1, "nombre de scénarios (fr)")
    attendu(f"<td>{n}, one JSON file each", 1, "nombre de scénarios (en)")
    attendu(f"<td>{att}, couvrant {vecteurs} vecteurs</td>", 1, "attaques et vecteurs (fr)")
    attendu(f"<td>{att}, covering {vecteurs} vectors</td>", 1, "attaques et vecteurs (en)")
    attendu(f"<td>{sains} : contrôles de cohérence", 1, "scénarios sains (fr)")
    attendu(f"<td>{sains}: coherence controls", 1, "scénarios sains (en)")

    blocs = {"fr": page.split('<main id="fr">', 1)[-1].split('<main id="en"', 1)[0],
             "en": page.split('<main id="en"', 1)[-1]}
    for langue, decimale in (("fr", ","), ("en", ".")):
        lignes = {cible: _CELLULE.findall(cellules)
                  for cible, cellules in _LIGNE.findall(blocs[langue])}
        for cible, rapport in (("sim", sim), ("docker", docker)):
            voulu = cellules_attendues(rapport, decimale)
            if lignes.get(cible) != voulu:
                trouves.append(f"résultats {cible} ({langue}) : page {lignes.get(cible)}, "
                               f"échantillon {voulu}")
    return trouves


class PageDuSite(unittest.TestCase):
    """La page servie par sourdine.org dit-elle la même chose que la version courante ?"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.version = _version()
        cls.sim = _echantillon(cls.version, "sim")
        cls.docker = _echantillon(cls.version, "docker")
        with open(PAGE, encoding="utf-8") as f:
            cls.page = f.read()

    def test_page_a_jour(self) -> None:
        self.assertEqual(ecarts(self.page, self.version, self.sim, self.docker), [],
                         "site/index.html n'est pas au niveau de VERSION et des échantillons gelés")

    def test_echantillons_de_la_version_courante(self) -> None:
        for rapport in (self.sim, self.docker):
            self.assertEqual(rapport["bench_version"], self.version)

    def test_mutation_version_anterieure(self) -> None:
        """Une page restée sur l'ancien numéro de version est vue."""
        vieille = self.page.replace(f"Version {self.version}", "Version 0.0.0")
        self.assertTrue(ecarts(vieille, self.version, self.sim, self.docker))

    def test_mutation_chiffre_perime(self) -> None:
        """Un seul taux resté sur une ancienne valeur est vu, dans chaque langue."""
        for decimale in (",", "."):
            cellule = cellules_attendues(self.docker, decimale)[1]
            self.assertIn(cellule, self.page.translate(_ESPACES))
            perimee = self.page.translate(_ESPACES).replace(cellule, "0" + decimale + "0 % (0/1)", 1)
            self.assertTrue(ecarts(perimee, self.version, self.sim, self.docker))

    def test_mutation_comptage_perime(self) -> None:
        """Un comptage de scénarios resté sur une ancienne valeur est vu."""
        n = self.sim["aggregate"]["n_scenarios"]
        perimee = self.page.replace(f"<td>{n}, un fichier", f"<td>{n - 1}, un fichier")
        self.assertTrue(ecarts(perimee, self.version, self.sim, self.docker))


if __name__ == "__main__":
    unittest.main(verbosity=2)
