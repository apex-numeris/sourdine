# Journal des modifications

Format inspiré de Keep a Changelog. Règle de numérotation : MAJEURE si le format de rapport
ou le protocole de mesure change, MINEURE si des scénarios entrent ou sortent, CORRECTIF si
les chiffres publiés ne bougent pas. Chaque version publiée regèle les deux échantillons
(`samples/`) et reçoit un DOI de version sous le DOI de concept
[10.5281/zenodo.22900756](https://doi.org/10.5281/zenodo.22900756).

## Non publié

### Modifié

- Cible docker : images épinglées montées en `prom/prometheus:v3.13.4` (ligne LTS,
  maintenue jusqu'au 31 juillet 2027, correctif de sécurité du 2 octobre 2026 pris par la
  pull request Dependabot #1, campagne rejouée sur cette version avec le même résultat) et `prom/alertmanager:v0.34.1`, à la place de
  `v2.48.0` (ligne 2.x hors support depuis juillet 2025, quatre avis de sécurité publiés
  en avril 2026 : CVE-2026-42154, CVE-2026-42151, CVE-2026-40179 et CVE-2026-44903, aucun
  atteignable dans l'usage du banc) et de `v0.26.0` (août 2023). Configurations de la cible
  inchangées. Campagne docker complète rejouée sur les nouvelles images : les cinq taux
  publiés sont identiques à l'échantillon gelé `samples/example-0.14.0-docker.json` et
  aucun scénario ne change de résultat.
- Backend docker (7 octobre 2026, commit 5b62ee5) : isolation des scénarios (le sink se
  vide en fin de remise à zéro, une fois Alertmanager sans alerte active) et fenêtre
  d'observation calculée depuis la configuration de la cible (portée de 12 à 16 s).
  Corrige l'échec de la campagne hebdomadaire du 5 octobre 2026 (ATT-ROUTE-BLACKHOLE-20
  lu non masqué par fuite de l'alerte du scénario précédent). Chiffres publiés inchangés.
- Intégration continue : rapport de campagne en artefact, résumé et annotations lisibles
  sans ouvrir les journaux, runner épinglé `ubuntu-24.04`, actions `checkout` et
  `setup-python` en v7.

### Ajouté

- `SECURITY.md` : périmètre, voies de signalement, engagements de délai.
- `.github/dependabot.yml` : surveillance mensuelle des actions GitHub et des images de la
  cible (correctifs seulement sur la ligne LTS de Prometheus).
- Ce journal.

## 1.0.0 (22 septembre 2026)

Première version publique. 47 scénarios étiquetés (26 attaques sur 22 vecteurs, 21 sains),
ligne de base `baseline-heuristic-v1` (16 heuristiques), mesure en deux passes et quatre
taux, cibles sim et docker, échantillons gelés 0.14.0, documentation `docs/01` à `docs/08`,
fiche `DATASHEET.md`, porte d'entrée anglaise. Code sous Apache 2.0, scénarios, échantillons
et documentation sous CC BY 4.0. DOI de version
[10.5281/zenodo.22900757](https://doi.org/10.5281/zenodo.22900757).
