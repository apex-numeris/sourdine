# Journal des modifications

Format inspiré de Keep a Changelog. Règle de numérotation : MAJEURE si le format de rapport
ou le protocole de mesure change, MINEURE si des scénarios entrent ou sortent, CORRECTIF si
les chiffres publiés ne bougent pas. Chaque version publiée regèle les deux échantillons
(`samples/`) et reçoit un DOI de version sous le DOI de concept
[10.5281/zenodo.22900756](https://doi.org/10.5281/zenodo.22900756).

## 1.1.0 (non publiée)

Version mineure : un scénario entre, la ligne de base est corrigée, l'interface du détecteur
est fermée. Le format de rapport et le protocole de mesure (deux passes, quatre taux) ne
changent pas. Le fichier `VERSION` porte désormais le numéro de release : il valait `0.14.0`
pour la release 1.0.0.

Chiffres de la ligne de base `baseline-heuristic-v1`, avant et après :

| Backend | Version | Suppression réussie | Rattrapage | Faux positifs | Suppression résiduelle | Cohérence |
|---|---|---|---|---|---|---|
| sim | 1.0.0 | 100 % (26/26) | 84,6 % (22/26) | 9,5 % (2/21) | 15,4 % (4/26) | 100 % |
| sim | 1.1.0 | 100 % (27/27) | 85,2 % (23/27) | 4,8 % (1/21) | 14,8 % (4/27) | 100 % |
| docker | 1.0.0 | 88,5 % (23/26) | 82,6 % (19/23) | 9,5 % (2/21) | 15,4 % (4/26) | 100 % |
| docker | 1.1.0 | 88,9 % (24/27) | 83,3 % (20/24) | 4,8 % (1/21) | 14,8 % (4/27) | 100 % |

Sur les 26 attaques de la version 1.0.0, aucun résultat ne bouge, dans aucun des deux
backends. L'attaque ajoutée est masquée et rattrapée par construction : elle explique à elle
seule la hausse du rattrapage. La baisse des faux positifs vient de la correction de la ligne
de base décrite ci-dessous.

### Corrigé

- Ligne de base, heuristique `silence_abuse` : la branche « silence étroit posé pendant une
  montée d'activité » ne regardait pas la classe de l'alerte visée, à la différence des trois
  heuristiques voisines (`notification_blackhole`, `rogue_inhibitor`,
  `silenced_under_threat`). Elle signalait donc tout silence de maintenance posé pendant que
  le trafic vivait, et ne rattrapait aucune attaque du catalogue. Elle exige maintenant que
  le silence vise une alerte de sécurité. Le faux positif `HLT-BENIGN-SILENCE-03`, présent
  depuis la version 0.1.0, disparaît.
- Interface du détecteur : jusqu'à la version 1.0.0, `detect(state, trace)` recevait le
  récit que la cible tient de sa propre manœuvre (des événements nommés par le scénario),
  et l'état portait un identifiant de silence choisi par scénario (`sil-atk`, `sil-ops`)
  ainsi que, en docker, un commentaire de silence variable. Mesuré sur le catalogue 1.0.0 :
  un détecteur qui ne lisait que les types d'événements de ce récit séparait 24 attaques
  sur 26 sans aucun faux positif, sans rien observer de la chaîne d'alerte. La ligne de base
  ne lisait rien de tout cela, ses taux publiés n'en dépendaient pas (vérifié en lui
  retirant la trace). Le détecteur reçoit maintenant `observable_trace(state)`, calculée à
  partir de l'état seul. Les identifiants de silence sont opaques et le commentaire est
  constant. La signature de l'interface ne change pas. Un détecteur tiers qui lisait le
  récit doit s'en passer : c'est une rupture voulue.
- Noms de l'état : deux noms inventés par le banc décrivaient la manœuvre. La source de la
  règle d'inhibition ajoutée par l'attaquant s'appelait `RogueMuter`, et les alertes sœurs
  de la noyade par groupement portaient les instances `flood-0` à `flood-19`. Elles
  deviennent `MaintenanceWindow` et `fw-2` à `fw-21`, en sim comme en docker. Le test de
  non-fuite garde désormais ce vocabulaire : aucun nom qui décrive la manœuvre, et une liste
  fermée et commentée des mots que seules des attaques portent. Aucun verdict ne change.
- Cible sim : l'étiquette de la source d'inhibition était mal formée dans l'état et dans les
  rapports (`FirewallDown[ob=firewall}` au lieu de `FirewallDown[job=firewall]`). Sans effet
  sur les verdicts, qui n'en lisent que le préfixe.
- Paire `ATT-STATISTICAL-REPLAY-18` / `HLT-BENIGN-NOISE-13` : la description annonçait deux
  séries identiques alors que les moyennes différaient (21 et 16). Le scénario sain prend la
  moyenne 21 : les deux états observables sont maintenant strictement identiques, comme
  annoncé. Aucun verdict ne change.
- Six libellés de verdict de la ligne de base réécrits sans tiret cadratin (champ `reason`
  des rapports, sans effet sur les verdicts).

### Modifié

- Cible docker : images épinglées montées en `prom/prometheus:v3.13.5` (ligne LTS,
  maintenue jusqu'au 31 juillet 2027) et `prom/alertmanager:v0.35.0`, à la place de
  `v2.48.0` (ligne 2.x hors support depuis juillet 2025, quatre avis de sécurité publiés
  en avril 2026 : CVE-2026-42154, CVE-2026-42151, CVE-2026-40179 et CVE-2026-44903, aucun
  atteignable dans l'usage du banc) et de `v0.26.0` (août 2023). Quatre étapes : `v3.13.3`
  et `v0.34.1` le 21 octobre 2026, `v3.13.4` le même jour (pull request Dependabot #1),
  `v3.13.5` et `v0.34.2` le 12 novembre 2026 (pull request Dependabot #2), `v0.35.0` dans
  cette version (pull request Dependabot #4). Alertmanager
  0.34.2 corrige l'avis GHSA-w5g2-x24w-p3fq du 29 octobre 2026 : jusqu'à la version 0.34.1,
  l'API v2 acceptait les requêtes de toute origine, si bien qu'une page web ouverte dans un
  navigateur capable d'atteindre un Alertmanager sans authentification pouvait créer des
  alertes et des silences. Le banc pilote la cible sans navigateur, la correction ne change
  donc rien pour lui. Configurations de la cible inchangées. À chaque étape, campagne docker
  complète rejouée sur les nouvelles images : les cinq taux publiés sont identiques à
  l'échantillon gelé `samples/example-0.14.0-docker.json` et aucun scénario ne change de
  résultat.
- Backend docker (7 octobre 2026, commit 5b62ee5) : isolation des scénarios (le sink se
  vide en fin de remise à zéro, une fois Alertmanager sans alerte active) et fenêtre
  d'observation calculée depuis la configuration de la cible (portée de 12 à 16 s).
  Corrige l'échec de la campagne hebdomadaire du 5 octobre 2026 (ATT-ROUTE-BLACKHOLE-20
  lu non masqué par fuite de l'alerte du scénario précédent). Chiffres publiés inchangés.
- Intégration continue : rapport de campagne en artefact, résumé et annotations lisibles
  sans ouvrir les journaux, runner épinglé `ubuntu-24.04`, actions `checkout` et
  `setup-python` en v7. Depuis le 12 novembre 2026, la campagne docker tourne aussi sur
  chaque pull request qui touche la cible ou le backend docker, et le run sim est rejoué
  sur Python 3.10, 3.12, 3.13, 3.14 et 3.15.
- Échantillons gelés : `samples/example-1.1.0.json` et `samples/example-1.1.0-docker.json`
  (ce dernier sur Prometheus 3.13.5 et Alertmanager 0.35.0). Les échantillons 0.14.0, ceux
  de la version 1.0.0, restent en place.

### Ajouté

- Scénario `ATT-SILENCE-NARROW-27` (vecteur `silence_abuse`) : silence étroit, à `alertname`
  littéral, posé sur une alerte de sécurité pendant la montée de l'attaque. C'est le pendant
  d'attaque du scénario sain `HLT-BENIGN-SILENCE-03`. Le catalogue passe à 48 scénarios
  (27 attaques sur 22 vecteurs, 21 sains).
- `tests/test_interface_leak.py` : garde l'étanchéité de l'interface du détecteur, avec
  preuve par mutation (le même contrôle, nourri de l'ancien récit, voit la fuite).
- `tests/test_twin_pairs.py` : vérifie les deux paires indiscernables (04 / 05 et 18 / 13,
  états strictement identiques en simulation) et la paire discriminante (27 / 03).
- Documentation des paires jumelles (README, fiche, `scenarios/SCHEMA.md`). Le faux positif
  restant, `HLT-BENIGN-SPIKE-05`, est irréductible pour un détecteur limité à la chaîne
  d'alerte : son état est identique à celui de l'attaque `ATT-LOW-SLOW-CATCHABLE-04`.
- `SECURITY.md` : périmètre, voies de signalement, engagements de délai.
- `.github/dependabot.yml` : surveillance des actions GitHub (mensuelle) et des images de la
  cible (hebdomadaire depuis le 12 novembre 2026 : ajouté au délai de carence de trois jours
  que Dependabot applique par défaut, le passage mensuel avait laissé passer Alertmanager
  0.34.2). Correctifs seulement sur la ligne LTS de Prometheus. Exporter et sink restent
  sur la ligne Python 3.12, maintenue jusqu'au 31 octobre 2028.
- Ce journal.

## 1.0.0 (22 septembre 2026)

Première version publique. 47 scénarios étiquetés (26 attaques sur 22 vecteurs, 21 sains),
ligne de base `baseline-heuristic-v1` (16 heuristiques), mesure en deux passes et quatre
taux, cibles sim et docker, échantillons gelés 0.14.0, documentation `docs/01` à `docs/08`,
fiche `DATASHEET.md`, porte d'entrée anglaise. Code sous Apache 2.0, scénarios, échantillons
et documentation sous CC BY 4.0. DOI de version
[10.5281/zenodo.22900757](https://doi.org/10.5281/zenodo.22900757).
