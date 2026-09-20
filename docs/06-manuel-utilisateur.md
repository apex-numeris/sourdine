# 06. Manuel utilisateur

Public : toute personne qui **lance le banc** et **lit les résultats**.

## 1. Pré-requis

- **Python ≥ 3.10** (aucune dépendance tierce, bibliothèque standard).
- Pour le backend fidélité : **Docker** + **docker compose v2**.

## 2. Installation

Le banc est autonome ; il n'y a rien à installer avec `pip`.

```bash
cd sourdine          # racine du dépôt cloné
python3 run_campaign.py --help
```

## 3. Lancer une campagne

### Cible sim (défaut, déterministe, aucun conteneur)

```bash
python3 run_campaign.py
```

### Cible docker (vrais Prometheus + Alertmanager éphémères)

```bash
python3 run_campaign.py --backend docker
```

Le banc **monte lui-même** sa cible jetable et la **détruit** à la fin (y compris
en cas d'erreur). La première exécution docker télécharge les images
(`prom/prometheus`, `prom/alertmanager`, `python:3.12-slim`).

Options utiles : `--out reports/ma-campagne.json`, `--quiet`,
`--scenarios <dir>`.

## 4. Lire les résultats

À la fin, un résumé s'affiche et un rapport JSON est écrit dans `reports/`
(+ `reports/latest.json`). Exemple de résumé :

```
  Taux                         valeur   sous-ensemble / preuve
  Suppression réussie         100.0%   attaques sans détecteur — danger client
  Rattrapage                   75.0%   parmi masquées — valeur produit
  Faux positifs                33.3%   scénarios sains — coût opérationnel
  Suppression résiduelle       25.0%   attaques non rattrapées — honnêteté
  Contrôle de cohérence       100.0%   cas graves sains — doit approcher 100%
```

### Comment interpréter

| Taux | À lire comme |
|---|---|
| **Suppression réussie** | Part des attaques qui masquent l'alarme **sans** détecteur. Élevé = grand danger si rien ne protège la chaîne d'alerte. |
| **Rattrapage** | Part des masquages que le détecteur repère. Plus c'est haut, plus le détecteur a de la valeur. |
| **Faux positifs** | Part des scénarios **sains** où le détecteur crie au masquage à tort. C'est le coût opérationnel. |
| **Suppression résiduelle** | Part des attaques qui passent **malgré** le détecteur. C'est l'honnêteté du chiffrage. |
| **Contrôle de cohérence** | Doit approcher **100 %**. En dessous, la cible est cassée et les autres taux ne veulent rien dire : ne pas exploiter la campagne. |

La **ventilation par niveau d'accès attaquant** indique contre quel profil
d'attaquant le masquage réussit (ex. un attaquant sans accès superviseur, qui ne
connaît que les seuils, vs un attaquant avec l'API des silences).

Le détail par scénario montre, pour chaque ligne : `masquée` (oui/—) et, pour les
attaques, `rattrap.` (oui/NON) ; pour les sains, `ok`/`FP`.

### Lire le JSON

Le rapport machine porte un `sourdine_report_version` (comparaison entre runs), le
`target_backend`, l'`aggregate` (les taux + la ventilation) et le détail
`scenarios`. Schéma complet : [doc 05 §6](05-specifications.md#6-schéma-du-rapport-json-versionné).

## 5. Ajouter un scénario

Déposer un JSON dans `scenarios/attacks/` ou `scenarios/healthy/` en suivant
[`scenarios/SCHEMA.md`](../scenarios/SCHEMA.md). Règles d'or :

- renseigner `ground_truth` (alarme attendue ? laquelle ? sur quels labels) ;
- choisir le `vector` et l'`access_level` ;
- **équilibrer** attaques et sains (sinon les taux perdent leur sens) ;
- pour un **nouveau** vecteur, voir le [manuel admin](07-manuel-administrateur.md)
  (interprétation à ajouter dans les cibles + éventuelle heuristique).

## 6. Dépannage

| Symptôme | Cause probable | Remède |
|---|---|---|
| `backend inconnu` | valeur `--backend` hors `sim`/`docker` | corriger l'option |
| `Cible docker non prête` | daemon Docker absent / images non téléchargées / ports occupés | `docker info`, pré-`docker pull`, vérifier que `127.0.0.1:39090/39093/39080/39099` sont libres |
| Contrôle de cohérence < 100 % | cible cassée (règles mal chargées, timing docker) | relancer ; en docker, augmenter la décantation (cf. admin) ; préférer `sim` pour un chiffrage reproductible |
| Taux docker ≠ taux sim | comportement réel d'Alertmanager (groupement, timing) | normal, cf. [constats de fidélité](04-architecture-technique.md#7-constats-de-fidélité-sim--docker-attendus-et-documentés) ; la **sim est la référence déterministe** |
| Conteneurs `sourdine-*` restants | campagne interrompue brutalement | `scripts/target_down.sh` |

## 7. Bon usage

- Pour un **chiffre reproductible et citable**, utilisez `sim`.
- Pour **valider le comportement réel**, utilisez `docker`.
- Le banc évalue une **baseline**. Un résultat n'est « celui de SentinelleIA » que
  lorsque le vrai détecteur est branché (cf. admin), jamais avant.
