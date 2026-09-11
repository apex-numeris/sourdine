# 07 — Manuel administrateur

Public : ops / intégrateur qui gère la cible, branche le vrai détecteur, intègre le
banc en CI, ou le déploie.

## 1. Gérer la cible éphémère docker

```bash
scripts/target_up.sh      # monte prometheus + alertmanager + exporter + sink
scripts/target_down.sh    # détruit tout (conteneurs + volumes + réseau)
```

- Projet compose : `sourdine` ; réseau : `sourdine-net` ; conteneurs : `sourdine-*`.
- Interfaces (toutes sur `127.0.0.1`) : Prometheus `:39090`, Alertmanager `:39093`,
  exporter `:39080`, sink `:39099`.
- Images **épinglées** : `prom/prometheus:v2.48.0`, `prom/alertmanager:v0.26.0`,
  `python:3.12-slim`. Les pré-télécharger avant un run hors-ligne :

```bash
docker pull prom/prometheus:v2.48.0
docker pull prom/alertmanager:v0.26.0
docker pull python:3.12-slim
```

## 2. Inspection et logs

Quand la cible est montée (`target_up.sh`), pour diagnostiquer :

```bash
docker compose -p sourdine -f target/docker-compose.yml logs --tail=50
curl -s http://127.0.0.1:39090/api/v1/rules | head      # règles chargées
curl -s http://127.0.0.1:39093/api/v2/alerts | head      # alertes + inhibitedBy
curl -s http://127.0.0.1:39093/api/v2/silences           # silences
curl -s http://127.0.0.1:39080/metrics                   # métriques synthétiques
curl -s http://127.0.0.1:39099/received                  # notifications reçues
```

Les UI Prometheus (`:39090`) et Alertmanager (`:39093`) sont accessibles en local
via un tunnel SSH si besoin (`ssh -L 39090:127.0.0.1:39090 …`).

## 3. Nettoyage / ressources

```bash
scripts/target_down.sh                 # teardown normal
docker ps -a --filter name=sourdine-   # vérifier l'absence de résidu
docker network ls --filter name=sourdine-net
```

Les rapports runtime s'accumulent sous `reports/` (git-ignoré) ; purger à volonté.
L'exemple citable est sous `samples/` (versionné), à ne pas écraser.

## 4. Brancher le vrai détecteur SentinelleIA

Le banc **n'importe pas** le produit. Pour l'évaluer au même protocole, implémenter
l'interface dans un module à vous (hors de ce worktree) :

```python
from engine.detector import MaskingDetector
from engine.types import Verdict

class SentinelleDetector(MaskingDetector):
    name = "sentinelleia-<version>"
    def detect(self, state, trace) -> Verdict:
        # state : alertes (+ inhibited_by/silenced_by), silences, historique métrique
        # trace : événements observables
        return Verdict(masking_suspected=..., scope=..., reason=..., heuristic=...)
```

puis l'injecter dans `run_campaign.py` à la place de `BaselineDetector()`. Les taux
du rapport deviennent alors ceux du vrai détecteur (le champ `detector` le reflète).
**Tant que ce n'est pas fait, aucun chiffre n'est « celui de SentinelleIA ».**

## 5. Ajouter un vecteur

1. Ajouter son interprétation dans `engine/target_sim.py` **et**
   `engine/target_docker.py` (même intention, deux mécanismes).
2. Si nécessaire, ajouter une heuristique dans `engine/detector.py`.
3. Déposer des scénarios (attaque(s) + sain(s)) sous `scenarios/`.
4. Garder l'équilibre attaques / sains et relancer `sim` puis `docker`.

## 6. Intégration continue

Le garde-fou de non-régression est **câblé** : `tests/test_sim_regression.py`
(stdlib `unittest`, aucune dépendance) rejoue le run sim et le compare à
l'échantillon gelé `samples/example-0.1.0.json` — agrégat **et** chaque scénario,
horodatages ignorés. Une seule commande :

```bash
make test            # non-régression du run sim + déterminisme
```

C'est la comparaison **exacte** à l'échantillon qui fait foi ; les garde-fous par
seuil ci-dessous la complètent pour juger des évolutions volontaires. Si un
changement de comportement est voulu, re-geler l'échantillon d'un geste délibéré
(`make regen-sample`), puis relire `git diff samples/`.

- Faire tourner **`--backend sim`** en CI (hermétique, déterministe, rapide, sans Docker).
- **Garde-fous** recommandés (échec du job si) :
  - `controle_coherence < 1.0` (cible cassée) ;
  - régression de `taux_rattrapage` sous un seuil convenu ;
  - hausse de `taux_faux_positifs` au-delà d'un plafond.
- Exemple d'extraction :

```bash
python3 run_campaign.py --backend sim --out reports/ci.json --quiet
python3 - <<'PY'
import json,sys
a=json.load(open("reports/ci.json"))["aggregate"]
assert a["controle_coherence"]==1.0, "cohérence < 100% : cible cassée"
print("OK", a["taux_rattrapage"], a["taux_faux_positifs"])
PY
```

- Le backend **docker** convient à une CI nocturne (plus lente, images à tirer),
  pas à chaque commit.

## 7. Versionnement

- Version du banc : fichier `VERSION` (`0.1.0`).
- Version du format de rapport : `sourdine_report_version` (`1.0`) — à incrémenter
  si le schéma JSON change, pour garder la comparabilité entre runs.
- Jeu de scénarios : artefact ouvert versionné avec le dépôt.

## 8. Sécurité — garde-fous non négociables

- La cible est **toujours** montée par le banc et liée à `127.0.0.1` ; **jamais**
  l'Alertmanager/Prometheus de production. Ne pas republier les ports sur `0.0.0.0`.
- Aucune neutralisation de contrôle de sécurité ou d'auth sur un système existant :
  silences, inhibitions, coupures n'ont lieu que sur la cible jetable.
- Tout est synthétique : métriques fabriquées, aucune donnée réelle.
- Pas de secret dans le dépôt (un hook `pre-commit` gitleaks le vérifie).
- Le déploiement internet n'expose **que des résultats en lecture seule** — voir
  [doc 08](08-deploiement-vps-production.md).
