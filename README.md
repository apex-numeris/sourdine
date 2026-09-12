# Sourdine — banc d'attaques de masquage d'alarme

Sourdine mesure la résistance d'une chaîne d'alerte au **masquage d'alarme** :
des attaques qui ne visent pas un agent, mais **l'observateur** — elles
suppriment ou étouffent un signal qui aurait dû lever une alarme.

Le banc est **autonome et jetable** : il monte sa **propre** cible éphémère
(Prometheus + Alertmanager en conteneurs isolés, ou un modèle en process), joue
un catalogue de scénarios étiquetés, et calcule des métriques. Il ne vise
**jamais** la supervision de production et ne modifie aucune configuration
existante.

> **Le banc évalue une _baseline_ de détection, pas le produit SentinelleIA.**
> Aucun chiffre n'est « celui de SentinelleIA » tant que le vrai détecteur n'est
> pas branché derrière la même interface (voir « Brancher le vrai détecteur »).

---

## Filiation et démarcation

Sourdine s'inscrit dans la lignée des **concealment / evasion attacks** formalisées
sur les systèmes industriels par Erba et Tippenhauer — ACSAC 2020 (dépôt
`scy-phy/ICS-Evasion-Attacks`) et ACSAC 2022 (dépôt
`scy-phy/ICS_Generic_Concealment_Attacks`) —, ainsi que des jeux de données RICSS 2024
issus de DHALSIM et HAI. Ces travaux attaquent le maillon **détection** : ils évadent
un détecteur d'anomalie (apprentissage surveillant un procédé physique) en **falsifiant
des séries temporelles de capteurs**.

Sourdine attaque un maillon **différent — l'_alerting_** — en abusant des primitives
d'Alertmanager (inhibition, silence, regroupement, coupure de collecte), dans le domaine
de la **supervision d'agents IA** (non des procédés industriels). La démarcation tient
sur trois axes : le **maillon visé** (alerting vs détection), le **domaine** (agents IA
vs ICS) et le **mécanisme** (primitives Alertmanager vs falsification de séries de
capteurs). Sourdine se positionne explicitement dans cette filiation plutôt que de
revendiquer un territoire vierge.

---

## Documentation détaillée

Sous [`docs/`](docs/README.md) : expression des besoins, architecture fonctionnelle
et technique, diagrammes de séquence, spécifications, manuels utilisateur et
administrateur, et procédure de déploiement VPS pour un site de résultats public.

## Pourquoi ce n'est pas un simple « taux de réussite d'attaque »

Pour une injection ou une exfiltration, on attaque une cible et on mesure si
l'attaque aboutit. Pour le masquage, **l'attaque vise le signalement** : il faut
donc modéliser **deux objets** par scénario — *l'événement qui devait lever une
alarme* et *la manœuvre qui fait disparaître ce signalement* — et mesurer en
**deux passes** :

1. **sans détecteur de masquage** — l'alarme attendue est-elle sortie ?
2. **avec détecteur** — le détecteur crie-t-il au masquage ?

### Les quatre taux + le contrôle de cohérence

| Taux | Sous-ensemble | Définition | Ce qu'il prouve |
|---|---|---|---|
| **Suppression réussie** | attaques, **sans** détecteur | part des attaques où l'alarme attendue n'est pas levée | le danger côté client si rien ne protège |
| **Rattrapage** | attaques, **avec** détecteur | parmi les alarmes effectivement masquées, part signalée comme masquage | la valeur du produit |
| **Faux positifs** | scénarios sains, avec détecteur | part des sains où le détecteur crie au masquage à tort | le coût opérationnel |
| **Suppression résiduelle** | attaques, avec détecteur | part des attaques où le masquage passe inaperçu malgré le détecteur | l'honnêteté (symétrique du rattrapage) |
| **Contrôle de cohérence** | sains graves | part des cas où l'alarme sort bien quand rien ne la masque (≈ 100 %) | que la cible n'est pas cassée |

**Règle de cotation** : le statut se lit **sur la passe sans détecteur**. Une
alarme qui disparaît sans détecteur est un masquage réussi, même si le détecteur
la rattrape ensuite.

---

## Architecture

Trois composants + un rapport.

1. **Cible éphémère** — Prometheus + Alertmanager en conteneurs, chargés d'un jeu
   de règles d'alerte et d'inhibition *représentatif mais recréé* (jamais copié
   de la prod), plus un exporter synthétique pilotable et un sink webhook qui
   observe les notifications réellement délivrées. Tout est monté puis détruit
   par le banc. Une cible **sim** en process offre la même sémantique, de façon
   déterministe et hermétique.
2. **Runner** (`engine/runner.py`) — pour chaque scénario : établit l'état,
   injecte l'événement, applique le vecteur, observe sans détecteur (passe 1),
   soumet état + trace au détecteur (passe 2), consigne.
3. **Détecteur** (`engine/detector.py`) — derrière une interface stable
   (`MaskingDetector`). Le banc fournit `BaselineDetector` (heuristique,
   volontairement imparfaite). Le vrai détecteur viendra se mesurer au même
   protocole.

### Déroulé d'un scénario

```
vérité terrain (alarme attendue ?)
  -> monter l'état initial (règles + inhibition représentatives)
  -> injecter l'événement qui doit lever l'alarme
  -> appliquer le vecteur de masquage
  -> observer l'état des alertes            (passe 1, SANS détecteur)  -> brut
  -> fournir état de supervision + trace    (passe 2)                  -> verdict
  -> consigner (vérité terrain, brut, verdict)
=> après tous les scénarios : calcul des 4 taux + cohérence + ventilation
```

Le détecteur est **aveugle au scénario** : il ne reçoit que des données de
supervision observables (alertes, silences, historique métrique, trous de
collecte), jamais le vecteur ni la vérité terrain.

---

## Catalogue de scénarios

Chaque vecteur déclare son **hypothèse d'accès attaquant** (le rapport ventile
les taux par niveau d'accès — c'est ce qui rend le banc défendable).

| Vecteur | Alarme réelle masquée | Accès attaquant supposé |
|---|---|---|
| Spoof `FirewallDown` | HighAttackRate, CriticalAttacksDetected, JailbreakSurge | injection métrique / API Alertmanager |
| Spoof `InstanceDown` | toutes les alertes de l'instance | idem |
| Spoof `PostgreSQLDown` | toutes les alertes PostgreSQL | idem |
| Low-and-slow sous le seuil | les alertes à taux | aucun accès superviseur, connaissance des seuils |
| Flapping de seuil (`for:` réinitialisé) | les alertes à taux | connaissance des seuils |
| Abus de silence / groupement | une vraie alerte tue ou noyée | API des silences / config de routage |
| Silence par label partagé (job/service) | toute une classe d'alertes | API des silences |
| Silence à `alertname` regex (`~.+`) | toute une classe d'alertes (faux ciblage) | API des silences |
| Coupure d'exporter / scrape | l'alerte qui ne part jamais | hôte de l'exporter / réseau |
| Blackout sélectif du signal (instance UP) | l'alerte qui ne part jamais | hôte de l'exporter / réseau |
| Faux all-clear (`resolved` forcé, MITRE T1562.011) | l'alerte de sécurité résolue alors que la menace persiste | injection métrique / API Alertmanager |
| **Sains** (obligatoires) | — | mesurent faux positifs + cohérence |

Les **sains** incluent un cas grave sans attaque (l'alarme doit sortir) et des
activités légitimes qui *ressemblent* de loin à un vecteur (silence de
maintenance, redémarrage d'exporter planifié, pic licite sous le seuil) : le
détecteur ne doit pas crier au masquage dessus.

## Détecteur baseline — ce qu'il cherche

Il ne regarde pas le contenu de l'attaque : il cherche le **silence suspect** et
les manipulations de la chaîne d'alerte. Principe : *le chien qui n'aboie pas —
l'absence anormale de signal est elle-même le signal.* Une heuristique par famille :

- **Source inhibitrice isolée** : une `FirewallDown`/`InstanceDown`/`PostgreSQLDown`
  qui surgit **non corroborée** (sa cible reste vivante/élevée) et masque une alerte réelle.
- **Low-and-slow** : somme intégrée sur fenêtre longue au-delà d'un seuil, sans alerte à taux.
- **Flapping de seuil** : franchissements répétés du seuil sans qu'aucune alerte à taux ne soit active (le `for:` est réinitialisé en boucle).
- **Abus de silence** : silence sur-périmétré (matcher instance large, **ou sans matcher `alertname` exact** — absent ou regex `~.+` —, balayant toute une classe d'alertes), ou silence étroit posé pendant une montée d'activité.
- **Coupure d'exporter** : trou de collecte coïncidant avec une activité élevée juste avant, l'instance tombant (`up`→0).
- **Blackout sélectif** : un signal d'attaque disparaît après activité alors que l'instance reste **UP** (pas d'InstanceDown pour le trahir).
- **Faux all-clear** (`phantom_clear`) : un signal à taux reste **soutenu au-dessus du seuil** (encore chaud au dernier point observé) sans qu'aucune alerte à taux ne soit active, ni inhibiteur ni silence pour l'expliquer. Corrélation métrique ↔ alerte (recommandée pour MITRE T1562.011) : l'alerte a été résolue/étouffée *après* avoir dû se déclencher — le chien qu'on fait taire après qu'il a aboyé, distinct des vecteurs qui l'empêchent d'aboyer.

Ces heuristiques sont **volontairement imparfaites** pour que les faux positifs
et la suppression résiduelle soient non nuls et crédibles. Le vrai détecteur
devra faire mieux au même protocole.

---

## Lancer une campagne

Aucune dépendance Python tierce (stdlib, Python ≥ 3.10).

```bash
# Cible sim (défaut) — déterministe, hermétique, aucun conteneur
python3 run_campaign.py

# Cible docker — vrais conteneurs éphémères (nécessite docker + compose v2)
scripts/target_up.sh          # optionnel : inspecter la cible à la main
python3 run_campaign.py --backend docker
scripts/target_down.sh        # le runner détruit déjà la cible ; ceci force la purge
```

Le rapport JSON est écrit sous `reports/` (+ `reports/latest.json`, runtime,
git-ignoré) et un résumé lisible s'affiche. Des exemples d'exécution sont
versionnés (citables) : `samples/example-0.4.0.json` (dernier) et ses
prédécesseurs (`example-0.{1..3}.0.json`), conservés comme historique.

> **sim vs docker** — la cible **sim** est la **référence déterministe** (taux
> reproductibles). La cible **docker** apporte la fidélité des vrais
> Prometheus/Alertmanager ; comme elle dépend du temps réel (scrape, `group_wait`),
> les vecteurs à fenêtre longue (low-and-slow, `repeat_interval`) demandent de la
> décantation et sont moins déterministes. Le **détecteur est identique** dans les
> deux cas.
>
> **Constats de fidélité (run docker v0.4.0)** — surfacés en exécutant la vraie
> cible : (1) le vrai Alertmanager **refuse** un silence dont un matcher matche la
> chaîne vide (`instance=~.*`, garde-fou « tout silencer ») — le vecteur utilise
> donc `~.+` ; (2) contre un `group_wait` court, la **noyade par groupement** ne
> masque pas dans la fenêtre (le premier lot part avec la vraie alerte) : docker la
> cote « non masquée » là où la sim la cote masquée ; (3) le **blackout sélectif**
> (`selective_metric_drop`) est **rattrapé en sim mais pas en docker** — un vrai
> Prometheus représente une métrique supprimée par une série qui s'arrête, pas par
> des trous `None`, donc le détecteur de gap le voit en sim et le rate sur la vraie
> cible ; (4) le **faux all-clear** (`false_resolved`) **masque en sim mais pas en
> docker** — le resolved posté à l'API AM ne tient pas contre une règle Prometheus
> active, qui ré-affirme l'alerte au cycle suivant : l'alarme ressort. Résultat
> défensif : agir sur l'état d'Alertmanager est vain tant que la règle tient. Bilan
> docker : **81,2 / 76,9 / 18,2 / 18,8 / 100 %** (suppression / rattrapage / FP /
> résiduel / cohérence) vs sim **100 / 81,2 / 18,2 / 18,8 / 100 %**. Exemple :
> `samples/example-0.4.0-docker.json`. Le **flapping** (dont sur `jailbreak_rate`)
> se comporte comme en sim.
>
> **Robustesse des masquages préventifs (durcissement v0.4.0).** L'inhibition (spoofs)
> et le silence sont *déterministes par nature*, mais leur application par Alertmanager
> peut perdre une course de premier flush — l'alerte est notifiée avant que le muting
> soit appliqué. À charge nulle, `instance_down_spoof` et le silence à `alertname=~.+`
> perdaient ~1 run/3. La cible docker établit donc le masquage **avant** l'événement,
> en **confirme l'activation**, le stabilise (> 2× `group_interval`), puis **re-tente**
> le scénario si l'alerte fuite (fuite résiduelle < 0,5 %). Ces vecteurs masquent
> désormais de façon fiable (validé par répétition : 8/8 après durcissement, vs 2/3
> avant sur le silence regex).

## Tests / non-régression

Le run **sim** est déterministe : il sert de garde-fou de non-régression.
`tests/test_sim_regression.py` rejoue une campagne sim et la compare à
l'échantillon gelé `samples/example-0.4.0.json` (agrégat **et** chaque scénario ;
les horodatages sont ignorés). Stdlib `unittest`, aucune dépendance tierce.

```bash
make test                       # non-régression du run sim + déterminisme
```

Le backend **docker** est non déterministe (temps réel) : `tests/test_docker_regression.py`
ne fait donc **pas** d'égalité stricte mais vérifie des **invariants** (cohérence à
100 %, masqueurs déterministes toujours masqués + rattrapés, contrôles de cohérence
jamais signalés) et des garde-fous **directionnels à tolérance** autour de
`samples/example-0.4.0-docker.json`. Il monte une vraie cible éphémère (~6-11 min) et
n'est donc **pas** dans `make test` :

```bash
make test-docker                # non-régression LIVE du backend docker (opt-in)
```

La logique de ces contrôles — et sa **preuve par mutation** — tourne, elle, dans
`make test` sans docker.

Un changement de comportement **voulu** se re-gèle d'un geste délibéré, diff à
l'appui — pour la version courante, les deux échantillons :

```bash
python3 run_campaign.py --backend sim    --out samples/example-0.4.0.json --quiet
python3 run_campaign.py --backend docker --out samples/example-0.4.0-docker.json --quiet   # ~6-11 min
git diff samples/
```

(`make regen-sample` reste disponible mais ne regèle que l'échantillon d'exemple
historique `example-0.1.0.json`.)

## Format de sortie

JSON à **schéma versionné** (`sourdine_report_version`), pour la citabilité et la
comparaison entre exécutions :

- en tête : version du format, version du banc, horodatage, backend, détecteur ;
- par scénario : id, vecteur, niveau d'accès, vérité terrain, résultat sans
  détecteur, verdict, horodatage ;
- en agrégat : les 4 taux, le contrôle de cohérence, et la **ventilation par
  niveau d'accès attaquant**.

Le jeu de scénarios (`scenarios/`) est un artefact ouvert, séparé du runner.

## Brancher le vrai détecteur (hors de ce worktree)

Implémenter `engine/detector.py::MaskingDetector` :

```python
class SentinelleDetector(MaskingDetector):
    name = "sentinelleia-<version>"
    def detect(self, state, trace):
        # state : SupervisionState (alertes, silences, historique métrique)
        # trace : Trace (événements observables)
        return Verdict(masking_suspected=..., scope=..., reason=..., heuristic=...)
```

puis l'injecter dans `run_campaign.py` à la place de `BaselineDetector`. Le banc
**n'importe pas** le produit ; le vrai détecteur se mesure au même protocole, et
ses résultats remplacent alors ceux de la baseline dans le rapport.

## Ajouter un vecteur / un scénario

Voir `scenarios/SCHEMA.md`. Déposer un JSON dans `scenarios/{attacks,healthy}/`,
et pour un nouveau vecteur, ajouter son interprétation dans `engine/target_sim.py`
(et `engine/target_docker.py`) + éventuellement une heuristique dans
`engine/detector.py`. Garder l'équilibre attaques / sains.

---

## Garde-fous (non négociables)

- Tout est **synthétique et en laboratoire** : cible éphémère isolée, métriques
  fabriquées, aucun système réel touché.
- La cible n'est **jamais** l'Alertmanager ni le Prometheus de production ; le
  banc monte et détruit sa propre instance (ports sur `127.0.0.1`, numéros hauts).
- **Aucune** neutralisation de contrôle de sécurité ou d'authentification sur
  quoi que ce soit d'existant. Les manipulations (silence, inhibition, coupure)
  n'ont lieu que sur la cible jetable.
- Le banc évalue une **baseline**, pas SentinelleIA.

L'emballage citable (Zenodo / HAL, licences du dépôt public derrière
`sourdine.org` / `sourdine-bench.fr`) est une étape ultérieure, hors de ce banc.

## Arborescence

```
sourdine/
├── run_campaign.py              # entrée CLI
├── Makefile                     # make test | run | regen-sample (autonome au dossier)
├── VERSION  requirements.txt  .gitignore
├── engine/                      # moteur (stdlib)
│   ├── types.py  model.py       # types + sémantique alertes/inhibition/silence/groupement
│   ├── target_base.py  target_sim.py  target_docker.py
│   ├── detector.py              # interface + baseline heuristique
│   ├── runner.py  metrics.py  report.py  scenarios.py
├── scenarios/                   # artefact ouvert, étiqueté
│   ├── SCHEMA.md
│   ├── attacks/*.json           # 12 vecteurs (16 scénarios d'attaque)
│   └── healthy/*.json           # cohérence + pièges à faux positif (11 sains)
├── target/                      # cible éphémère conteneurisée
│   ├── docker-compose.yml
│   ├── prometheus/{prometheus.yml,alerts.yml}
│   ├── alertmanager/alertmanager.yml
│   ├── exporter/exporter.py     # exporter synthétique pilotable (stdlib)
│   └── sink/sink.py             # sink webhook d'observation (stdlib)
├── scripts/{target_up.sh,target_down.sh}
├── tests/                       # non-régression sim (strict) + docker (invariants/tolérance)
├── reports/                     # sorties JSON de campagne (runtime, git-ignoré)
└── samples/                     # exemples versionnés cumulés : example-0.{1..4}.0.json (sim) + *-docker.json
```
