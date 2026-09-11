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
| Abus de silence / groupement | une vraie alerte tue ou noyée | API des silences / config de routage |
| Coupure d'exporter / scrape | l'alerte qui ne part jamais | hôte de l'exporter / réseau |
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
- **Abus de silence** : silence posé pendant une montée d'activité, ou périmètre anormalement large.
- **Coupure d'exporter** : trou de collecte coïncidant avec une activité élevée juste avant.

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
git-ignoré) et un résumé lisible s'affiche. Un exemple d'exécution est versionné
(citable) : `samples/example-0.1.0.json`.

> **sim vs docker** — la cible **sim** est la **référence déterministe** (taux
> reproductibles). La cible **docker** apporte la fidélité des vrais
> Prometheus/Alertmanager ; comme elle dépend du temps réel (scrape, `group_wait`),
> les vecteurs à fenêtre longue (low-and-slow, `repeat_interval`) demandent de la
> décantation et sont moins déterministes. Le **détecteur est identique** dans les
> deux cas.
>
> **Constats de fidélité (run docker v0.1.0)** — surfacés en exécutant la vraie
> cible : (1) le vrai Alertmanager **refuse** un silence dont un matcher matche la
> chaîne vide (`instance=~.*`, garde-fou « tout silencer ») — le vecteur utilise
> donc `~.+` ; (2) contre un `group_wait` court, la **noyade par groupement** ne
> masque pas dans la fenêtre (le premier lot part avec la vraie alerte) : docker la
> cote « non masquée » là où la sim, qui modélise une config à fenêtre longue, la
> cote masquée. Résultat docker : **87,5 / 85,7 / 33,3 / 12,5 / 100 %**
> (suppression / rattrapage / FP / résiduel / cohérence) vs sim
> **100 / 75 / 33 / 25 / 100 %**. Exemple : `samples/example-0.1.0-docker.json`.

## Tests / non-régression

Le run **sim** est déterministe : il sert de garde-fou de non-régression.
`tests/test_sim_regression.py` rejoue une campagne sim et la compare à
l'échantillon gelé `samples/example-0.1.0.json` (agrégat **et** chaque scénario ;
les horodatages sont ignorés). Stdlib `unittest`, aucune dépendance tierce.

```bash
make test                       # non-régression du run sim + déterminisme
```

Un changement de comportement **voulu** se re-gèle d'un geste délibéré, diff à l'appui :

```bash
make regen-sample && git diff samples/
```

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
│   ├── attacks/*.json           # 6 vecteurs
│   └── healthy/*.json           # cohérence + pièges à faux positif
├── target/                      # cible éphémère conteneurisée
│   ├── docker-compose.yml
│   ├── prometheus/{prometheus.yml,alerts.yml}
│   ├── alertmanager/alertmanager.yml
│   ├── exporter/exporter.py     # exporter synthétique pilotable (stdlib)
│   └── sink/sink.py             # sink webhook d'observation (stdlib)
├── scripts/{target_up.sh,target_down.sh}
├── tests/                       # non-régression du run sim (stdlib unittest)
├── reports/                     # sorties JSON de campagne (runtime, git-ignoré)
└── samples/                     # exemples versionnés : example-0.1.0.json (sim) + example-0.1.0-docker.json
```
