# Sourdine : banc d'attaques de masquage d'alarme

*Version de référence. English version: [`README.en.md`](README.en.md).*

Sourdine mesure la résistance d'une chaîne d'alerte au **masquage d'alarme** :
des attaques qui ne visent pas un agent, mais **l'observateur** : elles
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
sur les systèmes industriels par Erba et Tippenhauer (ACSAC 2020, dépôt
`scy-phy/ICS-Evasion-Attacks` ; ACSAC 2022, dépôt
`scy-phy/ICS_Generic_Concealment_Attacks`), ainsi que des jeux de données RICSS 2024
issus de DHALSIM et HAI. Ces travaux attaquent le maillon **détection** : ils évadent
un détecteur d'anomalie (apprentissage surveillant un procédé physique) en **falsifiant
des séries temporelles de capteurs**.

Sourdine attaque un maillon **différent, l'_alerting_**, en abusant des primitives
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
donc modéliser **deux objets** par scénario, *l'événement qui devait lever une
alarme* et *la manœuvre qui fait disparaître ce signalement*, et mesurer en
**deux passes** :

1. **sans détecteur de masquage** : l'alarme attendue est-elle sortie ?
2. **avec détecteur** : le détecteur crie-t-il au masquage ?

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

1. **Cible éphémère** : Prometheus + Alertmanager en conteneurs, chargés d'un jeu
   de règles d'alerte et d'inhibition *représentatif mais recréé* (jamais copié
   de la prod), plus un exporter synthétique pilotable et un sink webhook qui
   observe les notifications réellement délivrées. Tout est monté puis détruit
   par le banc. Une cible **sim** en process offre la même sémantique, de façon
   déterministe et hermétique.
2. **Runner** (`engine/runner.py`) : pour chaque scénario, établit l'état,
   injecte l'événement, applique le vecteur, observe sans détecteur (passe 1),
   soumet état + trace au détecteur (passe 2), consigne.
3. **Détecteur** (`engine/detector.py`) : derrière une interface stable
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
les taux par niveau d'accès, ce qui rend le banc défendable).

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
| Rejeu / gel de métrique (ACSAC 2022 concealment) | l'attaque, figée à un palier après un franchissement, ne ré-alerte plus | hôte de l'exporter / ingestion métrique |
| Concealment statistique (distribution-preserving, ACSAC 2022), **résiduel** | l'attaque diluée en bruit réaliste sous le seuil (indétectable marginalement) | hôte de l'exporter / ingestion métrique |
| Constrained replay (rejeu sur un sous-ensemble, ACSAC 2022) | l'attaque masquée sur `attack_rate` mais pas sur `blocked_rate` (incohérence spatiale) | hôte de l'exporter / ingestion métrique |
| Route black-hole (blocage d'indicateur, MITRE T1562.006) | l'alerte de sécurité active mais reroutée vers un récepteur trou-noir (notification avalée), sans silence ni inhibiteur | API / config de routage Alertmanager |
| Watchdog suppression (dead man's switch, MITRE T1562) | chaîne d'alerte désactivée + signal d'attaque aveuglé : rien n'est observable, seul le heartbeat watchdog éteint le trahit | plan de contrôle / infra de la chaîne d'alerte |
| Bombe de cardinalité (DoS d'ingestion, MITRE Impair Defenses) | flot de séries à haute cardinalité, `sample_limit` dépassé, scrape rejeté (`up`=0), vrai signal jamais ingéré ; le pic de `scrape_samples` la trahit | ingestion métrique |
| Règle d'inhibition rogue (MITRE T1562.001) | l'attaquant ajoute une règle d'inhibition à source NON sanctionnée qui étouffe la classe sécurité ; dérive de config vs baseline | API / config de routage Alertmanager |
| Panne induite du garde (MITRE T1562.001) | l'attaquant coupe **réellement** le firewall puis attaque : l'inhibition **sanctionnée** `FirewallDown → classe sécurité` étouffe l'alerte en fonctionnant exactement comme prévu | hôte du firewall / réseau |
| Périmètre d'inhibition élargi (MITRE T1562.001) | les labels `equal` d'une règle sanctionnée sont retirés : une panne **réelle** sur une instance anodine étouffe alors la classe sécurité d'une autre instance | API / config de routage Alertmanager |
| Silence pré-positionné (MITRE T1562.001) | un silence étroit et irréprochable est posé **au calme**, bien avant l'attaque qui vient ensuite le rejoindre : la forme est parfaite, seul le **décalage temporel** trahit | API des silences |
| **Sains** (obligatoires) | aucun | mesurent faux positifs + cohérence |

Les **sains** incluent un cas grave sans attaque (l'alarme doit sortir) et des
activités légitimes qui *ressemblent* de loin à un vecteur (silence de
maintenance, redémarrage d'exporter planifié, pic licite sous le seuil) : le
détecteur ne doit pas crier au masquage dessus.

## Détecteur baseline : ce qu'il cherche

Il ne regarde pas le contenu de l'attaque : il cherche le **silence suspect** et
les manipulations de la chaîne d'alerte. Principe : *le chien qui n'aboie pas :
l'absence anormale de signal est elle-même le signal.* Une heuristique par famille :

- **Source inhibitrice isolée** : une `FirewallDown`/`InstanceDown`/`PostgreSQLDown`
  qui surgit **non corroborée** (sa cible reste vivante/élevée) et masque une alerte réelle.
- **Low-and-slow** : somme intégrée sur fenêtre longue au-delà d'un seuil, sans alerte à taux.
- **Flapping de seuil** : franchissements répétés du seuil sans qu'aucune alerte à taux ne soit active (le `for:` est réinitialisé en boucle).
- **Abus de silence** : silence sur-périmétré (matcher instance large, **ou sans matcher `alertname` exact** (absent ou regex `~.+`), balayant toute une classe d'alertes), ou silence étroit posé pendant une montée d'activité.
- **Coupure d'exporter** : trou de collecte coïncidant avec une activité élevée juste avant, l'instance tombant (`up` à 0).
- **Blackout sélectif** : un signal d'attaque disparaît après activité alors que l'instance reste **UP** (pas d'InstanceDown pour le trahir).
- **Faux all-clear** (`phantom_clear`) : un signal à taux reste **soutenu au-dessus du seuil** (encore chaud au dernier point observé) sans qu'aucune alerte à taux ne soit active, ni inhibiteur ni silence pour l'expliquer. Corrélation entre métrique et alerte (recommandée pour MITRE T1562.011) : l'alerte a été résolue/étouffée *après* avoir dû se déclencher : le chien qu'on fait taire après qu'il a aboyé, distinct des vecteurs qui l'empêchent d'aboyer.
- **Rejeu / gel** (`frozen_replay`) : après un **franchissement** du seuil (attaque réelle), le signal est **figé** à un palier intermédiaire constant (variance nulle) sans disparaître : la métrique reste présente et plausible, mais sa dynamique gelée trahit le rejeu/stale (ACSAC 2022, consistance temporelle). Distinct du low-and-slow (jamais au-dessus du seuil) et du pic bénin (qui retombe au repos).
- **Incohérence spatiale** (`spatial_incoherence`) : `attack_rate` (attaques rapportées) et `blocked_rate` (requêtes bloquées) sont normalement corrélés ; quand le firewall **bloque massivement** mais **ne rapporte quasi aucune attaque**, deux signaux qui devraient bouger ensemble divergent, signature du *constrained replay* (ACSAC 2022, consistance spatiale). C'est ce que le concealment marginal, aussi soigné soit-il, ne peut pas contourner s'il ne masque qu'un sous-ensemble des signaux.
- **Blocage d'indicateur au routage** (`notification_blackhole`) : une alerte de **sécurité** est **active** et sa menace **soutenue au-dessus du seuil** (elle aurait dû notifier), mais sa notification n'a **jamais atteint le récepteur** (`route_muted` : reroutée vers un récepteur trou-noir ou mutée au niveau de la route), **sans** silence ni inhibiteur pour l'expliquer. C'est un 4ᵉ levier de suppression, distinct de l'inhibition, du silence et du groupement (le fil est débranché *après* le déclenchement, *avant* le récepteur) ; corrélation entre métrique et livraison, recommandée pour MITRE T1562.006 (« détecter l'absence de report alors que l'activité est réelle »). Le **discriminant est la classe de l'alerte** : la non-livraison d'une alerte opérationnelle pendant une maintenance peut être légitime, celle d'une alerte de sécurité pendant une menace soutenue ne l'est pas.
- **Dead man's switch** (`watchdog_gap`) : le heartbeat `watchdog`, toujours émis (`vector(1)`) tant que la chaîne d'alerte est vivante, s'est **éteint de façon soutenue** (>= `WATCHDOG_MIN_SILENCE` ticks en fin de fenêtre). *Un système de supervision ne peut pas surveiller de façon fiable sa propre panne* : quand la chaîne (de Prometheus à la livraison, en passant par Alertmanager) est désactivée, toutes les alertes tombent en silence sans que rien ne le signale, sauf ce heartbeat qui cesse, remarqué par un veilleur **indépendant**. C'est la dernière ligne de défense (MITRE T1562 Impair Defenses) : même un attaquant qui aveugle parfaitement le signal d'attaque est trahi par le switch. Un **raté transitoire** (scrape manqué) se rétablit et est toléré ; seul un **silence soutenu** compte, sinon on paierait chaque jitter (alert fatigue).
- **Bombe de cardinalité** (`cardinality_flood`) : le nombre d'échantillons du scrape (`scrape_samples`) **explose** au-delà de `CARDINALITY_FLOOD_THRESHOLD`. Un attaquant qui injecte un flot de séries à haute cardinalité fait dépasser le `sample_limit` de Prometheus, qui **rejette le scrape entier** : `up` passe à 0 « comme si la cible était tombée » et le vrai signal n'est jamais ingéré. La fausse panne est **indiscernable** d'une vraie coupure pour les heuristiques d'absence ; c'est le **pic de `scrape_samples`**, bien au-delà de toute croissance légitime (un déploiement n'ajoute que quelques dizaines de séries), qui distingue la bombe d'ingestion, un déni de service de la supervision à des fins d'évasion (MITRE Impair Defenses / T1499). Alerte standard : `prometheus_target_scrapes_exceeded_sample_limit_total`.
- **Règle d'inhibition rogue** (`rogue_inhibitor`) : une alerte de **sécurité** est inhibée par une source d'inhibition qui n'appartient **pas** à l'ensemble sanctionné de la baseline (`INHIBITOR_SOURCES`). L'attaquant a ajouté une règle d'inhibition dont la source est une alerte bénigne qu'il contrôle, pour étouffer la classe sécurité (MITRE T1562.001 Disable or Modify Tools, altération de la config d'alerte). C'est **distinct des spoofs** (qui falsifient une source *sanctionnée* et sont rattrapés par non-corroboration) : ici la source est *illégitime*, donc l'heuristique d'inhibition, qui ne regarde que les sources sanctionnées, ne l'examine même pas. Détection par **dérive de config**. Le discriminant combine **source non sanctionnée ET cible de sécurité** : une source non sanctionnée qui inhibe une alerte *opérationnelle* (ex. maintenance DB) reste légitime.
- **Panne induite du garde** (`guard_down_under_threat`) : une source d'inhibition **sanctionnée et corroborée** (`FirewallDown` avec `fw_up` réellement à 0) inhibe une alerte de **sécurité** alors que la menace est **réelle et soutenue** au-dessus du seuil *pendant la panne*. L'attaquant ne falsifie rien : il **désactive vraiment** le contrôle de sécurité, puis attaque, et la règle de réduction de bruit (« ne pas crier au débordement quand le firewall est tombé ») devient sa couverture. C'est le complément exact de l'**inhibition isolée**, sur le même motif de corroboration lu à l'envers : là-bas la source ment (panne non corroborée = spoof), ici elle dit vrai, et c'est cela même qui la rend invisible à la corroboration. C'est le motif documenté des *EDR killers* (MITRE T1562.001 : désactiver le contrôle, puis opérer dans l'angle mort). Le **discriminant est la concomitance**, pas la panne : une maintenance de firewall est une opération banale ; sans ce garde, chacune deviendrait un faux positif.
- **Périmètre d'inhibition élargi** (`inhibition_scope_creep`) : une alerte justifiée (son propre signal au-dessus de son seuil) est inhibée par une source **sanctionnée**, mais **aucune source active de ce nom ne s'accorde avec elle sur les labels `equal`** de la règle : l'inhibition a franchi une frontière qu'elle n'avait pas le droit de franchir. La documentation d'Alertmanager prévient que si les labels `equal` sont absents des deux alertes, *la règle s'applique quand même* : les retirer transforme une inhibition ciblée en **suppression globale**, et une panne réelle sur une instance anodine suffit alors à étouffer la classe sécurité d'une autre. C'est la quatrième heuristique de la famille inhibition, et la seule dont le tell n'est ni le mensonge de la source (`inhibitor_isolation`), ni son illégitimité (`rogue_inhibitor`), ni la nature de la panne (`guard_down_under_threat`), mais le **périmètre**. Discriminant délibérément indépendant de la classe de l'alerte : le pendant sain (une inhibition parfaitement bornée, mécanisme normal de réduction de bruit) ne s'en distingue QUE par là.
- **Silence pré-positionné** (`silenced_under_threat`) : une alerte de **sécurité** est effectivement **étouffée par un silence** alors que sa menace est **réelle et soutenue** au-dessus du seuil. L'attaquant a posé son silence *au calme*, bien avant de frapper : étroit, `alertname` littéral, périmètre irréprochable : au moment de sa création il est **indiscernable d'une maintenance planifiée**, et c'est bien pour cela que l'abus de silence, qui juge la **forme** et l'activité **au moment de la pose**, ne peut rien voir ; `phantom_clear` s'abstient de son côté dès qu'un silence existe, le tenant pour une explication suffisante. Toute la manœuvre tient au **décalage dans le temps** entre la pose et l'usage. Le tell n'est donc ni la forme ni la date, mais l'**effet observé**, ce qui rejoint la contre-mesure recommandée : une suppression se re-vérifie **pendant** sa fenêtre, pas seulement à son ouverture. Discriminant = la **classe** de l'alerte : silencer une alerte opérationnelle pendant une maintenance est le geste d'exploitation le plus banal qui soit.

Ces heuristiques sont **volontairement imparfaites** pour que les faux positifs
et la suppression résiduelle soient non nuls et crédibles. Le **full statistical concealment**
(`statistical_replay`) en est l'exemple emblématique : en préservant la distribution du trafic
normal **et** la cohérence de *tous* les signaux, il ne brise aucune consistance vérifiable et
reste **indétectable** (cf. ACSAC 2022 sur le full replay), d'où une suppression résiduelle assumée. En
revanche, dès que le concealment ne masque qu'un **sous-ensemble** des signaux (*constrained
replay*), il brise la consistance **spatiale** et redevient détectable (`spatial_incoherence`) :
c'est le contraste exact d'ACSAC 2022 entre full et constrained replay. La suppression résiduelle
non nulle mesure honnêtement ce qui reste hors de portée ; le vrai détecteur devra faire mieux encore.

---

## Lancer une campagne

Aucune dépendance Python tierce (stdlib, Python ≥ 3.10).

```bash
# Cible sim (défaut) : déterministe, hermétique, aucun conteneur
python3 run_campaign.py

# Cible docker : vrais conteneurs éphémères (nécessite docker + compose v2)
scripts/target_up.sh          # optionnel : inspecter la cible à la main
python3 run_campaign.py --backend docker
scripts/target_down.sh        # le runner détruit déjà la cible ; ceci force la purge
```

Le rapport JSON est écrit sous `reports/` (+ `reports/latest.json`, runtime,
git-ignoré) et un résumé lisible s'affiche. Des exemples d'exécution sont
versionnés (citables) : `samples/example-0.14.0.json` (dernier) et ses
prédécesseurs (`example-0.{1..13}.0.json`), conservés comme historique.

> **sim vs docker** : la cible **sim** est la **référence déterministe** (taux
> reproductibles). La cible **docker** apporte la fidélité des vrais
> Prometheus/Alertmanager ; comme elle dépend du temps réel (scrape, `group_wait`),
> les vecteurs à fenêtre longue (low-and-slow, `repeat_interval`) demandent de la
> décantation et sont moins déterministes. Le **détecteur est identique** dans les
> deux cas.
>
> **Constats de fidélité (run docker v0.14.0)** : surfacés en exécutant la vraie
> cible : (1) le vrai Alertmanager **refuse** un silence dont un matcher matche la
> chaîne vide (`instance=~.*`, garde-fou « tout silencer ») ; le vecteur utilise
> donc `~.+` ; (2) contre un `group_wait` court, la **noyade par groupement** ne
> masque pas dans la fenêtre (le premier lot part avec la vraie alerte) : docker la
> cote « non masquée » là où la sim la cote masquée ; (3) le **blackout sélectif**
> (`selective_metric_drop`) est **rattrapé en sim mais pas en docker** : un vrai
> Prometheus représente une métrique supprimée par une série qui s'arrête, pas par
> des trous `None` ; (4) le **faux all-clear** (`false_resolved`) **masque en sim mais
> pas en docker** : le resolved posté à l'API AM ne tient pas contre une règle Prometheus
> active, qui ré-affirme l'alerte (résultat défensif) ; (5) le **rejeu/gel**
> (`stale_replay`) **masque dans les deux backends**, mais son rattrapage en docker
> dépend de la visibilité du pic de franchissement bref (TIMING_SENSITIVE). À noter :
> le **concealment statistique** (`statistical_replay`) masque et reste **résiduel dans
> les deux backends** ; ce n'est pas un écart de fidélité mais une limite de la baseline
> (cf. « Détecteur baseline »). Le **constrained replay** (`constrained_replay`), lui, ne masque
> qu'un sous-ensemble des signaux et est **rattrapé par la consistance spatiale**
> (`spatial_incoherence`) dans les deux backends, le contraste ACSAC 2022 full vs constrained.
> Le **route black-hole** (`route_blackhole`, MITRE T1562.006) masque de façon
> **déterministe dans les deux backends** (le routage vers le récepteur trou-noir ne
> dépend pas d'une fenêtre temporelle) et est **rattrapé par `notification_blackhole`** :
> c'est un masqueur fort (STRONG), pas un écart de fidélité.
> Le **watchdog suppression** (`watchdog_suppression`, MITRE T1562) masque lui aussi de façon
> **déterministe dans les deux backends** (le heartbeat mis à 0 ne dépend pas du timing) et est
> **rattrapé par `watchdog_gap`** : masqueur fort (STRONG), aucun écart de fidélité.
> La **bombe de cardinalité** (`cardinality_flood`, MITRE Impair Defenses / T1499) masque de façon
> **déterministe dans les deux backends** (`scrape_samples` haut + `up`=0, valeurs explicites) et est
> **rattrapée par `cardinality_flood`** : masqueur fort (STRONG), aucun écart de fidélité.
> La **règle d'inhibition rogue** (`rogue_inhibitor`, MITRE T1562.001) masque de façon
> **déterministe dans les deux backends** (règle baked à source non sanctionnée, appliquée en
> préventif avec confirmation+retry comme les spoofs) et est **rattrapée par `rogue_inhibitor`** :
> masqueur fort (STRONG), aucun écart de fidélité.
> La **panne induite du garde** (`guard_outage_cover`, MITRE T1562.001) est le seul vecteur qui
> **n'ajoute rien à la cible** : ni règle, ni label, ni alerte postée. Il coupe `fw_up` ; la règle
> `FirewallDown` fire d'elle-même et l'inhibition **sanctionnée** `FirewallDown → classe sécurité`
> étouffe l'alerte en fonctionnant exactement comme prévu. La chaîne est prise **telle qu'elle est**,
> ce qui en fait un trou réel plutôt qu'un artifice de banc. Masquage préventif (panne établie et
> confirmée active avant le fire) : **déterministe dans les deux backends**, **rattrapé par
> `guard_down_under_threat`**, masqueur fort (STRONG), aucun écart de fidélité.
> Le **périmètre d'inhibition élargi** (`inhibition_scope_creep`, MITRE T1562.001) s'appuie sur une
> règle privée de son `equal`, **bakée** dans `alertmanager.yml` et **inerte** tant que l'instance
> leurre ne tombe pas. Le vrai Alertmanager applique alors l'inhibition **globalement**, conformément
> à l'avertissement de sa propre documentation (« if all label names listed in `equal` are missing
> from both the source and target alerts, the inhibition rule will apply! ») : c'est le comportement
> **réel du produit**, pas une convention du banc. Masquage préventif : **déterministe dans les deux
> backends**, **rattrapé par `inhibition_scope_creep`**, masqueur fort (STRONG), aucun écart de fidélité.
> Bilan docker : **88,5 / 82,6 / 9,5 / 15,4 / 100 %** (suppression / rattrapage / FP /
> résiduel / cohérence) vs sim **100 / 84,6 / 9,5 / 15,4 / 100 %**. Exemple :
> `samples/example-0.14.0-docker.json`. Le **flapping** (dont sur `jailbreak_rate`)
> se comporte comme en sim.
>
> **Robustesse des masquages préventifs (durcissement v0.4.0).** L'inhibition (spoofs)
> et le silence sont *déterministes par nature*, mais leur application par Alertmanager
> peut perdre une course de premier flush : l'alerte est notifiée avant que le muting
> soit appliqué. À charge nulle, `instance_down_spoof` et le silence à `alertname=~.+`
> perdaient ~1 run/3. La cible docker établit donc le masquage **avant** l'événement,
> en **confirme l'activation**, le stabilise (> 2× `group_interval`), puis **re-tente**
> le scénario si l'alerte fuite (fuite résiduelle < 0,5 %). Ces vecteurs masquent
> désormais de façon fiable (validé par répétition : 8/8 après durcissement, vs 2/3
> avant sur le silence regex).

## Tests / non-régression

Le run **sim** est déterministe : il sert de garde-fou de non-régression.
`tests/test_sim_regression.py` rejoue une campagne sim et la compare à
l'échantillon gelé `samples/example-0.14.0.json` (agrégat **et** chaque scénario ;
les horodatages sont ignorés). Stdlib `unittest`, aucune dépendance tierce.

```bash
make test                       # non-régression du run sim + déterminisme
```

Le backend **docker** est non déterministe (temps réel) : `tests/test_docker_regression.py`
ne fait donc **pas** d'égalité stricte mais vérifie des **invariants** (cohérence à
100 %, masqueurs déterministes toujours masqués + rattrapés, contrôles de cohérence
jamais signalés) et des garde-fous **directionnels à tolérance** autour de
`samples/example-0.14.0-docker.json`. Il monte une vraie cible éphémère (~6-18 min) et
n'est donc **pas** dans `make test` :

```bash
make test-docker                # non-régression LIVE du backend docker (opt-in)
```

La logique de ces contrôles, et sa **preuve par mutation**, tourne, elle, dans
`make test` sans docker.

Un changement de comportement **voulu** se re-gèle d'un geste délibéré, diff à
l'appui ; pour la version courante, les deux échantillons :

```bash
python3 run_campaign.py --backend sim    --out samples/example-0.14.0.json --quiet
python3 run_campaign.py --backend docker --out samples/example-0.14.0-docker.json --quiet   # ~6-18 min
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

## Brancher le vrai détecteur (hors de ce dépôt)

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

## Résultats de référence (v0.14.0, détecteur `baseline-heuristic-v1`)

| Backend | Suppression réussie | Rattrapage | Faux positifs | Suppression résiduelle | Cohérence |
|---|---|---|---|---|---|
| sim (déterministe) | 100 % (26/26) | 84,6 % (22/26) | 9,5 % (2/21) | 15,4 % (4/26) | 100 % |
| docker (vrais conteneurs) | 88,5 % (23/26) | 82,6 % (19/23) | 9,5 % (2/21) | 15,4 % (4/26) | 100 % |

Lecture de ces chiffres, sans embellissement :

- les 2 faux positifs (`HLT-BENIGN-SILENCE-03`, `HLT-BENIGN-SPIKE-05`) sont les mêmes depuis
  la v0.1.0 ; quinze scénarios sains ont été ajoutés depuis sans nouveau faux positif, et la
  baisse du taux vient du dénominateur (6 sains en v0.1.0, 21 en v0.14.0), pas du détecteur ;
- l'ensemble résiduel en simulation est fermé à 4 attaques depuis la v0.6.0
  (`ATT-FLAP-STEALTH-10`, `ATT-GROUP-FLOOD-07`, `ATT-LOW-SLOW-STEALTH-05`,
  `ATT-STATISTICAL-REPLAY-18`), dont le concealment statistique complet, indétectable
  marginalement (voir « Détecteur baseline ») ;
- en conteneurs, l'ensemble résiduel diffère : `ATT-GROUP-FLOOD-07` en sort (l'alarme finit
  par sortir) et `ATT-SIGNAL-BLACKOUT-12` y entre ; trois attaques ne masquent pas
  (`ATT-FALSE-RESOLVED-15`, `ATT-FALSE-RESOLVED-JAILBREAK-16`, `ATT-GROUP-FLOOD-07`). Ces
  écarts de fidélité sont nommés et expliqués au paragraphe « Constats de fidélité » ci-dessus.

## Licences

| Partie du dépôt | Licence | Fichier |
|---|---|---|
| Moteur, runner, cible docker, tests, scripts (`engine/`, `run_campaign.py`, `target/`, `tests/`, `scripts/`, `Makefile`) | Apache License 2.0 | `LICENSE` |
| Scénarios étiquetés (`scenarios/`) | Creative Commons Attribution 4.0 International | `scenarios/LICENSE` |
| Échantillons gelés (`samples/`) | Creative Commons Attribution 4.0 International | `samples/LICENSE` |
| Documentation de méthode (`docs/`) | Creative Commons Attribution 4.0 International | `docs/LICENSE` |

Titulaire des droits : Apex Numeris SAS. Détail dans `NOTICE`.

## Citation

Auteur : Quoc-Nam Nguyen (Apex Numeris SAS, Lyon). Titulaire des droits : Apex Numeris SAS.
Le bouton « Cite this repository » de GitHub lit `CITATION.cff` ; chaque release reçoit un DOI
Zenodo, et le DOI de concept, commun à toutes les versions, est celui à citer. La fiche
`DATASHEET.md` (en anglais : `DATASHEET.en.md`) décrit le banc sur le modèle des
datasheets for datasets.

## Arborescence

```
sourdine/
├── run_campaign.py              # entrée CLI
├── Makefile                     # make test | run | regen-sample (autonome au dossier)
├── VERSION  requirements.txt  .gitignore
├── LICENSE  NOTICE              # Apache-2.0 (code et harnais) ; titulaire, auteur, double licence
├── CITATION.cff  .zenodo.json   # citation GitHub ; métadonnées du DOI Zenodo
├── DATASHEET.md  DATASHEET.en.md   # fiche du banc (datasheet for datasets), français et anglais
├── README.md  README.en.md      # ce document (référence en français, version anglaise)
├── engine/                      # moteur (stdlib)
│   ├── types.py  model.py       # types + sémantique alertes/inhibition/silence/groupement
│   ├── target_base.py  target_sim.py  target_docker.py
│   ├── detector.py              # interface + baseline heuristique
│   ├── runner.py  metrics.py  report.py  scenarios.py
├── scenarios/                   # artefact ouvert, étiqueté (CC BY 4.0, fichier LICENSE du dossier)
│   ├── SCHEMA.md
│   ├── attacks/*.json           # 22 vecteurs (26 scénarios d'attaque)
│   └── healthy/*.json           # cohérence + pièges à faux positif (21 sains)
├── target/                      # cible éphémère conteneurisée
│   ├── docker-compose.yml
│   ├── prometheus/{prometheus.yml,alerts.yml}
│   ├── alertmanager/alertmanager.yml
│   ├── exporter/exporter.py     # exporter synthétique pilotable (stdlib)
│   └── sink/sink.py             # sink webhook d'observation (stdlib)
├── scripts/{target_up.sh,target_down.sh}
├── tests/                       # non-régression sim (strict) + docker (invariants/tolérance)
├── reports/                     # sorties JSON de campagne (runtime, git-ignoré)
├── docs/                        # documentation de méthode (CC BY 4.0, fichier LICENSE du dossier)
└── samples/                     # exemples versionnés cumulés : example-0.{1..14}.0.json (sim) + *-docker.json (CC BY 4.0)
```
