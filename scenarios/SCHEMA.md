# Schéma du jeu de scénarios Sourdine

Le jeu de scénarios est un **artefact ouvert et étiqueté**, séparé du code du
runner, pour être publié et cité indépendamment. Un fichier = un scénario JSON,
sous `attacks/` (vecteur de masquage) ou `healthy/` (sain, pour mesurer les faux
positifs et la cohérence). Chaque scénario décrit une **intention** haut-niveau ;
les cibles (sim / docker) l'instancient.

## Champs

| Champ | Type | Rôle |
|---|---|---|
| `id` | string | Identifiant stable et citable (préfixe `ATT-` ou `HLT-`). |
| `kind` | `"attack"` \| `"healthy"` | Famille. |
| `vector` | string | Vecteur de masquage (ou `"none"` pour un sain). |
| `title` | string | Titre court. |
| `description` | string | Ce que fait le scénario et pourquoi. |
| `access_level` | string | **Hypothèse d'accès attaquant** (ventilation du rapport). |
| `coherence_control` | bool | `true` = cas grave sain servant de contrôle de cohérence. |
| `ground_truth.alarm_expected` | bool | **Vérité terrain** : une alarme était-elle attendue ? |
| `ground_truth.expected_alert` | string\|null | Nom de l'alerte qui aurait dû être levée. |
| `ground_truth.labels` | object | Labels de la série visée (`job`, `instance`). |
| `event` | object | L'événement qui devait lever l'alarme (`make_fire`, `severity`). |
| `masking` | object | La manœuvre qui efface le signalement (`type`, `params`). |
| `tags` | string[] | Étiquettes libres. |

## Vecteurs (`vector`)

`firewall_down_spoof`, `instance_down_spoof`, `postgres_down_spoof`,
`low_and_slow`, `threshold_flapping`, `silence_abuse`, `silence_shared_label`,
`silence_regex_alertname`, `grouping_repeat_abuse`, `exporter_cutoff`,
`selective_metric_drop`, `false_resolved`, `stale_replay`, `statistical_replay`,
`constrained_replay`, `route_blackhole`, `watchdog_suppression`, `cardinality_flood`,
`rogue_inhibitor`, `none`.

## Niveaux d'accès (`access_level`)

| Valeur | Hypothèse |
|---|---|
| `metric_or_am_api` | Injection de métrique ou création d'alerte via ingestion / API Alertmanager. |
| `threshold_knowledge` | Aucun accès superviseur ; connaît seulement les seuils. |
| `silence_or_routing_api` | Accès à l'API des silences ou à la config de routage. |
| `exporter_host_or_network` | Accès à l'hôte de l'exporter ou capacité réseau à bloquer le scrape. |
| `n/a` | Scénarios sains. |

## `masking.type` et `params`

- `spoof_inhibitor` — injecte une alerte source inhibitrice. `params` : {}.
- `low_and_slow` — `params.rate` (< seuil instantané).
- `threshold_flapping` — `params.high`/`low` ; `cycles` (rattrapable) ou `spikes` (furtif).
- `silence_abuse` — `params.broad` (bool), `params.at` (tick).
- `silence_shared_label` — `params.label` (ex. `job`), `params.value`, `params.at`.
- `silence_regex_alertname` — `params.at` (silence à matcher `alertname=~".+"` sur l'instance).
- `grouping_repeat_abuse` — `params.count` (taille du flot).
- `exporter_cutoff` — `params.pre_ticks` (activité avant la coupure ; l'instance tombe).
- `selective_metric_drop` — `params.pre_ticks` (activité avant le trou ; l'instance reste UP).
- `false_resolved` — `params.at` (tick du faux `resolved` posté à l'API Alertmanager) ; le signal à taux reste soutenu au-dessus du seuil. Masque en sim (état figé) ; en docker, la règle Prometheus ré-affirme l'alerte au cycle suivant — écart de fidélité assumé (T1562.011).
- `stale_replay` — `params.pre_ticks` (franchissement bref du seuil), `spike` (valeur du pic), `frozen` (palier figé, zone grise sous le seuil). Rejeu/gel : la métrique franchit le seuil puis est figée à un palier constant (ACSAC 2022, consistance temporelle).
- `statistical_replay` — `params.mean` (moyenne sous le seuil). Concealment distribution-preserving : signal bruité tiré de la distribution normale, cumul normal — **résiduel** (indétectable par la baseline marginale ; ACSAC 2022, consistance statistique).
- `constrained_replay` — `params.attack` (rejeu bas de attack_rate), `blocked` (blocked_rate élevé, non masqué). Rejeu sur un sous-ensemble : casse la corrélation attack_rate ↔ blocked_rate → **détectable** par la consistance SPATIALE (ACSAC 2022).
- `route_blackhole` — `params.rate` (taux d'attaque soutenu au-dessus du seuil). L'alerte de sécurité fire mais est reroutée vers un récepteur trou-noir (label de routage `route_target=blackhole`) : notification avalée, sans silence ni inhibiteur (MITRE T1562.006 Indicator Blocking). **Déterministe** dans les deux backends, rattrapé par `notification_blackhole` (corrélation métrique ↔ livraison, discriminant : classe de l'alerte).
- `watchdog_suppression` — `params.silent_from` (tick à partir duquel le heartbeat s'éteint). La chaîne d'alerte est désactivée et le signal d'attaque aveuglé : rien n'est observable, seul le heartbeat `watchdog` (toujours à 1 sinon) tombe à 0 de façon soutenue (dead man's switch, MITRE T1562 Impair Defenses). **Déterministe** dans les deux backends, rattrapé par `watchdog_gap` (silence soutenu du heartbeat).
- `cardinality_flood` — `params.samples` (nombre d'échantillons du scrape floodé), `pre_ticks` (début du flood). Une bombe de cardinalité fait dépasser `sample_limit` : le scrape est rejeté (`up`=0, fausse panne) et le vrai signal n'est jamais ingéré ; seul le pic de `scrape_samples` la distingue d'une vraie coupure (MITRE Impair Defenses / T1499 épuisement de ressources). **Déterministe** dans les deux backends, rattrapé par `cardinality_flood` (magnitude de `scrape_samples`).
- `rogue_inhibitor` — `params` : {} (l'alerte fire via `event.make_fire`). L'attaquant ajoute une règle d'inhibition dont la source (`RogueMuter`) n'est pas sanctionnée et étouffe la classe sécurité. `inhibitor_isolation` ne regarde que les sources sanctionnées → ne l'examine pas ; seul `rogue_inhibitor` (source non sanctionnée inhibant une alerte de SÉCURITÉ) la rattrape (MITRE T1562.001, dérive de config). **Déterministe** (préventif : règle baked + source postée avant le fire, confirmation+retry).
- `none` (sains) — `type` bénin : `benign_silence` (`broad`, `alertname`, `at`, `minor_activity`),
  `benign_exporter_restart` (`pre_ticks`, `gap`), `benign_spike` (`rate`),
  `benign_jitter` (`high`, `low`), `benign_brief_spike` (`spike`, `at`, `dur`, `baseline`),
  `benign_signal_gap` (`low`, `at`), `benign_resolve` (`high`, `low`, `at` : la métrique
  franchit le seuil puis retombe durablement — all-clear légitime),
  `benign_settle` (`high`, `frozen`, `pre_ticks` : activité sous le seuil puis palier — gel
  légitime sans franchissement), `benign_noise` (`mean` : trafic licite bruité sous le seuil,
  indiscernable d'une attaque à distribution préservée), `benign_correlated` (`level` :
  attack_rate et blocked_rate cohérents/corrélés — pas d'incohérence spatiale),
  `benign_route_mute` (`pg_conns` : une alerte opérationnelle NON-sécurité, route-mutée
  pendant une maintenance légitime — non délivrée mais pas une menace de sécurité),
  `benign_watchdog_blip` (`at`, `len` : raté transitoire du heartbeat watchdog qui se
  rétablit — chaîne saine, pas un dead man's switch),
  `benign_cardinality_bump` (`samples` : croissance de cardinalité légitime, sous
  `sample_limit`, scrape réussi — pas une bombe),
  `benign_maintenance_inhibition` (`pg_conns` : une source non sanctionnée inhibe une alerte
  OPÉRATIONNELLE pendant une maintenance — légitime, car la cible n'est pas de sécurité), ou `none`.

## Règle de cotation (normative)

Le **statut de masquage se lit sur la passe SANS détecteur**. Une alarme attendue
qui ne sort pas = masquage réussi, même si le détecteur la rattrape ensuite.
Ne jamais coter un scénario « non concerné » parce que la protection l'a rattrapé.

## Ajouter un scénario

Déposer un JSON dans `attacks/` ou `healthy/`, renseigner `ground_truth` et
`masking`. Équilibrer attaques et sains (sinon les taux ne veulent rien dire).
Pour un nouveau vecteur : ajouter son interprétation dans `engine/target_sim.py`
(et `engine/target_docker.py`), et, si besoin, une heuristique dans
`engine/detector.py`.
