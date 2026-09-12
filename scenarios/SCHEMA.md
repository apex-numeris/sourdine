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
`constrained_replay`, `none`.

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
- `none` (sains) — `type` bénin : `benign_silence` (`broad`, `alertname`, `at`, `minor_activity`),
  `benign_exporter_restart` (`pre_ticks`, `gap`), `benign_spike` (`rate`),
  `benign_jitter` (`high`, `low`), `benign_brief_spike` (`spike`, `at`, `dur`, `baseline`),
  `benign_signal_gap` (`low`, `at`), `benign_resolve` (`high`, `low`, `at` : la métrique
  franchit le seuil puis retombe durablement — all-clear légitime),
  `benign_settle` (`high`, `frozen`, `pre_ticks` : activité sous le seuil puis palier — gel
  légitime sans franchissement), `benign_noise` (`mean` : trafic licite bruité sous le seuil,
  indiscernable d'une attaque à distribution préservée), `benign_correlated` (`level` :
  attack_rate et blocked_rate cohérents/corrélés — pas d'incohérence spatiale), ou `none`.

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
