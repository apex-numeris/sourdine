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
`low_and_slow`, `silence_abuse`, `grouping_repeat_abuse`, `exporter_cutoff`, `none`.

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
- `silence_abuse` — `params.broad` (bool), `params.at` (tick).
- `grouping_repeat_abuse` — `params.count` (taille du flot).
- `exporter_cutoff` — `params.pre_ticks` (activité avant la coupure).
- `none` (sains) — `type` bénin : `benign_silence` (`broad`, `alertname`, `at`, `minor_activity`),
  `benign_exporter_restart` (`pre_ticks`, `gap`), `benign_spike` (`rate`), ou `none`.

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
