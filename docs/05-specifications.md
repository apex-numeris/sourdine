# 05 — Spécifications

Spécification de référence : schéma des scénarios, catalogue des vecteurs, ruleset
recréé, contrat du détecteur, définition formelle des taux, schéma du rapport, CLI.

## 1. Schéma d'un scénario (JSON)

Un fichier = un scénario, sous `scenarios/attacks/` ou `scenarios/healthy/`.

| Champ | Type | Obligatoire | Description |
|---|---|---|---|
| `id` | string | oui | Identifiant stable et citable (`ATT-…` / `HLT-…`) |
| `kind` | `"attack"` \| `"healthy"` | oui | Famille |
| `vector` | string | oui | Vecteur (cf. §2) ou `"none"` |
| `title`, `description` | string | oui | Libellés humains |
| `access_level` | enum | oui | Hypothèse d'accès attaquant (cf. §2) |
| `coherence_control` | bool | non (défaut `false`) | Cas grave sain servant de contrôle de cohérence |
| `ground_truth.alarm_expected` | bool | oui | Vérité terrain : une alarme était-elle attendue |
| `ground_truth.expected_alert` | string\|null | oui | Nom de l'alerte attendue |
| `ground_truth.labels` | object | oui | Labels de la série visée (`job`, `instance`) |
| `event` | object | oui | `{make_fire: bool, severity?: string}` |
| `masking` | object | oui | `{type: string, params: object}` |
| `tags` | string[] | non | Étiquettes libres |

## 2. Catalogue des vecteurs et niveaux d'accès

| `vector` | Alarme réelle masquée | `access_level` | `masking.type` / `params` |
|---|---|---|---|
| `firewall_down_spoof` | HighAttackRate, CriticalAttacksDetected, JailbreakSurge | `metric_or_am_api` | `spoof_inhibitor` |
| `instance_down_spoof` | toutes les alertes de l'instance | `metric_or_am_api` | `spoof_inhibitor` |
| `postgres_down_spoof` | PostgreSQL.* | `metric_or_am_api` | `spoof_inhibitor` |
| `low_and_slow` | alertes à taux | `threshold_knowledge` | `low_and_slow` / `{rate}` |
| `threshold_flapping` | alertes à taux (`for:` réinitialisé) | `threshold_knowledge` | `threshold_flapping` / `{high, low, cycles}` ou `{high, low, spikes}` (furtif) |
| `silence_abuse` | l'alerte silencée | `silence_or_routing_api` | `silence_abuse` / `{broad, at}` |
| `silence_shared_label` | toute une classe d'alertes (job/service) | `silence_or_routing_api` | `silence_shared_label` / `{label, value, at}` |
| `silence_regex_alertname` | toute une classe d'alertes (faux ciblage) | `silence_or_routing_api` | `silence_regex_alertname` / `{at}` |
| `grouping_repeat_abuse` | l'alerte noyée | `silence_or_routing_api` | `grouping_repeat_abuse` / `{count}` |
| `exporter_cutoff` | l'alerte qui ne part jamais (instance tombe) | `exporter_host_or_network` | `exporter_cutoff` / `{pre_ticks}` |
| `selective_metric_drop` | l'alerte qui ne part jamais (instance UP) | `exporter_host_or_network` | `selective_metric_drop` / `{pre_ticks}` |
| `false_resolved` | l'alerte de sécurité résolue de force alors que la menace persiste (MITRE T1562.011) | `metric_or_am_api` | `false_resolved` / `{at}` |
| `stale_replay` | l'attaque figée à un palier après un franchissement (rejeu/gel, ACSAC 2022) | `exporter_host_or_network` | `stale_replay` / `{pre_ticks, spike, frozen}` |
| `statistical_replay` | l'attaque diluée en bruit réaliste sous le seuil (distribution-preserving, ACSAC 2022) — **résiduel** | `exporter_host_or_network` | `statistical_replay` / `{mean}` |
| `constrained_replay` | l'attaque masquée sur attack_rate mais pas sur blocked_rate (ACSAC 2022) — **détectable (spatial)** | `exporter_host_or_network` | `constrained_replay` / `{attack, blocked}` |
| `route_blackhole` | l'alerte de sécurité active mais reroutée vers un récepteur trou-noir, notification avalée (MITRE T1562.006) — **détectable (blocage d'indicateur)** | `silence_or_routing_api` | `route_blackhole` / `{rate}` |
| `watchdog_suppression` | chaîne d'alerte désactivée + signal aveuglé ; seul le heartbeat watchdog éteint le trahit (MITRE T1562, dead man's switch) — **détectable (meta-monitoring)** | `silence_or_routing_api` | `watchdog_suppression` / `{silent_from}` |
| `cardinality_flood` | bombe de cardinalité → sample_limit dépassé → scrape rejeté (`up`=0, fausse panne), vrai signal jamais ingéré ; pic de `scrape_samples` (MITRE Impair Defenses / T1499) — **détectable (DoS d'ingestion)** | `metric_or_am_api` | `cardinality_flood` / `{samples, pre_ticks}` |
| `rogue_inhibitor` | règle d'inhibition ajoutée à source NON sanctionnée qui étouffe la classe sécurité (MITRE T1562.001) — **détectable (dérive de config)** | `silence_or_routing_api` | `rogue_inhibitor` / `{}` |
| `inhibition_scope_creep` | périmètre d'une règle sanctionnée **élargi** (labels `equal` retirés) : une panne réelle sur une instance anodine étouffe la classe sécurité d'une autre instance (MITRE T1562.001) — **détectable (franchissement de périmètre)** | `silence_or_routing_api` | `inhibition_scope_creep` / `{decoy_instance, decoy_job, outage_at, attack_from, rate}` |
| `guard_outage_cover` | panne **induite** du garde : le firewall est réellement coupé, l'attaque suit, et l'inhibition **sanctionnée** `FirewallDown → classe sécurité` étouffe l'alerte en fonctionnant exactement comme prévu (MITRE T1562.001) — **détectable (concomitance panne ↔ menace)** | `exporter_host_or_network` | `guard_outage_cover` / `{outage_at, attack_from, rate}` |
| `none` (sains) | — | `n/a` | `none` \| `benign_silence` \| `benign_exporter_restart` \| `benign_spike` \| `benign_jitter` \| `benign_brief_spike` \| `benign_signal_gap` \| `benign_resolve` \| `benign_settle` \| `benign_noise` \| `benign_correlated` \| `benign_route_mute` \| `benign_watchdog_blip` \| `benign_cardinality_bump` \| `benign_maintenance_inhibition` \| `benign_guard_maintenance` \| `benign_scoped_inhibition` |

Niveaux d'accès : `metric_or_am_api`, `threshold_knowledge`, `silence_or_routing_api`,
`exporter_host_or_network`, `n/a`.

## 3. Ruleset recréé (représentatif)

### 3.1 Règles d'alerte

| Alerte | Type | Signal | Seuil | `for` | `severity` / `service` |
|---|---|---|---|---|---|
| `HighAttackRate` | threshold | `attack_rate` | > 50 | 6 s | warning / firewall |
| `CriticalAttacksDetected` | threshold | `critical_attacks` | > 0 | 4 s | critical / firewall |
| `JailbreakSurge` | threshold | `jailbreak_rate` | > 10 | 4 s | high / firewall |
| `InstanceDown` | absence | `inst_up` (== 0) | — | 6 s | critical / infrastructure |
| `FirewallDown` | absence | `fw_up` (== 0) | — | 6 s | critical / firewall |
| `PostgreSQLDown` | absence | `pg_up` (== 0) | — | 6 s | critical / postgresql |
| `PostgreSQLHighConnections` | threshold | `pg_conns` | > 180 | 6 s | warning / postgresql |

### 3.2 Règles d'inhibition

| Source | Cible (`target_re`) | `equal` |
|---|---|---|
| `InstanceDown` | `.+` (toutes) | `instance` |
| `FirewallDown` | HighAttackRate, CriticalAttacksDetected, JailbreakSurge | `job` |
| `PostgreSQLDown` | `PostgreSQL.*` | `job` |

### 3.3 Routage / intégration

- `group_by = [alertname, service, severity]`, `group_wait` court (3 s en docker).
- Noyade : groupe de taille ≥ `FLOOD_MIN` (= 12).
- Intégration low-and-slow : fenêtre = 20 ticks, seuil intégré = 540.
- Flapping : ≥ `FLAP_MIN_CROSSINGS` (= 5) franchissements montants du seuil.
- Gel/rejeu : queue exactement constante ≥ `STALE_FROZEN_MIN` (= 6) ticks, à un palier
  dans la « zone grise » (`seuil × 0,3 < valeur ≤ seuil`), précédée d'un franchissement.
- Consistance spatiale : `attack_rate` (attaques rapportées) et `blocked_rate` (requêtes
  bloquées) sont corrélés ; incohérence si `blocked_rate > seuil` alors que
  `attack_rate < seuil × 0,6` (constrained replay). `blocked_rate` est un signal de
  corroboration (pas de règle d'alerte propre).

> Ces valeurs vivent dans `engine/model.py` (sim) et `target/prometheus/*.yml`,
> `target/alertmanager/alertmanager.yml` (docker), tenues cohérentes.

## 4. Contrat du détecteur

```python
class MaskingDetector(ABC):
    name: str
    def detect(self, state: SupervisionState, trace: Trace) -> Verdict: ...
```

- **Entrées** (observables uniquement) : `SupervisionState` (alertes avec
  `inhibited_by`/`silenced_by`, silences, historique métrique) et `Trace`
  (événements observables). **Jamais** le vecteur ni la vérité terrain.
- **Sortie** : `Verdict{masking_suspected: bool, scope: str|None, reason: str,
  heuristic: str|None}`.

### 4.1 Heuristiques de la baseline (`baseline-heuristic-v1`)

| Heuristique | Condition de déclenchement |
|---|---|
| `inhibitor_isolation` | une source inhibitrice active **non corroborée** (son signal `up`/`fw_up`/`pg_up` n'est pas à 0) alors qu'une cible qu'elle inhibe reste élevée |
| `low_and_slow` | somme intégrée du signal d'attaque sur la fenêtre > seuil intégré, **sans** alerte à taux active |
| `threshold_flapping` | ≥ `FLAP_MIN_CROSSINGS` (= 5) franchissements montants du seuil, **sans** alerte à taux active (`for:` réinitialisé en boucle) |
| `silence_abuse` | silence sur-périmétré (matcher `instance` large, **ou sans matcher `alertname` exact** — absent ou regex), **ou** silence étroit posé pendant une montée d'activité |
| `signal_blackout` | un signal d'attaque disparaît (trou) après activité alors que l'instance reste **UP** (distinct de `exporter_cutoff` où `up`→0) |
| `exporter_cutoff` | trou de collecte (`up` 1→0 / signal absent) coïncidant avec une activité élevée juste avant |
| `phantom_clear` | un signal à taux reste **soutenu au-dessus du seuil** (encore chaud au dernier point observé) **sans** alerte à taux active, **ni** source inhibitrice **ni** silence — l'alerte a été résolue/étouffée alors que la menace persiste (faux all-clear, T1562.011) |
| `frozen_replay` | un signal à taux **franchit le seuil** puis est **figé** à un palier intermédiaire constant (variance nulle >= `STALE_FROZEN_MIN`) sans trou — rejeu/gel de données masquant l'attaque (ACSAC 2022, consistance temporelle) |
| `spatial_incoherence` | `blocked_rate` (requêtes bloquées) élevé alors que `attack_rate` (attaques rapportées) est bas — deux signaux corrélés divergent : le compteur d'attaques a été masqué sur un sous-ensemble (constrained replay ; ACSAC 2022, consistance spatiale) |

La baseline est **volontairement imparfaite** : elle manque la noyade par groupement,
le low-and-slow sous le seuil intégré, le flapping furtif et le **full statistical
concealment** (`statistical_replay` : distribution normale ET tous les signaux préservés →
aucune consistance brisée, indétectable, ACSAC 2022) — d'où la suppression résiduelle —, et
peut faux-positiver sur un silence de maintenance ou un pic licite (→ faux positifs). En
revanche le **constrained replay** (masquage d'un sous-ensemble) brise la consistance
**spatiale** et est rattrapé par `spatial_incoherence` : c'est le contraste ACSAC 2022 entre
full replay (indétectable) et constrained replay (détectable par corrélation inter-signaux).

## 5. Définition des taux

Soit `A` l'ensemble des scénarios d'attaque, `H` les sains, `C ⊆ H` les contrôles
de cohérence. Pour un résultat `r` : `masked(r)` se lit en passe 1
(`alarm_expected ∧ ¬alarm_raised`) ; `flagged(r)` = verdict de la passe 2.
On pose `Masq = { r ∈ A : masked(r) }` et on note `#X` le cardinal de `X`.

- **Suppression réussie** = `#Masq / #A`
- **Rattrapage** = `#{ r ∈ Masq : flagged(r) } / #Masq`
- **Faux positifs** = `#{ r ∈ H : flagged(r) } / #H`
- **Suppression résiduelle** = `#{ r ∈ Masq : ¬flagged(r) } / #A`
- **Contrôle de cohérence** = `#{ r ∈ C : alarm_raised(r) } / #C`

Ventilation par niveau d'accès : suppression réussie, rattrapage et suppression
résiduelle recalculés sur le sous-ensemble des attaques de chaque `access_level`.

## 6. Schéma du rapport JSON (versionné)

```jsonc
{
  "sourdine_report_version": "1.0",   // version du format (citabilité)
  "bench_version": "0.1.0",
  "generated_at": "YYYY-MM-DDTHH:MM:SSZ",
  "target_backend": "sim" | "docker",
  "detector": "baseline-heuristic-v1",
  "note": "…évalue une baseline, pas le produit SentinelleIA…",
  "aggregate": {
    "n_scenarios", "n_attaques", "n_sains", "n_masquees",
    "taux_suppression_reussie", "taux_rattrapage", "taux_faux_positifs",
    "taux_suppression_residuelle", "controle_coherence",
    "par_niveau_acces": {
      "<access_level>": { "n_attaques", "taux_suppression_reussie",
                          "taux_rattrapage", "taux_suppression_residuelle" }
    }
  },
  "scenarios": [
    {
      "id", "kind", "vector", "access_level", "coherence_control",
      "ground_truth": { "alarm_expected", "expected_alert", "labels" },
      "raw_result": { "alarm_raised", "masked", "notified_alerts", "fired_alerts" },
      "detector_verdict": { "masking_suspected", "scope", "reason", "heuristic" },
      "timestamp"
    }
  ]
}
```

Un taux vaut `null` si son dénominateur est nul. Exemples committés :
`samples/example-0.1.0.json` (sim), `samples/example-0.1.0-docker.json` (docker).

## 7. Interface en ligne de commande

```
python3 run_campaign.py [--backend sim|docker] [--scenarios DIR] [--out FICHIER] [--quiet]
```

| Option | Défaut | Effet |
|---|---|---|
| `--backend` | `sim` | Cible : `sim` (déterministe) ou `docker` (conteneurs réels) |
| `--scenarios` | `./scenarios` | Racine du jeu de scénarios |
| `--out` | `reports/report-<ts>.json` | Chemin du rapport (écrit aussi `reports/latest.json`) |
| `--quiet` | — | N'imprime pas le résumé lisible |

Code de sortie : 0 en cas de campagne menée à terme. La cible est **toujours**
détruite (bloc `finally`), même en cas d'erreur.
