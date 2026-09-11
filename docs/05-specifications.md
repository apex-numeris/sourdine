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
| `grouping_repeat_abuse` | l'alerte noyée | `silence_or_routing_api` | `grouping_repeat_abuse` / `{count}` |
| `exporter_cutoff` | l'alerte qui ne part jamais | `exporter_host_or_network` | `exporter_cutoff` / `{pre_ticks}` |
| `none` (sains) | — | `n/a` | `none` \| `benign_silence` \| `benign_exporter_restart` \| `benign_spike` \| `benign_jitter` \| `benign_brief_spike` |

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
| `silence_abuse` | silence sur-périmétré (matcher `instance` large **ou sans matcher `alertname`**), **ou** silence étroit posé pendant une montée d'activité |
| `exporter_cutoff` | trou de collecte (`up` 1→0 / signal absent) coïncidant avec une activité élevée juste avant |

La baseline est **volontairement imparfaite** : elle manque la noyade par
groupement, le low-and-slow sous le seuil intégré et le flapping furtif (peu de
franchissements) — d'où la suppression résiduelle —, et peut faux-positiver sur un
silence de maintenance ou un pic licite (→ faux positifs).

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
