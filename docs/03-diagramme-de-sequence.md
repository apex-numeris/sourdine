# 03. Diagrammes de séquence

## 1. Campagne complète (tous backends)

```mermaid
sequenceDiagram
    autonumber
    actor U as Utilisateur (CLI)
    participant R as Runner
    participant T as Cible (sim|docker)
    participant D as Détecteur
    participant M as Métriques
    participant P as Rapport

    U->>R: run_campaign.py --backend <sim|docker>
    R->>T: setup() (monte la cible éphémère)
    loop pour chaque scénario
        R->>T: execute(scénario)
        Note over T: reset → injecte l'événement →<br/>applique le vecteur de masquage
        T-->>R: RawResult (passe 1), SupervisionState, Trace
        R->>D: detect(state, trace)  (passe 2)
        D-->>R: Verdict {masking_suspected, scope, heuristic}
        R->>R: consigne (vérité terrain, brut, verdict)
    end
    R->>T: teardown() (détruit la cible)
    R->>M: compute_metrics(résultats)
    M-->>R: 4 taux + cohérence + ventilation
    R->>P: build_report() + write (JSON) + résumé lisible
    P-->>U: reports/…json + tableau
```

## 2. Exécution d'un scénario de spoof (backend docker, bout-en-bout)

Exemple avec `ATT-FW-DOWN-SPOOF-01` : l'attaquant injecte une alerte `FirewallDown`
pour inhiber `HighAttackRate`.

```mermaid
sequenceDiagram
    autonumber
    participant R as Runner (DockerTarget)
    participant E as Exporter<br/>(synthétique)
    participant PR as Prometheus
    participant AM as Alertmanager
    participant SK as Sink (webhook)
    participant D as Détecteur baseline

    Note over R: _reset()
    R->>E: POST /reset (métriques par défaut : fw_up=1…)
    R->>SK: POST /reset (vide le registre)
    R->>AM: résout les alertes injectées précédentes + supprime les silences
    R->>R: t0 = maintenant (fenêtre propre au scénario)

    Note over R: injecter l'événement
    R->>E: POST /set attack_rate{job=firewall,instance=fw-1}=120
    PR->>E: scrape /metrics (toutes les 2 s)
    PR->>PR: règle HighAttackRate (>50, for 6s) → FIRING
    PR->>AM: alerte HighAttackRate

    Note over R: appliquer le vecteur
    R->>AM: POST /api/v2/alerts [FirewallDown{job=firewall}]
    AM->>AM: inhibit_rules : FirewallDown masque HighAttackRate (même job)

    Note over R: passe 1, observation (après décantation)
    AM--xSK: HighAttackRate NON notifiée (inhibée)
    R->>SK: GET /received
    SK-->>R: (HighAttackRate absente) ⇒ alarm_raised = false ⇒ MASQUÉE

    Note over R: passe 2, état + trace au détecteur
    R->>AM: GET /api/v2/alerts (statut + inhibitedBy), GET /api/v2/silences
    R->>PR: GET /api/v1/query_range (attack_rate, fw_up, …) depuis t0
    R->>D: detect(state, trace)
    Note over D: FirewallDown active, mais fw_up=1 (non corroborée)<br/>et la cible HighAttackRate reste élevée → inhibition suspecte
    D-->>R: Verdict{masking_suspected=true, scope=job=firewall, heuristic=inhibitor_isolation}
```

## 3. Cycle de vie de la cible docker (montée / destruction garanties)

```mermaid
sequenceDiagram
    autonumber
    participant R as run_campaign (finally)
    participant C as docker compose (projet « sourdine »)
    participant NET as réseau sourdine-net
    participant CT as conteneurs sourdine-*

    R->>C: up -d (prometheus, alertmanager, exporter, sink)
    C->>NET: crée le réseau isolé
    C->>CT: crée + démarre les 4 conteneurs (ports sur 127.0.0.1:39xxx)
    R->>CT: sonde /-/ready (prom, am) et /healthz (exporter, sink)
    CT-->>R: prêts
    Note over R,CT: … exécution de tous les scénarios …
    R->>C: down -v -t 3 (même en cas d'erreur, bloc finally)
    C->>CT: stoppe + supprime les conteneurs
    C->>NET: supprime le réseau + volumes
    Note over R: aucun résidu, vérifié par docker ps / network ls
```

## 4. Vecteur de coupure d'exporter (low-and-slow du signal)

Exemple : `ATT-EXPORTER-CUTOFF-08`.

```mermaid
sequenceDiagram
    autonumber
    participant R as Runner
    participant E as Exporter
    participant PR as Prometheus
    participant AM as Alertmanager
    participant D as Détecteur

    R->>E: POST /set attack_rate=130 (activité d'attaque)
    PR->>E: scrape (quelques cycles)
    R->>E: POST /set inst_up=0 + POST /del attack_rate (coupure)
    PR->>E: scrape → cible muette
    PR->>PR: attack_rate absent ⇒ HighAttackRate ne part jamais<br/>inst_up==0 (for 6s) ⇒ InstanceDown FIRING
    PR->>AM: InstanceDown (inhibe le reste de l'instance)
    Note over R: passe 1 : HighAttackRate jamais notifiée ⇒ MASQUÉE
    R->>D: detect(state, trace)
    Note over D: trou de collecte (inst_up : 1→0) coïncidant<br/>avec une activité élevée juste avant ⇒ suspect
    D-->>R: Verdict{masking_suspected=true, heuristic=exporter_cutoff}
```

> La sim suit exactement la même logique, sans le réseau ni le temps réel : elle
> calcule l'état final de façon déterministe (cf. [doc 04](04-architecture-technique.md)).
