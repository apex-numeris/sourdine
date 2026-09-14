# Documentation Sourdine

Documentation complète du **banc d'attaques de masquage d'alarme** (projet Sourdine).
Version du banc : **0.12.0**. Langue : français. Support : Markdown versionné (diagrammes mermaid).

Sourdine mesure la résistance d'une chaîne d'alerte (Prometheus / Alertmanager) au
**masquage d'alarme** : des attaques qui visent *l'observateur* — supprimer ou
étouffer un signal qui aurait dû lever une alarme — et non un agent applicatif.

## Jeu documentaire

| # | Document | Pour qui | Contenu |
|---|----------|----------|---------|
| 01 | [Expression des besoins](01-expression-des-besoins.md) | Décideur, archi | Problème, parties prenantes, exigences fonctionnelles et non fonctionnelles, périmètre, critères de succès |
| 02 | [Architecture fonctionnelle](02-architecture-fonctionnelle.md) | Archi, dev | Composants, flux, mesure en deux passes, interface détecteur |
| 03 | [Diagrammes de séquence](03-diagramme-de-sequence.md) | Dev | Exécution d'un scénario, cycle de vie de la cible, vecteur bout-en-bout |
| 04 | [Architecture technique](04-architecture-technique.md) | Dev, ops | Modules, backends sim/docker, cible éphémère, stack, ports/réseau |
| 05 | [Spécifications](05-specifications.md) | Dev | Schéma scénario, interface détecteur, définitions des taux, schéma du rapport JSON, ruleset |
| 06 | [Manuel utilisateur](06-manuel-utilisateur.md) | Utilisateur du banc | Installer, lancer une campagne, lire le rapport, ajouter un scénario |
| 07 | [Manuel administrateur](07-manuel-administrateur.md) | Ops | Gérer la cible, logs, nettoyage, brancher le vrai détecteur, CI |
| 08 | [Déploiement VPS production](08-deploiement-vps-production.md) | Ops/SRE | Publier un site de résultats en lecture seule pour l'internet, cible jamais exposée |

## Résumé exécutif

- **Pourquoi** : le masquage d'alarme n'est pas une injection ; l'attaque fait
  disparaître le *signalement*. On modélise donc deux objets par scénario
  (l'événement attendu + la manœuvre) et on mesure en **deux passes** (sans puis
  avec détecteur).
- **Quoi** : banc autonome et jetable. Il monte sa **propre** cible éphémère
  (Prometheus + Alertmanager isolés, ou un modèle sim en process), joue un
  catalogue de scénarios étiquetés (20 vecteurs + scénarios sains), et calcule
  quatre taux + un contrôle de cohérence, ventilés par niveau d'accès attaquant.
- **Garde-fous** : tout est synthétique et en laboratoire ; la cible n'est jamais
  la supervision de production ; le banc évalue une **baseline** de détection, pas
  le produit SentinelleIA (qui se branchera au même protocole).
- **État** : v0.12.0, deux backends fonctionnels ; 20 vecteurs / 43 scénarios
  (24 attaques / 19 sains).
  - Référence **sim** (déterministe) : suppression 100 % / rattrapage 83,3 % / faux
    positifs 10,5 % / résiduel 16,7 % / cohérence 100 %.
  - **docker** (vrais conteneurs) : 87,5 / 81,0 / 10,5 / 16,7 / 100 % — divergences de
    fidélité sur la noyade par groupement, le blackout sélectif, le faux all-clear et
    le rejeu/gel (cf. doc 04 §7). Masquages préventifs (inhibition/silence) durcis (cf.
    doc 04 §5.4). Le **full statistical concealment** (`statistical_replay`) reste résiduel
    (limite assumée) ; le **constrained replay** (sous-ensemble masqué) est rattrapé par la
    **consistance spatiale** (`spatial_incoherence`) — contraste ACSAC 2022. Le **route
    black-hole** (`route_blackhole`, MITRE T1562.006 Indicator Blocking) masque de façon
    déterministe dans les deux backends et est rattrapé par `notification_blackhole` ; le
    **watchdog suppression** (`watchdog_suppression`, MITRE T1562, dead man's switch) est
    rattrapé par `watchdog_gap` (heartbeat éteint) même quand tout le reste est aveuglé ; la
    **bombe de cardinalité** (`cardinality_flood`, MITRE Impair Defenses / T1499) fait échouer
    le scrape (sample_limit, `up`=0, fausse panne) et est rattrapée par `cardinality_flood`
    (pic de `scrape_samples`) là où les heuristiques d'absence voient une simple coupure ; la
    **règle d'inhibition rogue** (`rogue_inhibitor`, MITRE T1562.001) étouffe la classe sécurité
    par une source d'inhibition NON sanctionnée et est rattrapée par `rogue_inhibitor` (dérive de
    config vs baseline) là où l'heuristique d'inhibition, bornée aux sources sanctionnées, ne la voit
    pas ; la **panne induite du garde** (`guard_outage_cover`, MITRE T1562.001) coupe **réellement** le
    firewall AVANT d'attaquer, de sorte que l'inhibition **sanctionnée** `FirewallDown → classe sécurité`
    étouffe l'alerte en fonctionnant exactement comme prévu — la corroboration ne peut rien contre elle
    (la panne est vraie), et seule `guard_down_under_threat` la rattrape, sur la **concomitance** de la
    panne du garde et d'une menace réelle et soutenue.

## Historique (branche `feature/masquage-alarmes`)

- `3bf6467d` — banc Sourdine v0.1.0 (moteur, scénarios, cible, détecteur baseline).
- `59c26c61` — backend docker fonctionnel + constats de fidélité.

> Le code source est sous `sourdine/` ; le `README.md` racine du projet est le
> point d'entrée rapide, cette documentation en est la version détaillée.
