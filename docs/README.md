# Documentation Sourdine

Documentation complète du **banc d'attaques de masquage d'alarme** (projet Sourdine).
Version du banc : **0.1.0**. Langue : français. Support : Markdown versionné (diagrammes mermaid).

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
  catalogue de scénarios étiquetés (9 vecteurs + scénarios sains), et calcule
  quatre taux + un contrôle de cohérence, ventilés par niveau d'accès attaquant.
- **Garde-fous** : tout est synthétique et en laboratoire ; la cible n'est jamais
  la supervision de production ; le banc évalue une **baseline** de détection, pas
  le produit SentinelleIA (qui se branchera au même protocole).
- **État** : v0.1.0, deux backends fonctionnels.
  - Référence **sim** (déterministe) : suppression 100 % / rattrapage 75 % / faux
    positifs 33 % / résiduel 25 % / cohérence 100 %.
  - **docker** (vrais conteneurs) : 87,5 / 85,7 / 33,3 / 12,5 / 100 % — divergence
    unique sur la noyade par groupement (constat de fidélité, cf. doc 04/05).

## Historique (branche `feature/masquage-alarmes`)

- `3bf6467d` — banc Sourdine v0.1.0 (moteur, scénarios, cible, détecteur baseline).
- `59c26c61` — backend docker fonctionnel + constats de fidélité.

> Le code source est sous `sourdine/` ; le `README.md` racine du projet est le
> point d'entrée rapide, cette documentation en est la version détaillée.
