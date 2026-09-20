# 01. Expression des besoins

## 1. Contexte

SentinelleIA protège des appels LLM via une chaîne d'agents, et sa **supervision**
(Prometheus + Alertmanager) lève des alarmes de sécurité : `HighAttackRate`,
`CriticalAttacksDetected`, `JailbreakSurge`, `DataExfiltrationAttempt`, etc. Un
adversaire averti n'a pas besoin de vaincre les détecteurs : il lui suffit
d'empêcher l'alarme de **sortir**. C'est le **masquage d'alarme**.

Contrairement à une injection de prompt ou une exfiltration (où l'on attaque un
agent et mesure si l'attaque aboutit), le masquage vise **l'observateur**. Le
signal de détection peut être correct ; c'est son *acheminement en alarme* qui est
supprimé ou étouffé.

## 2. Problème à résoudre

Il n'existe pas, dans le projet, d'instrument pour **mesurer** la résistance de la
chaîne d'alerte au masquage, ni pour **évaluer objectivement** un détecteur de
masquage. Sans cet instrument :

- on ne connaît pas le *danger côté client* (combien d'attaques de masquage
  passeraient si rien ne protégeait la chaîne d'alerte) ;
- on ne peut pas *chiffrer la valeur* d'un détecteur de masquage, ni son *coût
  opérationnel* (faux positifs) ;
- on ne peut pas comparer deux détecteurs sur un protocole commun et reproductible.

## 3. Parties prenantes

| Partie prenante | Intérêt |
|---|---|
| Équipe sécurité SentinelleIA | Mesurer et améliorer la résistance au masquage ; brancher le vrai détecteur |
| Direction (CEO) | Chiffres défendables (citables), preuve de rigueur, futur dépôt public (`sourdine.org`) |
| Ops / SRE | Comprendre le coût opérationnel (faux positifs) avant d'activer un détecteur |
| Auditeur externe | Protocole transparent, jeu de scénarios ouvert, résultats reproductibles |

## 4. Besoins fonctionnels

- **BF1. Modéliser deux objets par scénario** : l'événement qui devait lever une
  alarme, et la manœuvre qui fait disparaître ce signalement.
- **BF2. Mesure en deux passes** : observer l'alarme **sans** détecteur (passe 1),
  puis soumettre l'état + la trace à un **détecteur** (passe 2).
- **BF3. Catalogue de vecteurs** : au moins les six vecteurs retenus (spoof
  `FirewallDown` / `InstanceDown` / `PostgreSQLDown`, low-and-slow, abus de
  silence / groupement, coupure d'exporter), chacun portant son **hypothèse
  d'accès attaquant**.
- **BF4. Scénarios sains** : cas graves sans attaque (contrôle de cohérence) et
  activités légitimes ressemblant à un vecteur (pièges à faux positif).
- **BF5. Quatre taux + cohérence** : suppression réussie, rattrapage, faux
  positifs, suppression résiduelle ; plus un contrôle de cohérence ; le tout
  **ventilé par niveau d'accès attaquant**.
- **BF6. Détecteur derrière une interface stable** : une baseline fournie, et un
  point de branchement pour le vrai détecteur SentinelleIA (hors banc).
- **BF7. Cible éphémère autonome** : le banc monte et détruit sa propre cible
  (Prometheus + Alertmanager), jamais la supervision réelle.
- **BF8. Sortie machine versionnée** : rapport JSON à schéma versionné + résumé
  lisible ; jeu de scénarios ouvert et citable, séparé du code.

## 5. Besoins non fonctionnels

- **BNF1. Isolement / innocuité** : tout synthétique, en laboratoire ; aucune
  config de production modifiée ; cible liée à `127.0.0.1`.
- **BNF2. Reproductibilité** : un backend déterministe (sim) donnant des taux
  stables, indépendants de la machine.
- **BNF3. Fidélité** : un backend sur de **vrais** Prometheus + Alertmanager pour
  valider le comportement réel.
- **BNF4. Zéro dépendance tierce** : bibliothèque standard Python uniquement (la
  campagne doit tourner à blanc sans installation réseau).
- **BNF5. Honnêteté de la baseline** : heuristiques volontairement imparfaites :
  faux positifs et suppression résiduelle **non nuls** et crédibles.
- **BNF6. Citabilité** : versionnement du format de sortie et du jeu de scénarios.
- **BNF7. Extensibilité** : ajouter un vecteur ou un scénario sans refondre le moteur.

## 6. Règle de cotation (normative)

Le statut de masquage se lit **sur la passe SANS détecteur**. Une alarme attendue
qui ne sort pas est un **masquage réussi**, même si le détecteur la rattrape
ensuite. On ne cote jamais un scénario « non concerné » au motif que la protection
l'a rattrapé.

## 7. Périmètre

**Dans le périmètre** : le banc, sa cible éphémère, le jeu de scénarios, le
détecteur baseline, le format de sortie, la documentation.

**Hors périmètre** (étapes ultérieures, côté CEO) : le vrai détecteur SentinelleIA
(se branche au même protocole), la publication Zenodo/HAL, les licences du dépôt
public. Le banc **n'évalue jamais** le produit SentinelleIA tant que le vrai
détecteur n'est pas branché.

## 8. Critères de succès

- Les quatre taux + la cohérence sont produits, ventilés par niveau d'accès.
- La baseline présente des faux positifs **et** une suppression résiduelle non nuls.
- Le contrôle de cohérence approche 100 % (la cible n'est pas cassée).
- Un run déterministe (sim) et un run fidèle (docker) sont tous deux exécutables,
  la cible étant montée et détruite par le banc, sans toucher la production.

## 9. Contraintes et hypothèses

- Python ≥ 3.10 ; Docker + Compose v2 pour le backend docker.
- La chaîne d'alerte cible est représentative (règles + inhibitions **recréées**,
  jamais copiées de la production).
- L'attaquant dispose, selon le vecteur, d'un niveau d'accès déclaré (cf. doc 05) ;
  le rapport ventile par ce niveau pour rester défendable face à l'objection
  « l'attaquant n'a pas cet accès ».
