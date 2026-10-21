# Politique de sécurité

*Version de référence. English version below.*

## Périmètre

Sourdine est un banc de mesure. Sa cible (Prometheus, Alertmanager, exporter et sink en
conteneurs) est éphémère : liée à `127.0.0.1`, montée par le banc, détruite à la fin de
chaque campagne. Elle n'est jamais un système de production et n'a pas vocation à être
exposée. Les vulnérabilités qui nous intéressent sont celles du banc lui-même : moteur,
runner, scripts, scénarios, intégration continue et choix des images épinglées.

## Signaler une vulnérabilité

Deux voies, au choix :

1. le signalement privé de GitHub, onglet Security du dépôt, bouton « Report a vulnerability ».
2. un courriel à qnn@apex-numeris.com, objet commençant par `[sourdine]`.

Merci de ne pas ouvrir d'issue publique avant un premier échange.

## Engagements

| Étape | Délai |
|---|---|
| Accusé de réception | une semaine ouvrée |
| Qualification (atteignable ou non dans l'usage du banc, gravité) | deux semaines ouvrées |
| Correctif | dans la semaine si la faille est atteignable dans l'usage du banc, sinon au plus tard dans la version suivante |
| Mention dans `CHANGELOG.md` | avec l'accord du rapporteur |

## Versions prises en charge

Seule la dernière version publiée (dernier tag `v*`) reçoit des correctifs. Les images
épinglées de la cible (`target/docker-compose.yml`) sont surveillées par Dependabot et
montées en version quand un avis de sécurité les concerne.

---

# Security policy

## Scope

Sourdine is a measurement benchmark. Its target (Prometheus, Alertmanager, exporter and
sink in containers) is ephemeral: bound to `127.0.0.1`, brought up by the benchmark and
destroyed at the end of every campaign. It is never a production system and is not meant
to be exposed. The vulnerabilities we care about are those of the benchmark itself:
engine, runner, scripts, scenarios, continuous integration and the choice of pinned images.

## Reporting a vulnerability

Two channels, at your choice:

1. GitHub private reporting, Security tab of the repository, "Report a vulnerability" button.
2. an e-mail to qnn@apex-numeris.com, subject starting with `[sourdine]`.

Please do not open a public issue before a first exchange.

## Commitments

| Step | Delay |
|---|---|
| Acknowledgement | one working week |
| Qualification (reachable or not in the benchmark's use, severity) | two working weeks |
| Fix | within a week if the flaw is reachable in the benchmark's use, otherwise in the next release at the latest |
| Mention in `CHANGELOG.md` | with the reporter's consent |

## Supported versions

Only the latest published version (latest `v*` tag) receives fixes. The pinned images of
the target (`target/docker-compose.yml`) are watched by Dependabot and upgraded when a
security advisory concerns them.
