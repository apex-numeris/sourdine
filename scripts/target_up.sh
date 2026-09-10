#!/usr/bin/env bash
# Monte la cible éphémère Sourdine (Prometheus + Alertmanager + exporter + sink).
# Isolée et jetable ; ports sur 127.0.0.1. N'affecte aucun stack de production.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
docker compose -p sourdine -f "$HERE/target/docker-compose.yml" up -d
echo "Cible éphémère montée :"
echo "  Prometheus   http://127.0.0.1:39090"
echo "  Alertmanager http://127.0.0.1:39093"
echo "  Exporter     http://127.0.0.1:39080/metrics"
echo "  Sink         http://127.0.0.1:39099/received"
echo "Arrêt + purge : scripts/target_down.sh"
