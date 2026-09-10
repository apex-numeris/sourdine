#!/usr/bin/env bash
# Détruit la cible éphémère Sourdine et tout son état (conteneurs + volumes + réseau).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
docker compose -p sourdine -f "$HERE/target/docker-compose.yml" down -v -t 3
echo "Cible éphémère détruite."
