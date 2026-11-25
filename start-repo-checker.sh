#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f .env ] && [ -f .env.example ]; then
  echo "Creating .env from .env.example..."
  cp .env.example .env
fi

PORT="${GATEKEEPER_PORT:-8088}"
if [ -f .env ]; then
  ENV_PORT=$(grep -E '^GATEKEEPER_PORT=' .env | cut -d '=' -f2- | tr -d '\r' || true)
  if [ -n "$ENV_PORT" ]; then
    PORT="$ENV_PORT"
  fi
fi

echo "Building and starting Repo Gatekeeper..."
docker compose up -d --build

echo "Waiting for Repo Gatekeeper on http://localhost:${PORT} ..."
for _ in $(seq 1 30); do
  if curl -fsS "http://localhost:${PORT}/api/config" >/dev/null 2>&1; then
    echo "Repo Gatekeeper is running at: http://localhost:${PORT}"
    echo "View logs with: docker compose logs -f"
    exit 0
  fi
  sleep 1
done

echo "Container started, but health check did not respond within 30s. Check logs:"
docker compose logs --tail=30
