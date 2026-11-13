#!/usr/bin/env bash
# Run on the intended local computer or authorized Linux server. No remote SSH.
set -euo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
MODE=local
PORT=8000
DOMAIN=''
CHECK_ONLY=false
NO_BROWSER=false
while (($#)); do
  case "$1" in
    --mode) MODE="${2:?Missing local/server mode}"; shift 2 ;;
    --port) PORT="${2:?Missing port}"; shift 2 ;;
    --domain) DOMAIN="${2:?Missing domain}"; shift 2 ;;
    --check-only) CHECK_ONLY=true; shift ;;
    --no-browser) NO_BROWSER=true; shift ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done
[[ "$MODE" == local || "$MODE" == server ]] || { echo 'Choose --mode local or server.' >&2; exit 2; }
[[ "$PORT" =~ ^[0-9]{4,5}$ ]] && ((10#$PORT >= 1024 && 10#$PORT <= 65535)) || { echo 'Port must be 1024-65535.' >&2; exit 2; }
[[ "$ROOT" != *,* ]] || { echo 'Use a project path without commas.' >&2; exit 2; }
if [[ "$MODE" == server ]]; then
  [[ "$(uname -s)" == Linux ]] || { echo 'Server mode supports Linux Docker hosts.' >&2; exit 2; }
  [[ -n "$DOMAIN" ]] || { echo 'Server mode needs --domain with your public DNS hostname.' >&2; exit 2; }
fi
command -v docker >/dev/null || { echo 'Install and start Docker with the Compose v2 plugin, then rerun. See docs/LOCAL_SETUP.md or docs/SERVER_SETUP.md.' >&2; exit 1; }
if [[ -n "${DOCKER_HOST:-}" && ! "${DOCKER_HOST}" =~ ^unix:// ]]; then
  echo 'Remote DOCKER_HOST is not supported; run this script on the intended machine.' >&2; exit 1
fi
ENDPOINT="$(docker context inspect --format '{{.Endpoints.docker.Host}}')"
[[ "$ENDPOINT" == unix://* ]] || { echo 'Select a local Docker context first.' >&2; exit 1; }
[[ "$(docker info --format '{{.OSType}}')" == linux ]] || { echo 'A running Linux-container Docker engine is required.' >&2; exit 1; }
VERSION="$(docker compose version --short)"
if [[ "$VERSION" =~ ^v?([0-9]+)\.([0-9]+) ]]; then
  (( BASH_REMATCH[1] > 2 || (BASH_REMATCH[1] == 2 && BASH_REMATCH[2] >= 24) )) || { echo 'Compose v2.24+ required.' >&2; exit 1; }
else echo 'Could not verify Docker Compose version.' >&2; exit 1; fi
printf 'Compatible Docker engine and Compose found for %s mode.\n' "$MODE"
if $CHECK_ONLY; then echo 'Read-only check complete. No configuration or containers changed.'; exit 0; fi
if env | cut -d= -f1 | grep -Eq '^(UNIVERSALMAIL_|GOOGLE_CLIENT_|MICROSOFT_CLIENT_|MICROSOFT_TENANT$)'; then
  echo 'Deployment environment overrides found. Use a clean shell or manual Compose; no values were overwritten.' >&2; exit 1
fi
docker build -t universalmail:0.5.0 .
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" --mount "type=bind,source=$ROOT,target=/workspace" \
  --entrypoint python universalmail:0.5.0 /app/scripts/configure.py \
  --directory /workspace --mode "$MODE" --port "$PORT" --domain "$DOMAIN"
chmod 600 .env
COMPOSE=compose.yaml
[[ "$MODE" == local ]] || COMPOSE=compose.server.yaml
docker compose --env-file .env -p universalmail -f "$COMPOSE" up -d --wait --wait-timeout 120
# Verify from inside the container, not by assuming a start command implies readiness.
docker compose --env-file .env -p universalmail -f "$COMPOSE" exec -T universalmail python -c \
  "import json,urllib.request; h=json.load(urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=5)); assert h['service']=='universalmail' and h['status']=='ok' and h['version']=='0.5.0'; print('Backend container health verified.')"
URL="http://localhost:$PORT/setup"
if [[ "$MODE" == server ]]; then
  URL="https://$DOMAIN/setup"
  echo 'Container ready; public DNS, inbound access and issued HTTPS certificate still require external verification.'
fi
printf 'Setup: %s\n' "$URL"
echo 'Use UNIVERSALMAIL_API_KEY from .env to unlock the page. No mailbox connected; ChatGPT MCP connection not yet implemented.'
if [[ "$MODE" == local ]] && ! $NO_BROWSER; then
  if command -v xdg-open >/dev/null; then xdg-open "$URL" >/dev/null 2>&1 || true
  elif command -v open >/dev/null; then open "$URL" || true; fi
fi
