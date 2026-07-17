#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$PROJECT_ROOT"

SKIP_BUILD=false
SKIP_START=false
SKIP_CONTROL_PLANE=false
FORCE_CERTS=false
REAPPLY_CONFIG=false
PREPARE_ONLY=false
PROXY_MODE=auto
PROXY_VALUE=""
HEALTH_TIMEOUT="${INIT_HEALTH_TIMEOUT:-120}"

usage() {
  cat <<'EOF'
PQC Migration Gateway v3.6 system initializer

Usage:
  ./scripts/init_system.sh [options]
  make init INIT_ARGS="[options]"

Options:
  --skip-build          Use an existing pq-gateway:3.6 image.
  --skip-start          Prepare and publish configuration without starting containers.
  --skip-control-plane  Do not start the optional manager-api profile.
  --prepare-only        Do not require Docker; prepare secrets, PKI and initial release only.
  --force-certs         Regenerate the complete demo PKI (destructive certificate rotation).
  --reapply-config      Create a new configuration release even if desired.json exists.
  --proxy URL           Use an explicit proxy for the Docker build.
  --no-proxy            Build without the WSL proxy.
  -h, --help            Show this help.

The script never overwrites real values already present in .env. Demo certificates
are generated only when missing unless --force-certs is supplied.
EOF
}

log() {
  printf '[init] %s\n' "$*"
}

die() {
  printf '[init] ERROR: %s\n' "$*" >&2
  exit 1
}

need_command() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

env_value() {
  local key="$1"
  awk -v key="$key" 'index($0, key "=") == 1 { print substr($0, length(key) + 2); exit }' .env
}

set_env_value() {
  local key="$1"
  local value="$2"
  local temporary
  temporary="$(mktemp .env.tmp.XXXXXX)"
  awk -v key="$key" -v value="$value" '
    BEGIN { found=0 }
    index($0, key "=") == 1 { print key "=" value; found=1; next }
    { print }
    END { if (!found) print key "=" value }
  ' .env >"$temporary"
  chmod 600 "$temporary"
  mv "$temporary" .env
}

ensure_secret() {
  local key="$1"
  local current
  current="$(env_value "$key")"
  case "$current" in
    ""|replace-with-openssl-rand-hex-32|replace-with-a-different-openssl-rand-hex-32)
      set_env_value "$key" "$(openssl rand -hex 32)"
      log "generated ${key} in .env"
      ;;
    *)
      log "kept existing ${key} in .env"
      ;;
  esac
}

demo_pki_complete() {
  local path
  for path in \
    certs/ca.crt certs/ca.key certs/server.crt certs/server.key \
    certs/client.crt certs/client.key certs/untrusted/client.crt \
    certs/upstream/ca.crt certs/upstream/server.crt certs/upstream/server.key \
    certs/upstream/client.crt certs/upstream/client.key certs/wrong-upstream-ca.crt; do
    [[ -s "$path" ]] || return 1
  done
}

generate_demo_pki() {
  local log_file="runtime-data/control/pki-init.log"
  if ! ./certs/gen-classic-demo-certs.sh ./certs >"$log_file" 2>&1; then
    tail -n 80 "$log_file" >&2 || true
    die "demo PKI generation failed; see ${log_file}"
  fi
  log "demo PKI generation completed"
}

wait_for_gateway() {
  local deadline=$((SECONDS + HEALTH_TIMEOUT))
  local status=""
  log "waiting for pq-gateway health (timeout ${HEALTH_TIMEOUT}s)"
  while (( SECONDS < deadline )); do
    status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' pq-gateway 2>/dev/null || true)"
    case "$status" in
      healthy)
        log "pq-gateway is healthy"
        return 0
        ;;
      unhealthy|exited|dead)
        docker compose logs --tail=80 pq-gateway >&2 || true
        die "pq-gateway entered state: ${status}"
        ;;
    esac
    sleep 3
  done
  docker compose logs --tail=80 pq-gateway >&2 || true
  die "pq-gateway did not become healthy; last state: ${status:-unknown}"
}

while (($#)); do
  case "$1" in
    --skip-build) SKIP_BUILD=true ;;
    --skip-start) SKIP_START=true ;;
    --skip-control-plane) SKIP_CONTROL_PLANE=true ;;
    --force-certs) FORCE_CERTS=true ;;
    --reapply-config) REAPPLY_CONFIG=true ;;
    --prepare-only)
      PREPARE_ONLY=true
      SKIP_BUILD=true
      SKIP_START=true
      ;;
    --proxy)
      shift
      (($#)) || die "--proxy requires a URL"
      PROXY_MODE=explicit
      PROXY_VALUE="$1"
      ;;
    --no-proxy)
      PROXY_MODE=none
      PROXY_VALUE=""
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "unknown option: $1"
      ;;
  esac
  shift
done

[[ "$HEALTH_TIMEOUT" =~ ^[0-9]+$ ]] || die "INIT_HEALTH_TIMEOUT must be an integer"

need_command awk
need_command make
need_command openssl
need_command python3

if [[ "$PREPARE_ONLY" != true ]]; then
  need_command docker
  docker compose version >/dev/null 2>&1 || die "Docker Compose V2 is required (docker compose)"
  docker info >/dev/null 2>&1 || die "Docker daemon is not available to the current user"
fi

log "initializing workspace at ${PROJECT_ROOT}"
mkdir -p runtime-data/logs runtime-data/metrics runtime-data/scans runtime-data/control

if [[ ! -f .env ]]; then
  umask 077
  cp .env.example .env
  chmod 600 .env
  log "created .env from .env.example"
else
  chmod 600 .env
  log "using existing .env"
fi

ensure_secret MANAGER_API_TOKEN
ensure_secret PQ_CONFIG_SIGNING_KEY

if [[ "$FORCE_CERTS" == true ]]; then
  log "regenerating the complete demo PKI"
  generate_demo_pki
elif demo_pki_complete; then
  log "demo PKI already exists; leaving it unchanged"
else
  log "demo PKI is incomplete; generating it"
  generate_demo_pki
fi

log "validating the unified service configuration"
python3 scripts/render_gateway_config.py \
  --config config/services.json \
  --output /tmp/pq-gateway-v3.6-init-nginx.conf \
  --check

if [[ ! -f runtime-data/control/desired.json || "$REAPPLY_CONFIG" == true ]]; then
  log "creating the initial signed configuration release"
  PQ_CONFIG_SIGNING_KEY="$(env_value PQ_CONFIG_SIGNING_KEY)" \
    python3 manager/pqctl.py --operator system-init config apply --file config/services.json | \
    python3 -c 'import json,sys; release=json.load(sys.stdin); print("[init] staged configuration version {}".format(release["version"]))'
else
  log "desired configuration already exists; skipping initial release"
fi

if [[ "$SKIP_BUILD" != true ]]; then
  case "$PROXY_MODE" in
    explicit) ;;
    none) PROXY_VALUE="" ;;
    auto)
      if [[ -n "${WSL_DISTRO_NAME:-}" ]]; then
        PROXY_VALUE="$(env_value WSL_PROXY)"
      else
        PROXY_VALUE=""
      fi
      ;;
  esac
  if [[ -n "$PROXY_VALUE" ]]; then
    log "building the gateway image with the configured proxy"
  else
    log "building the gateway image without a proxy"
  fi
  make build WSL_PROXY="$PROXY_VALUE"
else
  log "image build skipped"
fi

if [[ "$SKIP_START" != true ]]; then
  log "starting gateway, demo backends and metrics agent"
  docker compose up -d --no-build --force-recreate
  wait_for_gateway
  if [[ "$SKIP_CONTROL_PLANE" != true ]]; then
    log "starting manager-api control plane"
    docker compose --profile control-plane up -d manager-api
  fi
  docker compose ps
else
  log "container startup skipped"
fi

cat <<'EOF'

Initialization completed.

Useful commands:
  docker compose ps
  make logs
  python3 manager/pqctl.py config history
  python3 manager/pqctl.py agent list
  curl http://127.0.0.1:18080/metrics
EOF
