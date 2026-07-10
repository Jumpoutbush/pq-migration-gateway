#!/usr/bin/env bash
set -Eeuo pipefail

# PQC Migration Gateway end-to-end experiment script
#
# Assumptions:
#   1. Run from the pq-migration-gateway repository root.
#   2. The gateway image has already been built successfully.
#   3. docker-compose.yml keeps:
#        TLS_GROUPS: "X25519MLKEM768:X25519"
#
# Usage:
#   chmod +x scripts/run_full_experiment.sh
#   ./scripts/run_full_experiment.sh
#
# Optional:
#   COUNT=100 ./scripts/run_full_experiment.sh

EXPECTED_TLS_GROUPS="X25519MLKEM768:X25519"
BENCH_COUNT="${COUNT:-50}"
RESULT_ROOT="${RESULT_ROOT:-experiment-results}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RESULT_DIR="${RESULT_ROOT}/${TIMESTAMP}"

GATEWAY_SERVICE="pq-gateway"
BACKEND_SERVICE="bank-backend"
GATEWAY_CONTAINER="pq-gateway"
GATEWAY_HOSTNAME="bank-gateway.local"
GATEWAY_PORT="8443"
CA_FILE_HOST="certs/ca.crt"
CA_FILE_CONTAINER="/etc/pq-gateway/certs/ca.crt"
OPENSSL_BIN="/opt/openssl/bin/openssl"

mkdir -p "${RESULT_DIR}"

log() {
  printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

on_error() {
  local exit_code=$?
  printf '\nExperiment failed with exit code %s.\n' "${exit_code}" >&2
  docker compose ps -a >&2 || true
  docker compose logs --no-color --tail=100 "${GATEWAY_SERVICE}" >&2 || true
  exit "${exit_code}"
}
trap on_error ERR

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

require_file() {
  [[ -f "$1" ]] || die "Required file not found: $1"
}

wait_for_backend_health() {
  local retries=30
  local status=""

  for ((i = 1; i <= retries; i++)); do
    status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
      "${BACKEND_SERVICE}" 2>/dev/null || true)"
    if [[ "${status}" == "healthy" ]]; then
      return 0
    fi
    sleep 1
  done

  die "${BACKEND_SERVICE} did not become healthy"
}

wait_for_gateway_running() {
  local retries=30
  local status=""

  for ((i = 1; i <= retries; i++)); do
    status="$(docker inspect -f '{{.State.Status}}' "${GATEWAY_CONTAINER}" 2>/dev/null || true)"
    if [[ "${status}" == "running" ]]; then
      return 0
    fi
    sleep 1
  done

  die "${GATEWAY_SERVICE} did not remain running"
}

run_handshake() {
  local group="$1"
  local output_file="$2"
  local expected_pattern="$3"

  log "Testing TLS 1.3 group: ${group}"

  docker compose exec -T "${GATEWAY_SERVICE}" \
    "${OPENSSL_BIN}" s_client \
    -connect "localhost:${GATEWAY_PORT}" \
    -servername "${GATEWAY_HOSTNAME}" \
    -tls1_3 \
    -groups "${group}" \
    -CAfile "${CA_FILE_CONTAINER}" \
    -brief \
    </dev/null 2>&1 | tee "${output_file}"

  grep -q "Verification: OK" "${output_file}" \
    || die "Certificate verification failed for group ${group}"

  grep -Eq "${expected_pattern}" "${output_file}" \
    || die "Expected negotiated group not found for ${group}"
}

run_http_get() {
  local path="$1"
  local output_file="$2"

  log "Requesting HTTPS endpoint: ${path}"

  curl \
    --noproxy '*' \
    --fail-with-body \
    --silent \
    --show-error \
    --connect-timeout 10 \
    --max-time 30 \
    --resolve "${GATEWAY_HOSTNAME}:${GATEWAY_PORT}:127.0.0.1" \
    --cacert "${CA_FILE_HOST}" \
    "https://${GATEWAY_HOSTNAME}:${GATEWAY_PORT}${path}" \
    | tee "${output_file}"

  printf '\n'
}

run_http_transfer() {
  local output_file="$1"

  log "Submitting demo transfer through the gateway"

  curl \
    --fail-with-body \
    --silent \
    --show-error \
    --connect-timeout 10 \
    --max-time 30 \
    --resolve "${GATEWAY_HOSTNAME}:${GATEWAY_PORT}:127.0.0.1" \
    --cacert "${CA_FILE_HOST}" \
    -H 'Content-Type: application/json' \
    -d '{"from":"demo-001","to":"demo-002","amount":"100.00","currency":"CNY"}' \
    "https://${GATEWAY_HOSTNAME}:${GATEWAY_PORT}/api/transfer" \
    | tee "${output_file}"

  printf '\n'
}

run_benchmark() {
  local group="$1"
  local container_output="$2"
  local host_output="$3"

  log "Benchmarking ${group} with ${BENCH_COUNT} handshakes"

  docker compose exec -T "${GATEWAY_SERVICE}" \
    python3 /workspace/scripts/bench_handshake.py \
    --host "${GATEWAY_SERVICE}" \
    --port "${GATEWAY_PORT}" \
    --sni "${GATEWAY_HOSTNAME}" \
    --groups "${group}" \
    --openssl "${OPENSSL_BIN}" \
    --cafile "${CA_FILE_CONTAINER}" \
    --count "${BENCH_COUNT}" \
    --out "${container_output}"

  docker compose cp \
    "${GATEWAY_SERVICE}:${container_output}" \
    "${host_output}"
}

write_summary() {
  local summary_file="${RESULT_DIR}/SUMMARY.md"

  cat >"${summary_file}" <<EOF
# PQC Migration Gateway Experiment Summary

- Generated at: ${TIMESTAMP}
- TLS policy: \`${EXPECTED_TLS_GROUPS}\`
- Benchmark repetitions: ${BENCH_COUNT}

## Validated functions

- Docker services started successfully.
- Backend health check passed.
- Gateway remained running.
- TLS 1.3 Hybrid handshake succeeded with \`X25519MLKEM768\`.
- TLS 1.3 classical fallback succeeded with \`X25519\`.
- HTTPS reverse-proxy health endpoint succeeded.
- Demo balance endpoint succeeded.
- Demo transfer endpoint succeeded.
- Static cryptographic inventory completed.
- Handshake benchmark completed for both groups.

## Result files

- \`docker-compose-ps.txt\`
- \`openssl-version.txt\`
- \`nginx-build.txt\`
- \`tls-hybrid.txt\`
- \`tls-x25519.txt\`
- \`healthz.txt\`
- \`balance.json\`
- \`transfer.json\`
- \`crypto-inventory.json\`
- \`crypto-inventory.csv\`
- \`handshake-hybrid.json\`
- \`handshake-x25519.json\`
- \`gateway-logs.txt\`
EOF
}

main() {
  require_command docker
  require_command curl
  require_command python3
  require_file docker-compose.yml
  require_file "${CA_FILE_HOST}"
  require_file scripts/crypto_inventory.py

  docker compose version >/dev/null

  local configured_groups
  configured_groups="$(
    docker compose config |
      awk '$1 == "TLS_GROUPS:" {gsub(/"/, "", $2); print $2; exit}'
  )"

  [[ "${configured_groups}" == "${EXPECTED_TLS_GROUPS}" ]] \
    || die "TLS_GROUPS must remain ${EXPECTED_TLS_GROUPS}; current value: ${configured_groups:-<empty>}"

  log "TLS policy verified: ${configured_groups}"
  log "Starting existing images without rebuilding"

  docker compose up -d --no-build
  wait_for_backend_health
  wait_for_gateway_running

  docker compose ps | tee "${RESULT_DIR}/docker-compose-ps.txt"

  log "Recording OpenSSL and NGINX build information"

  docker compose exec -T "${GATEWAY_SERVICE}" \
    "${OPENSSL_BIN}" version -a \
    >"${RESULT_DIR}/openssl-version.txt" 2>&1

  docker compose exec -T "${GATEWAY_SERVICE}" \
    /opt/nginx/sbin/nginx -V \
    >"${RESULT_DIR}/nginx-build.txt" 2>&1

  run_handshake \
    "X25519MLKEM768" \
    "${RESULT_DIR}/tls-hybrid.txt" \
    'Negotiated TLS1\.3 group: X25519MLKEM768|Server Temp Key: X25519MLKEM768|Peer Temp Key: X25519MLKEM768'

  run_handshake \
    "X25519" \
    "${RESULT_DIR}/tls-x25519.txt" \
    'Negotiated TLS1\.3 group: X25519([^A-Za-z0-9]|$)|Peer Temp Key: X25519([^A-Za-z0-9]|$)'

  run_http_get "/healthz" "${RESULT_DIR}/healthz.txt"
  run_http_get "/api/balance" "${RESULT_DIR}/balance.json"
  run_http_transfer "${RESULT_DIR}/transfer.json"

  log "Running static cryptographic inventory"

  python3 scripts/crypto_inventory.py \
    --root ./certs \
    --root ./gateway \
    --root ./docker-compose.yml \
    --out-json "${RESULT_DIR}/crypto-inventory.json" \
    --out-csv "${RESULT_DIR}/crypto-inventory.csv"

  run_benchmark \
    "X25519MLKEM768" \
    "/tmp/handshake-hybrid.json" \
    "${RESULT_DIR}/handshake-hybrid.json"

  run_benchmark \
    "X25519" \
    "/tmp/handshake-x25519.json" \
    "${RESULT_DIR}/handshake-x25519.json"

  docker compose logs --no-color --tail=300 "${GATEWAY_SERVICE}" \
    >"${RESULT_DIR}/gateway-logs.txt"

  write_summary

  log "All experiments completed successfully"
  log "Results directory: ${RESULT_DIR}"
  printf '\nOpen the summary:\n  %s\n' "${RESULT_DIR}/SUMMARY.md"
}

main "$@"
