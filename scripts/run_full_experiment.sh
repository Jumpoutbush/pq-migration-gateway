#!/usr/bin/env bash
set -Eeuo pipefail

# PQC Migration Gateway v2 end-to-end experiment.
# Usage:
#   ./scripts/run_full_experiment.sh
#   COUNT=100 BUILD=1 ./scripts/run_full_experiment.sh

BENCH_COUNT="${COUNT:-50}"
BUILD="${BUILD:-0}"
RESULT_ROOT="${RESULT_ROOT:-experiment-results}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RESULT_DIR="${RESULT_ROOT}/${TIMESTAMP}"
GATEWAY_SERVICE="pq-gateway"
GATEWAY_CONTAINER="pq-gateway"
BACKEND_CONTAINER="bank-backend"
OPENSSL_BIN="/opt/openssl/bin/openssl"
CA_CONTAINER="/etc/pq-gateway/certs/ca.crt"
CA_HOST="certs/ca.crt"

mkdir -p "$RESULT_DIR"

log() { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
require() { command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"; }

on_error() {
  local code=$?
  printf '\nExperiment failed with exit code %s.\n' "$code" >&2
  docker compose ps -a >&2 || true
  docker compose logs --no-color --tail=120 "$GATEWAY_SERVICE" >&2 || true
  exit "$code"
}
trap on_error ERR

wait_container() {
  local container="$1" expected="$2" retries=60 status=""
  for ((i=1; i<=retries; i++)); do
    status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container" 2>/dev/null || true)"
    [[ "$status" == "$expected" ]] && return 0
    sleep 1
  done
  die "$container did not reach state $expected (last state: ${status:-missing})"
}

handshake_success() {
  local port="$1" sni="$2" group="$3" output="$4"
  log "TLS success test: ${sni}:${port} group=${group}"
  docker compose exec -T "$GATEWAY_SERVICE" \
    "$OPENSSL_BIN" s_client -connect "localhost:${port}" -servername "$sni" \
    -tls1_3 -groups "$group" -CAfile "$CA_CONTAINER" -verify_return_error -brief \
    </dev/null >"$output" 2>&1
  cat "$output"
  grep -q 'Verification: OK' "$output"
  grep -Eq "Negotiated TLS1\\.3 group: ${group}|Server Temp Key: ${group}|Peer Temp Key: ${group}" "$output"
}

handshake_expected_failure() {
  local port="$1" sni="$2" group="$3" output="$4"
  local rc

  log "TLS rejection test: ${sni}:${port} group=${group}"

  if docker compose exec -T "$GATEWAY_SERVICE" \
    "$OPENSSL_BIN" s_client \
      -connect "localhost:${port}" \
      -servername "$sni" \
      -tls1_3 \
      -groups "$group" \
      -CAfile "$CA_CONTAINER" \
      -brief \
      </dev/null >"$output" 2>&1
  then
    rc=0
  else
    rc=$?
  fi

  cat "$output"

  if grep -q 'Verification: OK' "$output" &&
     grep -Eq 'Negotiated TLS1\.3 group:|Server Temp Key:|Peer Temp Key:' "$output"
  then
    die "Expected ${sni}:${port} to reject group ${group}, but TLS succeeded"
  fi

  if [[ $rc -eq 0 ]]; then
    die "Expected TLS rejection, but openssl returned success"
  fi

  if grep -Eqi \
    'alert handshake failure|alert number 40|no suitable key share|handshake failure' \
    "$output"
  then
    log "Expected TLS rejection confirmed"
  else
    log "TLS connection was rejected with exit code ${rc}"
  fi
}

http_get_host() {
  local port="$1" sni="$2" path="$3" output="$4"
  curl --noproxy '*' --fail-with-body --silent --show-error \
    --connect-timeout 10 --max-time 30 \
    --resolve "${sni}:${port}:127.0.0.1" --cacert "$CA_HOST" \
    "https://${sni}:${port}${path}" | tee "$output"
  printf '\n'
}

http_with_openssl() {
  local port="$1" sni="$2" group="$3" path="$4" output="$5"
  set +e
  printf 'GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$path" "$sni" | \
    timeout 20s docker compose exec -T "$GATEWAY_SERVICE" \
      "$OPENSSL_BIN" s_client -quiet -connect "localhost:${port}" -servername "$sni" \
      -tls1_3 -groups "$group" -CAfile "$CA_CONTAINER" -verify_return_error \
      >"$output" 2>&1
  set -e
  grep -q '200 OK' "$output" || { cat "$output"; die "HTTP request failed for ${sni}:${port} group=${group}"; }
}

benchmark() {
  local port="$1" sni="$2" group="$3" container_out="$4" host_out="$5"
  log "Benchmark: ${sni}:${port} group=${group} count=${BENCH_COUNT}"
  docker compose exec -T "$GATEWAY_SERVICE" \
    python3 /workspace/scripts/bench_handshake.py \
      --host localhost --port "$port" --sni "$sni" --groups "$group" \
      --openssl "$OPENSSL_BIN" --cafile "$CA_CONTAINER" --count "$BENCH_COUNT" \
      --out "$container_out"
  docker cp "${GATEWAY_CONTAINER}:${container_out}" "$host_out"
}

write_summary() {
  python3 - "$RESULT_DIR" "$BENCH_COUNT" <<'PY'
import json, sys
from pathlib import Path
root=Path(sys.argv[1]); count=sys.argv[2]
def load(name):
    p=root/name
    return json.loads(p.read_text()) if p.exists() else {}
static=load('crypto-inventory.json').get('summary', {})
tls=load('tls-inventory.json').get('summary', {})
risk=load('risk-report.json').get('summary', {})
verify=load('migration-verification.json').get('summary', {})
fallback=load('fallback-report.json').get('summary', {})
db=load('inventory-db-summary.json')
text=f'''# PQC Migration Gateway v2 Experiment Summary

## Result

- Multi-service configuration: validated
- Compatibility endpoint: Hybrid/PQC and X25519 both accepted
- Strict endpoint: Hybrid/PQC accepted and X25519 rejected
- Transparent reverse proxy: validated with protocol-neutral service endpoints
- Static cryptographic inventory: completed
- Online TLS inventory: completed
- Risk assessment and SQLite import: completed
- Migration policy verification: {verify.get("passed", 0)}/{verify.get("services", 0)} passed
- Handshake benchmark repetitions per group: {count}

## Inventory

- Concrete assets: {static.get("concrete_assets", 0)}
- Source/configuration evidence: {static.get("source_evidence", 0)}
- Online endpoints: {tls.get("endpoints", 0)}
- PQC-capable endpoints: {tls.get("pqc_supported", 0)}
- Risk findings: {risk.get("total", 0)}
- SQLite assets/endpoints: {db.get("assets", 0)}/{db.get("endpoints", 0)}

## Runtime migration metrics

- Recorded requests: {fallback.get("connections", 0)}
- Hybrid/PQC requests: {fallback.get("hybrid_pqc", 0)}
- Classical fallback requests: {fallback.get("classical_fallback", 0)}
- Hybrid adoption rate: {fallback.get("hybrid_adoption_rate")}

## Files

- `crypto-inventory.json` / `.csv`
- `tls-inventory.json` / `.csv`
- `risk-report.json`
- `inventory.db`
- `migration-verification.json`
- `fallback-report.json`
- `handshake-hybrid.json`
- `handshake-x25519.json`
- `gateway-access.log`
- TLS transcript files
'''
(root/'SUMMARY.md').write_text(text)
PY
}

main() {
  require docker
  require curl
  require python3
  require timeout
  [[ -f config/services.json ]] || die 'config/services.json not found'

  log 'Validating multi-service configuration'
  python3 scripts/render_gateway_config.py --config config/services.json --output "$RESULT_DIR/rendered-nginx.conf" --check

  log 'Generating fresh demo certificates with all configured DNS names'
  ./certs/gen-classic-demo-certs.sh ./certs

  if [[ "$BUILD" == "1" ]] || [[ -z "$(docker compose images -q "$GATEWAY_SERVICE" 2>/dev/null)" ]]; then
    log 'Building gateway image'
    docker compose build "$GATEWAY_SERVICE"
  else
    log 'Using existing gateway image; set BUILD=1 to rebuild'
  fi

  docker compose up -d --force-recreate
  wait_container "$BACKEND_CONTAINER" healthy
  wait_container "$GATEWAY_CONTAINER" healthy
  docker compose ps | tee "$RESULT_DIR/docker-compose-ps.txt"

  docker compose exec -T "$GATEWAY_SERVICE" "$OPENSSL_BIN" version -a >"$RESULT_DIR/openssl-version.txt" 2>&1
  docker compose exec -T "$GATEWAY_SERVICE" /opt/nginx/sbin/nginx -V >"$RESULT_DIR/nginx-build.txt" 2>&1
  docker compose exec -T "$GATEWAY_SERVICE" sh -c ': > /var/log/nginx/access.log'

  handshake_success 8443 bank-gateway.local X25519MLKEM768 "$RESULT_DIR/tls-compat-hybrid.txt"
  handshake_success 8443 bank-gateway.local X25519 "$RESULT_DIR/tls-compat-x25519.txt"
  handshake_success 9443 strict-gateway.local X25519MLKEM768 "$RESULT_DIR/tls-strict-hybrid.txt"
  handshake_expected_failure 9443 strict-gateway.local X25519 "$RESULT_DIR/tls-strict-x25519-rejected.txt"

  log 'Testing transparent HTTP reverse proxy without host proxy variables'
  http_get_host 8443 bank-gateway.local /service-info "$RESULT_DIR/service-info-compat.json"
  http_with_openssl 8443 bank-gateway.local X25519MLKEM768 /service-info "$RESULT_DIR/http-hybrid.txt"
  http_with_openssl 8443 bank-gateway.local X25519 /service-info "$RESULT_DIR/http-x25519.txt"
  http_with_openssl 9443 strict-gateway.local X25519MLKEM768 /service-info "$RESULT_DIR/http-strict-hybrid.txt"

  log 'Running static cryptographic inventory v2'
  python3 scripts/crypto_inventory.py \
    --root ./certs --root ./gateway --root ./config --root ./docker-compose.yml \
    --root ./scripts --root ./scanner --root ./manager \
    --out-json "$RESULT_DIR/crypto-inventory.json" \
    --out-csv "$RESULT_DIR/crypto-inventory.csv"

  log 'Running online TLS inventory with OpenSSL 3.5 inside the gateway container'
  docker compose exec -T "$GATEWAY_SERVICE" \
    python3 /workspace/scanner/tls_scanner.py \
      --endpoint 'localhost:8443,bank-gateway.local' \
      --endpoint 'localhost:9443,strict-gateway.local' \
      --groups X25519MLKEM768:X25519 \
      --openssl "$OPENSSL_BIN" --cafile "$CA_CONTAINER" \
      --out-json /tmp/tls-inventory.json --out-csv /tmp/tls-inventory.csv
  docker cp "$GATEWAY_CONTAINER:/tmp/tls-inventory.json" "$RESULT_DIR/tls-inventory.json"
  docker cp "$GATEWAY_CONTAINER:/tmp/tls-inventory.csv" "$RESULT_DIR/tls-inventory.csv"

  python3 manager/risk_engine.py --static "$RESULT_DIR/crypto-inventory.json" --tls "$RESULT_DIR/tls-inventory.json" --out "$RESULT_DIR/risk-report.json"
  python3 manager/inventory_db.py --db "$RESULT_DIR/inventory.db" --static "$RESULT_DIR/crypto-inventory.json" --tls "$RESULT_DIR/tls-inventory.json" --risk "$RESULT_DIR/risk-report.json" --summary-json "$RESULT_DIR/inventory-db-summary.json"
  python3 manager/verify_migration.py --services config/services.json --tls "$RESULT_DIR/tls-inventory.json" --out "$RESULT_DIR/migration-verification.json"

  docker compose exec -T "$GATEWAY_SERVICE" sh -c 'cat /var/log/nginx/access.log' > "$RESULT_DIR/gateway-access.log"
  python3 manager/fallback_report.py --log "$RESULT_DIR/gateway-access.log" --out "$RESULT_DIR/fallback-report.json"

  benchmark 8443 bank-gateway.local X25519MLKEM768 /tmp/handshake-hybrid.json "$RESULT_DIR/handshake-hybrid.json"
  benchmark 8443 bank-gateway.local X25519 /tmp/handshake-x25519.json "$RESULT_DIR/handshake-x25519.json"

  docker compose logs --no-color --tail=300 "$GATEWAY_SERVICE" > "$RESULT_DIR/gateway-container.log"
  write_summary
  log "All v2 experiments completed: $RESULT_DIR"
}

main "$@"
