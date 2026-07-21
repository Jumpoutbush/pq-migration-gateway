#!/usr/bin/env bash
set -Eeuo pipefail

# PQC Migration Gateway v3.7 complete experiment.
# Default build path uses the WSL proxy at 127.0.0.1:7897.
# Usage:
#   ./scripts/run_full_experiment.sh
#   ./scripts/run_full_experiment.sh --latest
#   BUILD=1 PERF_PROFILE=standard ./scripts/run_full_experiment.sh

BUILD="${BUILD:-0}"
PERF_PROFILE="${PERF_PROFILE:-standard}"
RESULT_ROOT="${RESULT_ROOT:-experiment-results}"
UPDATE_LATEST=0

log(){ printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
die(){ printf 'ERROR: %s\n' "$*" >&2;exit 1; }

usage(){
  cat <<'EOF'
Usage:
  ./scripts/run_full_experiment.sh [--latest|latest]

Environment:
  BUILD=1                 Rebuild the gateway image before running.
  PERF_PROFILE=quick      Use quick, standard, or stress performance profile.
  RESULT_ROOT=path        Store experiment outputs under this directory.

Options:
  --latest, latest        Update experiment-results/latest to point to this run.
  -h, --help             Show this help.
EOF
}

while [[ $# -gt 0 ]];do
  case "$1" in
    --latest|latest)
      UPDATE_LATEST=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "Unknown argument: $1"
      ;;
  esac
  shift
done

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RESULT_DIR="${RESULT_ROOT}/${TIMESTAMP}"
IMAGE="pq-migration-gateway-pq-gateway:3.7"
PROXY_URL="${WSL_PROXY:-http://127.0.0.1:7897}"
OPENSSL_BIN="/opt/openssl/bin/openssl"
CA_CONTAINER="/etc/pq-gateway/certs/ca.crt"
CA_HOST="certs/ca.crt"
mkdir -p "$RESULT_DIR"

require(){ command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"; }
publish_latest(){
  [[ "$UPDATE_LATEST" == 1 ]] || return 0
  local link="${RESULT_ROOT}/latest"
  mkdir -p "$RESULT_ROOT"
  if [[ -e "$link" && ! -L "$link" ]];then
    printf 'ERROR: %s exists and is not a symlink; remove or rename it before using --latest\n' "$link" >&2
    return 1
  fi
  ln -sfn "$(basename "$RESULT_DIR")" "$link"
  log "Latest experiment pointer updated: $link -> $(basename "$RESULT_DIR")"
}
write_status(){
  local status="$1" message="$2" code="$3"
  python3 - "$RESULT_DIR/experiment-status.json" "$status" "$message" "$code" <<'PY'
import json,sys,time
open(sys.argv[1],'w').write(json.dumps({'generated_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'status':sys.argv[2],'message':sys.argv[3],'exit_code':int(sys.argv[4])},indent=2)+'\n')
PY
}
on_error(){
  local code=$? line=${BASH_LINENO[0]:-unknown}
  trap - ERR
  write_status FAIL "Experiment stopped near line ${line}" "$code" || true
  publish_latest || true
  docker compose ps -a >"$RESULT_DIR/docker-compose-ps-failure.txt" 2>&1 || true
  docker compose logs --no-color --tail=160 pq-gateway >"$RESULT_DIR/gateway-failure.log" 2>&1 || true
  printf '\nExperiment failed with exit code %s near line %s.\n' "$code" "$line" >&2
  exit "$code"
}
trap on_error ERR

build_gateway(){
  log "Building $IMAGE through WSL proxy $PROXY_URL"
  docker build \
    --network=host \
    --build-arg OPENSSL_VERSION=3.5.0 \
    --build-arg NGINX_VERSION=1.28.0 \
    --build-arg MAKE_JOBS=4 \
    --build-arg HTTP_PROXY="$PROXY_URL" \
    --build-arg HTTPS_PROXY="$PROXY_URL" \
    --build-arg http_proxy="$PROXY_URL" \
    --build-arg https_proxy="$PROXY_URL" \
    --build-arg NO_PROXY=localhost,127.0.0.1,::1 \
    --build-arg no_proxy=localhost,127.0.0.1,::1 \
    -f docker/Dockerfile.gateway \
    -t "$IMAGE" .
}
wait_state(){
  local container="$1" expected="$2" retries="${3:-90}" status=''
  for ((i=1;i<=retries;i++));do
    status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container" 2>/dev/null || true)"
    [[ "$status" == "$expected" ]] && return 0
    sleep 1
  done
  die "$container did not reach $expected; last=${status:-missing}"
}
handshake_success(){
  local port="$1" sni="$2" group="$3" output="$4"
  docker compose exec -T pq-gateway "$OPENSSL_BIN" s_client \
    -connect "localhost:${port}" -servername "$sni" -tls1_3 -groups "$group" \
    -CAfile "$CA_CONTAINER" -verify_return_error -brief </dev/null >"$output" 2>&1
  grep -q 'Verification: OK' "$output"
  grep -q "$group" "$output"
}
handshake_expected_failure(){
  local port="$1" sni="$2" group="$3" output="$4" rc
  if docker compose exec -T pq-gateway "$OPENSSL_BIN" s_client \
      -connect "localhost:${port}" -servername "$sni" -tls1_3 -groups "$group" \
      -CAfile "$CA_CONTAINER" -brief </dev/null >"$output" 2>&1; then rc=0;else rc=$?;fi
  if grep -q 'Verification: OK' "$output" && grep -q 'TLSv1.3' "$output";then
    die "Expected ${sni}:${port} to reject $group"
  fi
  [[ $rc -ne 0 ]]
  grep -Eqi 'alert handshake failure|alert number 40|no suitable key share|handshake failure' "$output"
}
http_get(){
  local port="$1" host="$2" path="$3" output="$4"
  curl --noproxy '*' --fail-with-body --silent --show-error --connect-timeout 5 --max-time 20 \
    --resolve "${host}:${port}:127.0.0.1" --cacert "$CA_HOST" \
    "https://${host}:${port}${path}" >"$output"
}
extract_log_delta(){
  local file="$1" start="$2" output="$3"
  if [[ -f "$file" ]];then tail -n "+$((start+1))" "$file" >"$output";else : >"$output";fi
}

write_summary(){
  python3 - "$RESULT_DIR" "$PERF_PROFILE" <<'PY'
import json,sys
from pathlib import Path
r=Path(sys.argv[1]);profile=sys.argv[2]
def load(path,default=None):
    p=r/path
    if not p.exists():return default or {}
    return json.loads(p.read_text())
static=load('crypto-inventory.json').get('summary',{});tls=load('tls-inventory.json').get('summary',{});risk=load('risk-report.json').get('summary',{});verify=load('migration-verification.json').get('summary',{});db=load('inventory-db-summary.json');mtls=load('mtls/mtls-matrix.json').get('summary',{});up=load('upstream/upstream-tls-matrix.json').get('summary',{});stream=load('stream/stream-protocol-matrix.json').get('summary',{});runtime=load('runtime-fallback-report.json').get('summary',{});experiment=load('experiment-fallback-report.json').get('summary',{});perf=load('performance/performance-report.json').get('summary',{});disc=load('network-discovery.json').get('summary',{});cmdb=load('cmdb-targets.json').get('summary',{});enterprise=load('enterprise-scan/enterprise-crypto-inventory.json').get('summary',{});enterprise_matrix=load('enterprise-scan/enterprise-scanner-matrix.json').get('summary',{});api_matrix=load('scan-migration-api/scan-migration-api-matrix.json').get('summary',{});api_first=load('api-first/api-first-matrix.json').get('summary',{})
text=f'''# PQC Migration Gateway v3.7 Experiment Summary

## Overall result

- HTTP/HTTPS and Stream configuration: validated
- Compatibility endpoint: Hybrid/PQC and X25519 accepted
- Strict endpoint: Hybrid/PQC accepted and X25519 rejected
- mTLS matrix: {mtls.get('passed',0)}/{mtls.get('tests',0)} passed
- Upstream HTTPS/SNI/mTLS/negative CA/rotation matrix: {up.get('passed',0)}/{up.get('tests',0)} passed
- MQTT TLS, generic TCP TLS and legacy protocol TLS: {stream.get('passed',0)}/{stream.get('tests',0)} passed
- Migration policy verification: {verify.get('passed',0)}/{verify.get('services',0)} passed
- Performance profile: {profile}; failed benchmark cases: {perf.get('failed_tests',0)}

## Enterprise discovery and inventory

- Enterprise source/binary/runtime matrix: {enterprise_matrix.get('passed',0)}/{enterprise_matrix.get('tests',0)} passed
- Scan-to-migration REST API matrix: {api_matrix.get('passed',0)}/{api_matrix.get('tests',0)} passed
- API-first onboarding/release/rollback matrix: {api_first.get('passed',0)}/{api_first.get('tests',0)} passed
- Languages covered: C/C++, Java, Rust, Go, Python and Shell
- Crypto-relevant artifacts: {enterprise.get('crypto_relevant_artifacts',0)}
- Native executables / Java archives / runtime processes: {enterprise.get('native_executables',0)}/{enterprise.get('java_archives',0)}/{enterprise.get('runtime_crypto_processes',0)}
- Concrete cryptographic assets: {static.get('concrete_assets',0)}
- Source/configuration evidence: {static.get('source_evidence',0)}
- Interface-level evidence: {static.get('interface_evidence',0)}
- Normalized CMDB targets: {cmdb.get('targets',0)}
- CIDR candidates/open endpoints: {disc.get('candidates',0)}/{disc.get('open',0)}
- TLS endpoints scanned: {tls.get('endpoints',0)}
- PQC-capable endpoints: {tls.get('pqc_supported',0)}
- Risk findings: {risk.get('total',0)}
- SQLite assets/evidence/artifacts/runtime processes/endpoints/CMDB assets: {db.get('assets',0)}/{db.get('evidence',0)}/{db.get('artifacts',0)}/{db.get('runtime_processes',0)}/{db.get('endpoints',0)}/{db.get('cmdb_assets',0)}

## Persistent runtime migration metrics

- All recorded connections: {runtime.get('connections',0)}
- Hybrid/PQC: {runtime.get('hybrid_pqc',0)}
- Classical fallback: {runtime.get('classical_fallback',0)}
- Hybrid adoption rate: {runtime.get('hybrid_adoption_rate')}

The persistent metrics include traffic accumulated in `runtime-data/logs`, not only this experiment. This experiment alone recorded {experiment.get('connections',0)} connections.

## Important outputs

- `experiment-status.json`
- `mtls/mtls-matrix.json`
- `upstream/upstream-tls-matrix.json`
- `stream/stream-protocol-matrix.json`
- `crypto-inventory.json` and `tls-inventory.json`
- `enterprise-scan/enterprise-scanner-matrix.json`, inventory JSON and CSV
- `scan-migration-api/scan-migration-api-matrix.json`
- `api-first/api-first-matrix.json`
- `network-discovery.json` and `cmdb-targets.json`
- `continuous-scan-latest.json` and `continuous-scan-diff.json`
- `risk-report.json` and `inventory.db`
- `migration-verification.json`
- `runtime-fallback-report.json` and `experiment-fallback-report.json`
- `performance/performance-report.json`, `.csv`, and `PERFORMANCE.md`
'''
(r/'SUMMARY.md').write_text(text)
PY
}

main(){
  require docker;require curl;require python3;require timeout
  [[ -f config/services.json ]]
  log 'Validating v3 HTTP and Stream gateway configuration'
  python3 scripts/render_gateway_config.py --config config/services.json --output "$RESULT_DIR/rendered-nginx.conf" --check
  log 'Generating gateway, client and upstream demo PKI'
  ./certs/gen-classic-demo-certs.sh ./certs >"$RESULT_DIR/certificate-generation.txt"

  if [[ "$BUILD" == 1 ]] || ! docker image inspect "$IMAGE" >/dev/null 2>&1;then build_gateway;else log "Using existing $IMAGE; set BUILD=1 to rebuild";fi
  mkdir -p runtime-data/logs runtime-data/metrics runtime-data/scans
  HTTP_START=0
  STREAM_START=0
  [[ -f runtime-data/logs/access.log ]] && HTTP_START=$(wc -l < runtime-data/logs/access.log)
  [[ -f runtime-data/logs/stream-access.log ]] && STREAM_START=$(wc -l < runtime-data/logs/stream-access.log)

  docker compose up -d --no-build --force-recreate
  wait_state bank-backend healthy;wait_state secure-backend healthy;wait_state tcp-backend healthy;wait_state legacy-backend healthy;wait_state mqtt-broker healthy;wait_state pq-gateway healthy
  docker compose ps | tee "$RESULT_DIR/docker-compose-ps.txt"
  docker compose exec -T pq-gateway "$OPENSSL_BIN" version -a >"$RESULT_DIR/openssl-version.txt" 2>&1
  docker compose exec -T pq-gateway /opt/nginx/sbin/nginx -V >"$RESULT_DIR/nginx-build.txt" 2>&1

  log 'Testing compatibility and strict TLS policies'
  handshake_success 8443 bank-gateway.local X25519MLKEM768 "$RESULT_DIR/tls-compat-hybrid.txt"
  handshake_success 8443 bank-gateway.local X25519 "$RESULT_DIR/tls-compat-x25519.txt"
  handshake_success 9443 strict-gateway.local X25519MLKEM768 "$RESULT_DIR/tls-strict-hybrid.txt"
  handshake_expected_failure 9443 strict-gateway.local X25519 "$RESULT_DIR/tls-strict-x25519-rejected.txt"
  http_get 8443 bank-gateway.local /service-info "$RESULT_DIR/service-info.json"

  log 'Running complete client mTLS matrix'
  ./scripts/test_mtls_matrix.sh "$RESULT_DIR/mtls"
  log 'Running upstream HTTPS, SNI, gateway mTLS, negative CA and certificate rotation matrix'
  ./scripts/test_upstream_tls.sh "$RESULT_DIR/upstream"
  log 'Running MQTT TLS, generic TCP TLS and legacy protocol tests'
  ./scripts/test_stream_protocols.sh "$RESULT_DIR/stream"

  log 'Running static cryptographic inventory'
  python3 scripts/crypto_inventory.py --root ./certs --root ./gateway --root ./backend --root ./config --root ./docker-compose.yml --root ./scripts --root ./scanner --root ./manager --out-json "$RESULT_DIR/crypto-inventory.json" --out-csv "$RESULT_DIR/crypto-inventory.csv"
  log 'Running enterprise source, executable, JAR and process-map scanner matrix'
  python3 scripts/test_enterprise_scanner.py "$RESULT_DIR/enterprise-scan"
  log 'Running scan-to-asset-to-migration REST API workflow matrix'
  python3 scripts/test_scan_migration_api.py "$RESULT_DIR/scan-migration-api"
  log 'Running live backend-to-Runtime-Agent-to-enterprise-asset REST API workflow matrix'
  python3 scripts/test_runtime_agent_workflow.py "$RESULT_DIR/runtime-agent"
  log 'Running API-first onboarding, service publication, status and rollback workflow matrix'
  python3 scripts/test_api_first_workflow.py "$RESULT_DIR/api-first"
  log 'Importing sample CMDB assets into normalized targets'
  PYTHONPATH=scanner python3 scanner/cmdb_import.py --input config/cmdb/sample-assets.csv --out-json "$RESULT_DIR/cmdb-targets.json" --out-csv "$RESULT_DIR/cmdb-targets.csv"
  log 'Running explicit CIDR discovery against locally exposed test ports'
  PYTHONPATH=scanner python3 scanner/network_discovery.py --cidr 127.0.0.1/32 --ports 8443,9443,10443,11443,12443,13443,14443,8883,15443,16443 --max-hosts 16 --workers 20 --timeout 2 --out-json "$RESULT_DIR/network-discovery.json" --out-csv "$RESULT_DIR/network-discovery.csv"

  log 'Running batch online TLS inventory through OpenSSL 3.5'
  docker compose exec -T pq-gateway python3 /workspace/scanner/tls_scanner.py --targets-file /etc/pq-gateway/config/scan-targets.json --groups X25519MLKEM768:X25519 --openssl "$OPENSSL_BIN" --cafile "$CA_CONTAINER" --workers 10 --allow-unreachable --out-json /tmp/tls-inventory.json --out-csv /tmp/tls-inventory.csv
  docker cp pq-gateway:/tmp/tls-inventory.json "$RESULT_DIR/tls-inventory.json";docker cp pq-gateway:/tmp/tls-inventory.csv "$RESULT_DIR/tls-inventory.csv"

  log 'Running one scheduled continuous-scan iteration and change detection'
  docker compose exec -T pq-gateway python3 /workspace/scanner/continuous_scan.py --config /etc/pq-gateway/config/continuous-scan.json --once >"$RESULT_DIR/continuous-scan-run.txt"
  cp runtime-data/scans/latest.json "$RESULT_DIR/continuous-scan-latest.json"
  latest_scan_dir=$(find runtime-data/scans -mindepth 1 -maxdepth 1 -type d | sort | tail -1)
  [[ -n "$latest_scan_dir" ]] && cp "$latest_scan_dir/diff.json" "$RESULT_DIR/continuous-scan-diff.json"

  python3 manager/risk_engine.py --static "$RESULT_DIR/crypto-inventory.json" --static "$RESULT_DIR/enterprise-scan/enterprise-crypto-inventory.json" --tls "$RESULT_DIR/tls-inventory.json" --out "$RESULT_DIR/risk-report.json"
  python3 manager/inventory_db.py --db "$RESULT_DIR/inventory.db" --static "$RESULT_DIR/crypto-inventory.json" --static "$RESULT_DIR/enterprise-scan/enterprise-crypto-inventory.json" --tls "$RESULT_DIR/tls-inventory.json" --risk "$RESULT_DIR/risk-report.json" --cmdb "$RESULT_DIR/cmdb-targets.json" --summary-json "$RESULT_DIR/inventory-db-summary.json"
  python3 manager/verify_migration.py --services config/services.json --tls "$RESULT_DIR/tls-inventory.json" --out "$RESULT_DIR/migration-verification.json"

  extract_log_delta runtime-data/logs/access.log "$HTTP_START" "$RESULT_DIR/experiment-http-access.log"
  extract_log_delta runtime-data/logs/stream-access.log "$STREAM_START" "$RESULT_DIR/experiment-stream-access.log"
  python3 manager/fallback_report.py --log "$RESULT_DIR/experiment-http-access.log" --log "$RESULT_DIR/experiment-stream-access.log" --out "$RESULT_DIR/experiment-fallback-report.json"
  python3 manager/fallback_report.py --log runtime-data/logs/access.log --log runtime-data/logs/stream-access.log --out "$RESULT_DIR/runtime-fallback-report.json"
  python3 manager/runtime_metrics.py --log runtime-data/logs/access.log --log runtime-data/logs/stream-access.log --out runtime-data/metrics/current.json --prometheus runtime-data/metrics/pqc_gateway.prom --once
  cp runtime-data/metrics/current.json "$RESULT_DIR/runtime-metrics-current.json";cp runtime-data/metrics/pqc_gateway.prom "$RESULT_DIR/pqc_gateway.prom"

  log "Running complete performance suite profile=$PERF_PROFILE"
  PERF_PROFILE="$PERF_PROFILE" ./scripts/run_performance_suite.sh "$RESULT_DIR/performance"
  write_summary
  write_status PASS 'All v3.7 experiments completed successfully' 0
  publish_latest || die "Could not update latest experiment pointer"
  log "All v3.7 experiments completed: $RESULT_DIR"
}
main "$@"
