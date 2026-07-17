#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SCAN_ROOT="${SCAN_ROOT:-$ROOT}"
SERVER_NAME="${SERVER_NAME:-pqc-gateway.local}"
LISTEN_PORT="${LISTEN_PORT:-8443}"
FORCE=0

usage(){
  cat <<'EOF'
Usage: scripts/init_enterprise.sh [options]

  --scan-root PATH     Host directory authorized for read-only scanning
  --server-name NAME   Initial Gateway SNI name (default: pqc-gateway.local)
  --listen-port PORT   Initial Gateway listen port (default: 8443)
  --force              Replace the generated pilot service configuration
EOF
}

while [[ $# -gt 0 ]];do
  case "$1" in
    --scan-root) SCAN_ROOT="$2";shift ;;
    --server-name) SERVER_NAME="$2";shift ;;
    --listen-port) LISTEN_PORT="$2";shift ;;
    --force) FORCE=1 ;;
    -h|--help) usage;exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2;usage >&2;exit 2 ;;
  esac
  shift
done

command -v python3 >/dev/null || { echo "python3 is required" >&2;exit 2; }
command -v openssl >/dev/null || { echo "openssl is required" >&2;exit 2; }
if [[ ! -d "$SCAN_ROOT" ]];then
  printf 'scan root does not exist on the host: %s\n' "$SCAN_ROOT" >&2
  printf 'Use an existing application directory, for example:\n' >&2
  printf '  make enterprise-init SCAN_ROOT="$PWD" SERVER_NAME=%s LISTEN_PORT=%s\n' "$SERVER_NAME" "$LISTEN_PORT" >&2
  printf 'Or create the directory first with: mkdir -p "%s"\n' "$SCAN_ROOT" >&2
  exit 2
fi

args=(onboard init --scan-root "$SCAN_ROOT" --server-name "$SERVER_NAME" --listen-port "$LISTEN_PORT")
[[ "$FORCE" == 1 ]] && args+=(--force)
python3 manager/pqctl.py "${args[@]}"

CERT_DIR="runtime-data/enterprise/certs"
mkdir -p "$CERT_DIR"
if [[ ! -s "$CERT_DIR/ca.crt" || ! -s "$CERT_DIR/ca.key" || ! -s "$CERT_DIR/server.crt" || ! -s "$CERT_DIR/server.key" ]];then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  cat >"$tmp/server.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${SERVER_NAME},DNS:localhost,IP:127.0.0.1
EOF
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$CERT_DIR/ca.key"
  openssl req -x509 -new -key "$CERT_DIR/ca.key" -sha384 -days 825 -out "$CERT_DIR/ca.crt" \
    -subj "/O=PQC Gateway Enterprise Pilot/CN=PQC Gateway Pilot CA"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$CERT_DIR/server.key"
  openssl req -new -key "$CERT_DIR/server.key" -out "$tmp/server.csr" \
    -subj "/O=PQC Gateway Enterprise Pilot/CN=${SERVER_NAME}"
  openssl x509 -req -in "$tmp/server.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/server.crt" -days 825 -sha384 -extfile "$tmp/server.ext"
  chmod 600 "$CERT_DIR/ca.key" "$CERT_DIR/server.key"
  chmod 644 "$CERT_DIR/ca.crt" "$CERT_DIR/server.crt"
  echo "Generated pilot TLS certificate in $CERT_DIR"
else
  echo "Preserving existing enterprise TLS certificate in $CERT_DIR"
fi

python3 scripts/render_gateway_config.py \
  --config config/enterprise/services.json \
  --output /tmp/pq-gateway-enterprise-nginx.conf \
  --check

cat <<EOF

Enterprise workspace initialized.
  Authorized scan root: $SCAN_ROOT
  Service config:       config/enterprise/services.json
  Secrets:              .env.enterprise
  Pilot certificate:    runtime-data/enterprise/certs

The generated certificate is for a pilot only. Replace it with enterprise PKI
before production traffic. Next: run 'make enterprise-up', then integrate
through GET /openapi.json and the authenticated Manager API.
EOF
