#!/usr/bin/env bash
set -euo pipefail

# Requires OpenSSL 3.5+ with native ML-DSA support.
# This script is optional. The default demo uses RSA certificates plus hybrid
# ML-KEM key exchange because that is usually the least disruptive migration step.

OUT_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/mldsa-demo}"
SERVER_NAME="${SERVER_NAME:-bank-gateway.local}"
CLIENT_NAME="${CLIENT_NAME:-bank-client.local}"
DAYS="${DAYS:-365}"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
MLDSA_ALG="${MLDSA_ALG:-ML-DSA-65}"

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

"$OPENSSL_BIN" list -signature-algorithms | grep -Eiq 'ML-DSA|MLDSA' || {
  echo "OpenSSL binary does not expose ML-DSA signature algorithms: $OPENSSL_BIN" >&2
  exit 1
}

cat > server.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:${SERVER_NAME},DNS:localhost,IP:127.0.0.1
EOF

cat > client.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=DNS:${CLIENT_NAME}
EOF

"$OPENSSL_BIN" genpkey -algorithm "$MLDSA_ALG" -out ca.key
"$OPENSSL_BIN" req -x509 -new -key ca.key -days "$DAYS" -out ca.crt \
  -subj "/C=CN/O=Demo Bank PQ Migration/CN=Demo ML-DSA CA"

"$OPENSSL_BIN" genpkey -algorithm "$MLDSA_ALG" -out server.key
"$OPENSSL_BIN" req -new -key server.key -out server.csr \
  -subj "/C=CN/O=Demo Bank PQ Migration/CN=${SERVER_NAME}"
"$OPENSSL_BIN" x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days "$DAYS" -extfile server.ext

"$OPENSSL_BIN" genpkey -algorithm "$MLDSA_ALG" -out client.key
"$OPENSSL_BIN" req -new -key client.key -out client.csr \
  -subj "/C=CN/O=Demo Bank PQ Migration/CN=${CLIENT_NAME}"
"$OPENSSL_BIN" x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days "$DAYS" -extfile client.ext

chmod 600 ca.key server.key client.key
rm -f server.csr client.csr ca.srl server.ext client.ext

echo "Generated optional ${MLDSA_ALG} demo certificate chain in: $OUT_DIR"
