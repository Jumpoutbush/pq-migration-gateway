#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
SERVER_NAME="${SERVER_NAME:-bank-gateway.local}"
CLIENT_NAME="${CLIENT_NAME:-bank-client.local}"
DAYS="${DAYS:-825}"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

cat > server.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${SERVER_NAME},DNS:localhost,IP:127.0.0.1
EOF

cat > client.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectAltName=DNS:${CLIENT_NAME}
EOF

"$OPENSSL_BIN" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out ca.key
"$OPENSSL_BIN" req -x509 -new -key ca.key -sha384 -days "$DAYS" -out ca.crt \
  -subj "/C=CN/O=Demo Bank PQ Migration/CN=Demo Bank Migration CA"

"$OPENSSL_BIN" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out server.key
"$OPENSSL_BIN" req -new -key server.key -out server.csr \
  -subj "/C=CN/O=Demo Bank PQ Migration/CN=${SERVER_NAME}"
"$OPENSSL_BIN" x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days "$DAYS" -sha384 -extfile server.ext

"$OPENSSL_BIN" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out client.key
"$OPENSSL_BIN" req -new -key client.key -out client.csr \
  -subj "/C=CN/O=Demo Bank PQ Migration/CN=${CLIENT_NAME}"
"$OPENSSL_BIN" x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days "$DAYS" -sha384 -extfile client.ext

chmod 600 ca.key server.key client.key
rm -f server.csr client.csr ca.srl server.ext client.ext

cat <<EOF
Generated demo RSA-3072 certificate chain in: $OUT_DIR
  CA:      $OUT_DIR/ca.crt
  Server:  $OUT_DIR/server.crt / $OUT_DIR/server.key
  Client:  $OUT_DIR/client.crt / $OUT_DIR/client.key
EOF
