#!/usr/bin/env bash
set -euo pipefail
DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/upstream}"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
DAYS="${DAYS:-825}"
cd "$DIR"
serial_before="$($OPENSSL_BIN x509 -in server.crt -noout -serial 2>/dev/null || true)"
cat > rotate.ext <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:upstream-secure.local,DNS:secure-backend,DNS:localhost,IP:127.0.0.1
EOF
"$OPENSSL_BIN" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out server.key.new
"$OPENSSL_BIN" req -new -key server.key.new -out server.csr.new \
  -subj "/C=CN/O=PQC Migration Demo/CN=upstream-secure.local"
"$OPENSSL_BIN" x509 -req -in server.csr.new -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt.new -days "$DAYS" -sha384 -extfile rotate.ext
chmod 600 server.key.new
mv server.key.new server.key
mv server.crt.new server.crt
rm -f server.csr.new rotate.ext ca.srl
serial_after="$($OPENSSL_BIN x509 -in server.crt -noout -serial)"
printf '{"serial_before":"%s","serial_after":"%s","rotated":%s}\n' \
  "${serial_before#serial=}" "${serial_after#serial=}" \
  "$([[ "$serial_before" != "$serial_after" ]] && echo true || echo false)"
