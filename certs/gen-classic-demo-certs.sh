#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
DAYS="${DAYS:-825}"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
SERVER_NAME="${SERVER_NAME:-bank-gateway.local}"
SERVER_ALT_NAMES="${SERVER_ALT_NAMES:-DNS:strict-gateway.local,DNS:mtls-gateway.local,DNS:optional-mtls-gateway.local,DNS:upstream-gateway.local,DNS:badca-gateway.local,DNS:upstream-noclient-gateway.local,DNS:mqtt-gateway.local,DNS:tcp-gateway.local,DNS:legacy-gateway.local,DNS:gateway.local,DNS:localhost,IP:127.0.0.1}"

mkdir -p "$OUT_DIR/upstream" "$OUT_DIR/untrusted"
cd "$OUT_DIR"

rm -f ./*.crt ./*.key ./*.csr ./*.srl ./*.ext
rm -f upstream/*.crt upstream/*.key upstream/*.csr upstream/*.srl upstream/*.ext
rm -f untrusted/*.crt untrusted/*.key untrusted/*.csr untrusted/*.srl untrusted/*.ext

cat > server.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${SERVER_NAME},${SERVER_ALT_NAMES}
EOF
cat > client.ext <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectAltName=DNS:gateway-client.local
EOF

"$OPENSSL_BIN" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out ca.key
"$OPENSSL_BIN" req -x509 -new -key ca.key -sha384 -days "$DAYS" -out ca.crt \
  -subj "/C=CN/O=PQC Migration Demo/CN=PQC Gateway Demo CA"
"$OPENSSL_BIN" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out server.key
"$OPENSSL_BIN" req -new -key server.key -out server.csr \
  -subj "/C=CN/O=PQC Migration Demo/CN=${SERVER_NAME}"
"$OPENSSL_BIN" x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days "$DAYS" -sha384 -extfile server.ext
"$OPENSSL_BIN" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out client.key
"$OPENSSL_BIN" req -new -key client.key -out client.csr \
  -subj "/C=CN/O=PQC Migration Demo/CN=gateway-client.local"
"$OPENSSL_BIN" x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days "$DAYS" -sha384 -extfile client.ext

# Untrusted client chain for negative mTLS tests.
"$OPENSSL_BIN" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out untrusted/ca.key
"$OPENSSL_BIN" req -x509 -new -key untrusted/ca.key -sha384 -days "$DAYS" -out untrusted/ca.crt \
  -subj "/C=CN/O=PQC Migration Demo/CN=Untrusted Client CA"
"$OPENSSL_BIN" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out untrusted/client.key
"$OPENSSL_BIN" req -new -key untrusted/client.key -out untrusted/client.csr \
  -subj "/C=CN/O=PQC Migration Demo/CN=untrusted-client.local"
"$OPENSSL_BIN" x509 -req -in untrusted/client.csr -CA untrusted/ca.crt -CAkey untrusted/ca.key -CAcreateserial \
  -out untrusted/client.crt -days "$DAYS" -sha384 -extfile client.ext

# Independent upstream PKI used by the HTTPS backend and gateway-to-upstream mTLS.
cat > upstream/server.ext <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:upstream-secure.local,DNS:secure-backend,DNS:localhost,IP:127.0.0.1
EOF
cat > upstream/client.ext <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectAltName=DNS:gateway-upstream-client.local
EOF
"$OPENSSL_BIN" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out upstream/ca.key
"$OPENSSL_BIN" req -x509 -new -key upstream/ca.key -sha384 -days "$DAYS" -out upstream/ca.crt \
  -subj "/C=CN/O=PQC Migration Demo/CN=Upstream Demo CA"
"$OPENSSL_BIN" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out upstream/server.key
"$OPENSSL_BIN" req -new -key upstream/server.key -out upstream/server.csr \
  -subj "/C=CN/O=PQC Migration Demo/CN=upstream-secure.local"
"$OPENSSL_BIN" x509 -req -in upstream/server.csr -CA upstream/ca.crt -CAkey upstream/ca.key -CAcreateserial \
  -out upstream/server.crt -days "$DAYS" -sha384 -extfile upstream/server.ext
"$OPENSSL_BIN" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out upstream/client.key
"$OPENSSL_BIN" req -new -key upstream/client.key -out upstream/client.csr \
  -subj "/C=CN/O=PQC Migration Demo/CN=gateway-upstream-client.local"
"$OPENSSL_BIN" x509 -req -in upstream/client.csr -CA upstream/ca.crt -CAkey upstream/ca.key -CAcreateserial \
  -out upstream/client.crt -days "$DAYS" -sha384 -extfile upstream/client.ext

# Wrong CA used to prove that upstream certificate verification rejects an untrusted chain.
"$OPENSSL_BIN" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out wrong-upstream-ca.key
"$OPENSSL_BIN" req -x509 -new -key wrong-upstream-ca.key -sha384 -days "$DAYS" -out wrong-upstream-ca.crt \
  -subj "/C=CN/O=PQC Migration Demo/CN=Wrong Upstream CA"

chmod 600 ./*.key upstream/*.key untrusted/*.key
rm -f ./*.csr ./*.srl ./*.ext upstream/*.csr upstream/*.srl upstream/*.ext untrusted/*.csr untrusted/*.srl untrusted/*.ext

cat <<EOF
Generated demo PKI in: $OUT_DIR
  Gateway CA/server/client: ca.crt, server.crt, client.crt
  Untrusted client:         untrusted/client.crt
  Upstream CA/server/client: upstream/ca.crt, upstream/server.crt, upstream/client.crt
  Wrong upstream CA:        wrong-upstream-ca.crt
EOF
