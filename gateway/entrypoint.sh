#!/usr/bin/env sh
set -eu

mkdir -p /tmp/pq-gateway /var/log/nginx /var/cache/nginx/client_temp

: "${GATEWAY_LISTEN_PORT:=8443}"
: "${GATEWAY_SERVER_NAME:=bank-gateway.local}"
: "${GATEWAY_CERT:=/etc/pq-gateway/certs/server.crt}"
: "${GATEWAY_KEY:=/etc/pq-gateway/certs/server.key}"
: "${TLS_GROUPS:=X25519MLKEM768:X25519}"
: "${UPSTREAM_URL:=http://bank-backend:8080}"
: "${UPSTREAM_TLS_VERIFY:=off}"
: "${UPSTREAM_CA:=/etc/pq-gateway/certs/upstream-ca.crt}"
: "${CLIENT_AUTH:=off}"
: "${CLIENT_CA:=/etc/pq-gateway/certs/ca.crt}"
: "${DNS_RESOLVER:=127.0.0.11}"
: "${UPSTREAM_CONNECT_TIMEOUT:=3s}"
: "${UPSTREAM_SEND_TIMEOUT:=30s}"
: "${UPSTREAM_READ_TIMEOUT:=30s}"

case "$CLIENT_AUTH" in
  off)
    cat > /tmp/pq-gateway/client-auth.conf <<EOF
# mTLS disabled.
EOF
    ;;
  optional)
    cat > /tmp/pq-gateway/client-auth.conf <<EOF
ssl_client_certificate ${CLIENT_CA};
ssl_verify_client optional;
ssl_verify_depth 3;
EOF
    ;;
  required|on)
    cat > /tmp/pq-gateway/client-auth.conf <<EOF
ssl_client_certificate ${CLIENT_CA};
ssl_verify_client on;
ssl_verify_depth 3;
EOF
    ;;
  *)
    echo "Unsupported CLIENT_AUTH=$CLIENT_AUTH. Use off, optional, or required." >&2
    exit 2
    ;;
esac

case "$UPSTREAM_TLS_VERIFY" in
  off)
    cat > /tmp/pq-gateway/upstream-tls.conf <<EOF
proxy_ssl_server_name on;
proxy_ssl_verify off;
proxy_ssl_protocols TLSv1.2 TLSv1.3;
EOF
    ;;
  on|required)
    cat > /tmp/pq-gateway/upstream-tls.conf <<EOF
proxy_ssl_server_name on;
proxy_ssl_verify on;
proxy_ssl_trusted_certificate ${UPSTREAM_CA};
proxy_ssl_verify_depth 3;
proxy_ssl_protocols TLSv1.2 TLSv1.3;
EOF
    ;;
  *)
    echo "Unsupported UPSTREAM_TLS_VERIFY=$UPSTREAM_TLS_VERIFY. Use off or on." >&2
    exit 2
    ;;
esac

envsubst '${GATEWAY_LISTEN_PORT} ${GATEWAY_SERVER_NAME} ${GATEWAY_CERT} ${GATEWAY_KEY} ${TLS_GROUPS} ${UPSTREAM_URL} ${DNS_RESOLVER} ${UPSTREAM_CONNECT_TIMEOUT} ${UPSTREAM_SEND_TIMEOUT} ${UPSTREAM_READ_TIMEOUT}' \
  < /etc/pq-gateway/templates/nginx.conf.template \
  > /tmp/pq-gateway/nginx.conf

echo "pq-gateway effective settings:" >&2
echo "  listen=${GATEWAY_LISTEN_PORT}" >&2
echo "  server_name=${GATEWAY_SERVER_NAME}" >&2
echo "  tls_groups=${TLS_GROUPS}" >&2
echo "  upstream=${UPSTREAM_URL}" >&2
echo "  client_auth=${CLIENT_AUTH}" >&2
echo "  upstream_tls_verify=${UPSTREAM_TLS_VERIFY}" >&2

exec /opt/nginx/sbin/nginx -g 'daemon off;' -c /tmp/pq-gateway/nginx.conf
