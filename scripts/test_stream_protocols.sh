#!/usr/bin/env bash
set -Eeuo pipefail
OUT_DIR="${1:-experiment-results/stream}"
mkdir -p "$OUT_DIR"
OPENSSL=/opt/openssl/bin/openssl
CA=/etc/pq-gateway/certs/ca.crt

# Verify Hybrid/PQC handshakes on every non-HTTP endpoint.
for spec in '8883 mqtt-gateway.local mqtt' '15443 tcp-gateway.local tcp' '16443 legacy-gateway.local legacy';do
  read -r port sni name <<<"$spec"
  docker compose exec -T pq-gateway "$OPENSSL" s_client -connect "localhost:$port" -servername "$sni" -tls1_3 -groups X25519MLKEM768 -CAfile "$CA" -verify_return_error -brief </dev/null >"$OUT_DIR/${name}-hybrid-handshake.txt" 2>&1 || true
  grep -q 'Verification: OK' "$OUT_DIR/${name}-hybrid-handshake.txt"
  grep -q 'X25519MLKEM768' "$OUT_DIR/${name}-hybrid-handshake.txt"
done

printf 'hello-stream\n' | timeout 12 docker compose exec -T pq-gateway "$OPENSSL" s_client -quiet -connect localhost:15443 -servername tcp-gateway.local -tls1_3 -groups X25519MLKEM768 -CAfile "$CA" -verify_return_error >"$OUT_DIR/tcp-echo.txt" 2>&1 || true
grep -q 'ECHO hello-stream' "$OUT_DIR/tcp-echo.txt"

printf 'PING\r\nVERSION\r\nQUIT\r\n' | timeout 12 docker compose exec -T pq-gateway "$OPENSSL" s_client -quiet -connect localhost:16443 -servername legacy-gateway.local -tls1_3 -groups X25519MLKEM768 -CAfile "$CA" -verify_return_error >"$OUT_DIR/legacy-line.txt" 2>&1 || true
grep -q 'LEGACY/1.0 READY' "$OUT_DIR/legacy-line.txt"
grep -q 'PONG' "$OUT_DIR/legacy-line.txt"

docker compose exec -T pq-gateway sh -lc '
  rm -f /tmp/mqtt-message.txt
  mosquitto_sub -h localhost -p 8883 --cafile /etc/pq-gateway/certs/ca.crt --tls-version tlsv1.3 -t pqc/v3/test -C 1 -W 15 > /tmp/mqtt-message.txt &
  pid=$!
  sleep 1
  mosquitto_pub -h localhost -p 8883 --cafile /etc/pq-gateway/certs/ca.crt --tls-version tlsv1.3 -t pqc/v3/test -m pqc-mqtt-ok
  wait "$pid"
  cat /tmp/mqtt-message.txt
' >"$OUT_DIR/mqtt-pubsub.txt" 2>&1
grep -q 'pqc-mqtt-ok' "$OUT_DIR/mqtt-pubsub.txt"

python3 - "$OUT_DIR/stream-protocol-matrix.json" <<'PY'
import json,sys,time
rows=[{'test':'mqtt_tls_hybrid_and_pubsub','status':'PASS'},{'test':'generic_tcp_tls_echo','status':'PASS'},{'test':'legacy_non_http_tls','status':'PASS'}]
p={'generated_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'summary':{'tests':3,'passed':3,'failed':0},'results':rows}
open(sys.argv[1],'w').write(json.dumps(p,indent=2)+'\n');print(json.dumps(p['summary'],indent=2))
PY
