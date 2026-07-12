#!/usr/bin/env bash
set -Eeuo pipefail
OUT_DIR="${1:-experiment-results/performance}"
PROFILE="${PERF_PROFILE:-standard}"
mkdir -p "$OUT_DIR";rm -f "$OUT_DIR/stop-stats"
case "$PROFILE" in
  quick) COUNT=20;CONCURRENCY=2;MQTT_COUNT=30;;
  standard) COUNT=100;CONCURRENCY=10;MQTT_COUNT=200;;
  stress) COUNT=500;CONCURRENCY=25;MQTT_COUNT=1000;;
  *) echo "Unknown PERF_PROFILE=$PROFILE" >&2;exit 2;;
esac
OPENSSL=/opt/openssl/bin/openssl;CA=/etc/pq-gateway/certs/ca.crt
python3 scripts/collect_docker_stats.py --container pq-gateway --container bank-backend --container secure-backend --container mqtt-broker --out "$OUT_DIR/docker-stats.jsonl" --stop-file "$OUT_DIR/stop-stats" --interval 1 & STATS_PID=$!
cleanup(){ touch "$OUT_DIR/stop-stats";wait "$STATS_PID" 2>/dev/null || true; };trap cleanup EXIT
bench_hs(){ local port="$1" sni="$2" group="$3" file="$4";shift 4;docker compose exec -T pq-gateway python3 /workspace/scripts/bench_handshake.py --host localhost --port "$port" --sni "$sni" --groups "$group" --openssl "$OPENSSL" --cafile "$CA" --count "$COUNT" --warmup 5 --concurrency "$CONCURRENCY" --out "/tmp/$file" "$@";docker cp "pq-gateway:/tmp/$file" "$OUT_DIR/$file"; }
bench_proto(){ local mode="$1" port="$2" sni="$3" group="$4" file="$5";shift 5;docker compose exec -T pq-gateway python3 /workspace/scripts/bench_protocol.py --mode "$mode" --host localhost --port "$port" --sni "$sni" --groups "$group" --openssl "$OPENSSL" --cafile "$CA" --count "$COUNT" --warmup 5 --concurrency "$CONCURRENCY" --out "/tmp/$file" "$@";docker cp "pq-gateway:/tmp/$file" "$OUT_DIR/$file"; }
bench_hs 8443 bank-gateway.local X25519MLKEM768 handshake-hybrid.json
bench_hs 8443 bank-gateway.local X25519 handshake-x25519.json
bench_hs 9443 strict-gateway.local X25519MLKEM768 handshake-strict-hybrid.json
bench_hs 10443 mtls-gateway.local X25519MLKEM768 handshake-mtls-hybrid.json --cert /etc/pq-gateway/certs/client.crt --key /etc/pq-gateway/certs/client.key
bench_proto http 8443 bank-gateway.local X25519MLKEM768 http-hybrid.json
bench_proto http 8443 bank-gateway.local X25519 http-x25519.json
bench_proto http 10443 mtls-gateway.local X25519MLKEM768 http-mtls-hybrid.json --cert /etc/pq-gateway/certs/client.crt --key /etc/pq-gateway/certs/client.key
bench_proto http 12443 upstream-gateway.local X25519MLKEM768 http-upstream-mtls-hybrid.json --path /tls-info
bench_proto tcp 15443 tcp-gateway.local X25519MLKEM768 tcp-hybrid.json
bench_proto tcp 15443 tcp-gateway.local X25519 tcp-x25519.json
bench_proto legacy 16443 legacy-gateway.local X25519MLKEM768 legacy-hybrid.json
docker compose exec -T pq-gateway python3 /workspace/scripts/bench_mqtt_openssl.py --host localhost --port 8883 --sni mqtt-gateway.local --groups X25519MLKEM768 --openssl "$OPENSSL" --cafile "$CA" --count "$MQTT_COUNT" --warmup 5 --out /tmp/mqtt-hybrid.json
docker cp pq-gateway:/tmp/mqtt-hybrid.json "$OUT_DIR/mqtt-hybrid.json"
docker compose exec -T pq-gateway python3 /workspace/scripts/bench_mqtt_openssl.py --host localhost --port 8883 --sni mqtt-gateway.local --groups X25519 --openssl "$OPENSSL" --cafile "$CA" --count "$MQTT_COUNT" --warmup 5 --out /tmp/mqtt-x25519.json
docker cp pq-gateway:/tmp/mqtt-x25519.json "$OUT_DIR/mqtt-x25519.json"
# Compatibility-client baseline using the distribution MQTT CLI.
docker compose exec -T pq-gateway python3 /workspace/scripts/bench_mqtt.py --host localhost --port 8883 --cafile "$CA" --count "$MQTT_COUNT" --out /tmp/mqtt-compatible-client.json
docker cp pq-gateway:/tmp/mqtt-compatible-client.json "$OUT_DIR/mqtt-compatible-client.json"
cleanup;trap - EXIT
python3 scripts/aggregate_performance.py --dir "$OUT_DIR"
