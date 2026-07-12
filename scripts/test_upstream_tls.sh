#!/usr/bin/env bash
set -Eeuo pipefail
OUT_DIR="${1:-experiment-results/upstream-tls}"
mkdir -p "$OUT_DIR"
CA=certs/ca.crt

request_code(){
  local port="$1" host="$2" path="$3" out="$4"
  curl --noproxy '*' --silent --show-error --connect-timeout 5 --max-time 20 \
    --resolve "${host}:${port}:127.0.0.1" --cacert "$CA" \
    -o "$out" -w '%{http_code}' "https://${host}:${port}${path}"
}
wait_healthy(){
  for _ in $(seq 1 40);do
    status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' secure-backend 2>/dev/null || true)"
    [[ "$status" == healthy ]] && return 0;sleep 1
  done
  return 1
}

code="$(request_code 12443 upstream-gateway.local /tls-info "$OUT_DIR/verified-before.json")"
[[ "$code" == 200 ]]
grep -q '"server_name_received":"upstream-secure.local"' "$OUT_DIR/verified-before.json"
grep -q 'gateway-upstream-client.local' "$OUT_DIR/verified-before.json"

code_bad="$(request_code 13443 badca-gateway.local /tls-info "$OUT_DIR/wrong-ca-body.txt")"
[[ "$code_bad" == 502 ]]
code_missing="$(request_code 14443 upstream-noclient-gateway.local /tls-info "$OUT_DIR/missing-client-cert-body.txt")"
[[ "$code_missing" == 502 ]]

./certs/rotate-upstream-server-cert.sh ./certs/upstream | tee "$OUT_DIR/certificate-rotation.json"
grep -q '"rotated":true' "$OUT_DIR/certificate-rotation.json"
docker compose restart secure-backend >/dev/null
wait_healthy
code_after="$(request_code 12443 upstream-gateway.local /tls-info "$OUT_DIR/verified-after.json")"
[[ "$code_after" == 200 ]]
grep -q '"server_name_received":"upstream-secure.local"' "$OUT_DIR/verified-after.json"

python3 - "$OUT_DIR" "$code" "$code_bad" "$code_missing" "$code_after" <<'PY'
import json,sys,time
from pathlib import Path
r=Path(sys.argv[1]);rotation=json.loads((r/'certificate-rotation.json').read_text())
rows=[
 {'test':'verified_ca_sni_upstream_mtls','status':'PASS' if sys.argv[2]=='200' else 'FAIL','http_status':int(sys.argv[2])},
 {'test':'wrong_upstream_ca_rejected','status':'PASS' if sys.argv[3]=='502' else 'FAIL','http_status':int(sys.argv[3])},
 {'test':'missing_upstream_client_certificate_rejected','status':'PASS' if sys.argv[4]=='502' else 'FAIL','http_status':int(sys.argv[4])},
 {'test':'upstream_certificate_rotation','status':'PASS' if sys.argv[5]=='200' and rotation.get('rotated') else 'FAIL','http_status':int(sys.argv[5]),**rotation},
]
p={'generated_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'summary':{'tests':len(rows),'passed':sum(x['status']=='PASS' for x in rows),'failed':sum(x['status']=='FAIL' for x in rows)},'results':rows}
(r/'upstream-tls-matrix.json').write_text(json.dumps(p,indent=2)+'\n');print(json.dumps(p['summary'],indent=2));raise SystemExit(0 if p['summary']['failed']==0 else 1)
PY
