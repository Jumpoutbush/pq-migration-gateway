#!/usr/bin/env bash
set -Eeuo pipefail
OUT_DIR="${1:-experiment-results/mtls}"
mkdir -p "$OUT_DIR"
CA=certs/ca.crt
GOOD_CERT=certs/client.crt
GOOD_KEY=certs/client.key
BAD_CERT=certs/untrusted/client.crt
BAD_KEY=certs/untrusted/client.key
RESULTS="$OUT_DIR/results.tsv"
: > "$RESULTS"

record(){ printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$RESULTS"; }
request(){
  local port="$1" host="$2" out="$3";shift 3
  curl --noproxy '*' --fail-with-body --silent --show-error --connect-timeout 5 --max-time 15 \
    --resolve "${host}:${port}:127.0.0.1" --cacert "$CA" "$@" \
    "https://${host}:${port}/service-info" >"$out" 2>"${out}.err"
}
expect_success(){
  local name="$1" port="$2" host="$3";shift 3;local out="$OUT_DIR/${name}.json"
  if request "$port" "$host" "$out" "$@"; then record "$name" PASS success; else cat "${out}.err" >&2;record "$name" FAIL unexpected_failure;return 1;fi
}
expect_failure(){
  local name="$1" port="$2" host="$3";shift 3;local out="$OUT_DIR/${name}.txt"
  if request "$port" "$host" "$out" "$@"; then record "$name" FAIL unexpected_success;return 1;else record "$name" PASS rejected;fi
}

expect_success off_no_certificate 8443 bank-gateway.local
expect_success optional_no_certificate 11443 optional-mtls-gateway.local
expect_success optional_valid_certificate 11443 optional-mtls-gateway.local --cert "$GOOD_CERT" --key "$GOOD_KEY"
expect_failure optional_untrusted_certificate 11443 optional-mtls-gateway.local --cert "$BAD_CERT" --key "$BAD_KEY"
expect_failure required_no_certificate 10443 mtls-gateway.local
expect_success required_valid_certificate 10443 mtls-gateway.local --cert "$GOOD_CERT" --key "$GOOD_KEY"
grep -q '"client_verify":"SUCCESS"' "$OUT_DIR/required_valid_certificate.json"
expect_failure required_untrusted_certificate 10443 mtls-gateway.local --cert "$BAD_CERT" --key "$BAD_KEY"

python3 - "$RESULTS" "$OUT_DIR/mtls-matrix.json" <<'PY'
import csv,json,sys,time
rows=[]
with open(sys.argv[1],encoding='utf-8') as f:
    for name,status,detail in csv.reader(f,delimiter='\t'):rows.append({'test':name,'status':status,'detail':detail})
p={'generated_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'summary':{'tests':len(rows),'passed':sum(x['status']=='PASS' for x in rows),'failed':sum(x['status']=='FAIL' for x in rows)},'results':rows}
open(sys.argv[2],'w').write(json.dumps(p,indent=2)+'\n');print(json.dumps(p['summary'],indent=2))
raise SystemExit(0 if p['summary']['failed']==0 else 1)
PY
