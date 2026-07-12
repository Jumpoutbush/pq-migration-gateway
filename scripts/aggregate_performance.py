#!/usr/bin/env python3
"""Aggregate benchmark JSON and docker resource samples into JSON/CSV/Markdown."""
from __future__ import annotations
import argparse,csv,json,re,time
from pathlib import Path

def parse_size(value:str)->float:
    units={'B':1,'kB':1000,'MB':1000**2,'GB':1000**3,'KiB':1024,'MiB':1024**2,'GiB':1024**3};m=re.search(r'([0-9.]+)\s*([KMG]i?B|kB|B)',value or '');return float(m.group(1))*units[m.group(2)] if m else 0
def main()->int:
    p=argparse.ArgumentParser();p.add_argument('--dir',required=True);a=p.parse_args();root=Path(a.dir);tests=[]
    for path in sorted(root.glob('*.json')):
        if path.name in {'performance-report.json'}:continue
        try:d=json.loads(path.read_text())
        except Exception:continue
        if 'test' in d:tests.append({'file':path.name,**d})
    resource={}
    stats=root/'docker-stats.jsonl'
    if stats.exists():
        for line in stats.read_text().splitlines():
            try:x=json.loads(line)
            except:continue
            name=x.get('Name') or x.get('Container','unknown');r=resource.setdefault(name,{'max_cpu_percent':0.0,'max_memory_bytes':0.0,'samples':0});r['samples']+=1;r['max_cpu_percent']=max(r['max_cpu_percent'],float(str(x.get('CPUPerc','0')).rstrip('%') or 0));r['max_memory_bytes']=max(r['max_memory_bytes'],parse_size(str(x.get('MemUsage','')).split('/')[0]))
    summary={'tests':len(tests),'failed_tests':sum(int(t.get('failures',0))>0 for t in tests),'resources':resource}
    report={'schema_version':1,'generated_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'summary':summary,'tests':tests,'resources':resource};(root/'performance-report.json').write_text(json.dumps(report,indent=2)+'\n')
    fields=['file','test','target','groups','attempts','messages','concurrency','successes','received','failures','mean_ms','p50_ms','p95_ms','p99_ms','throughput_per_s','messages_per_s']
    with (root/'performance-summary.csv').open('w',newline='',encoding='utf-8') as h:
        w=csv.DictWriter(h,fieldnames=fields);w.writeheader();w.writerows({k:t.get(k,'') for k in fields} for t in tests)
    lines=['# PQC Gateway v3 Performance Report','','| Test | Target | Group | Attempts | Concurrency | Failures | Mean ms | P95 ms | Throughput/s |','|---|---|---|---:|---:|---:|---:|---:|---:|']
    for t in tests:lines.append(f"| {t.get('test')} | {t.get('target','')} | {t.get('groups','')} | {t.get('attempts',t.get('messages',''))} | {t.get('concurrency','')} | {t.get('failures','')} | {t.get('mean_ms','')} | {t.get('p95_ms','')} | {t.get('throughput_per_s',t.get('messages_per_s',''))} |")
    lines += ['','## Resource maxima','']+[f"- {n}: CPU {r['max_cpu_percent']}%, memory {round(r['max_memory_bytes']/1024/1024,2)} MiB, samples {r['samples']}" for n,r in resource.items()]
    (root/'PERFORMANCE.md').write_text('\n'.join(lines)+'\n');print(json.dumps(summary,indent=2));return 0 if summary['failed_tests']==0 else 1
if __name__=='__main__':raise SystemExit(main())
