#!/usr/bin/env python3
"""Discover open TCP endpoints in explicitly supplied enterprise CIDRs."""
from __future__ import annotations
import argparse,csv,json,socket,time
from concurrent.futures import ThreadPoolExecutor,as_completed
from pathlib import Path
from target_sources import expand_cidrs

def check(target:dict,timeout:float)->dict:
    started=time.perf_counter();error='';opened=False
    try:
        with socket.create_connection((target['host'],target['port']),timeout=timeout):opened=True
    except OSError as exc:error=str(exc)
    return {**target,'open':opened,'latency_ms':round((time.perf_counter()-started)*1000,3),'error':error}

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cidr',action='append',required=True,help='CIDR to scan; repeatable')
    p.add_argument('--ports',default='443,8443');p.add_argument('--max-hosts',type=int,default=4096)
    p.add_argument('--workers',type=int,default=64);p.add_argument('--timeout',type=float,default=1.5)
    p.add_argument('--out-json',required=True);p.add_argument('--out-csv',default='')
    a=p.parse_args();ports=[int(x) for x in a.ports.split(',') if x.strip()]
    candidates=expand_cidrs(a.cidr,ports,a.max_hosts);results=[]
    with ThreadPoolExecutor(max_workers=max(1,a.workers)) as pool:
        futures=[pool.submit(check,t,a.timeout) for t in candidates]
        for f in as_completed(futures):results.append(f.result())
    results.sort(key=lambda x:(x['host'],x['port']));opened=[x for x in results if x['open']]
    payload={'schema_version':1,'generated_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'cidrs':a.cidr,'ports':ports,'summary':{'candidates':len(results),'open':len(opened),'closed':len(results)-len(opened)},'open_endpoints':opened,'results':results}
    Path(a.out_json).write_text(json.dumps(payload,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    if a.out_csv:
        fields=['host','port','open','latency_ms','error','source']
        with Path(a.out_csv).open('w',encoding='utf-8',newline='') as h:
            w=csv.DictWriter(h,fieldnames=fields);w.writeheader();w.writerows({k:r.get(k,'') for k in fields} for r in results)
    print(json.dumps(payload['summary'],indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
