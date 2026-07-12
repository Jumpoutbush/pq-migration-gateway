#!/usr/bin/env python3
"""Concurrent end-to-end TLS handshake benchmark using a selected OpenSSL group."""
from __future__ import annotations
import argparse,json,statistics,subprocess,time
from concurrent.futures import ThreadPoolExecutor,as_completed
from pathlib import Path

def percentile(values:list[float],p:float):
    if not values:return None
    s=sorted(values);return s[min(len(s)-1,max(0,int((len(s)-1)*p)))]
def one(openssl:str,host:str,port:int,sni:str,group:str,cafile:str,timeout:int,cert:str='',key:str='')->tuple[bool,float,str]:
    cmd=[openssl,'s_client','-connect',f'{host}:{port}','-servername',sni,'-tls1_3','-groups',group,'-brief']
    if cert and key:cmd += ['-cert',cert,'-key',key]
    if cafile:cmd += ['-CAfile',cafile,'-verify_return_error']
    start=time.perf_counter()
    try:r=subprocess.run(cmd,input=b'',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
    except subprocess.TimeoutExpired as exc:return False,(time.perf_counter()-start)*1000,str(exc)
    elapsed=(time.perf_counter()-start)*1000;text=(r.stdout+r.stderr).decode('utf-8','replace');return r.returncode==0 and ('Protocol version: TLSv1.3' in text or 'Protocol  : TLSv1.3' in text),elapsed,text

def main()->int:
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--host',required=True);p.add_argument('--port',type=int,required=True);p.add_argument('--sni',default='');p.add_argument('--groups',required=True);p.add_argument('--openssl',default='openssl');p.add_argument('--cafile',default='');p.add_argument('--count',type=int,default=50);p.add_argument('--warmup',type=int,default=5);p.add_argument('--concurrency',type=int,default=1);p.add_argument('--timeout',type=int,default=10);p.add_argument('--cert',default='');p.add_argument('--key',default='');p.add_argument('--out',default='');a=p.parse_args();sni=a.sni or a.host
    for _ in range(a.warmup):one(a.openssl,a.host,a.port,sni,a.groups,a.cafile,a.timeout,a.cert,a.key)
    start=time.perf_counter();times=[];fail=[]
    with ThreadPoolExecutor(max_workers=max(1,a.concurrency)) as pool:
        fs=[pool.submit(one,a.openssl,a.host,a.port,sni,a.groups,a.cafile,a.timeout,a.cert,a.key) for _ in range(a.count)]
        for f in as_completed(fs):
            ok,elapsed,text=f.result();times.append(elapsed) if ok else fail.append('\n'.join(text.splitlines()[-6:]))
    wall=time.perf_counter()-start
    result={'test':'tls_handshake','target':f'{a.host}:{a.port}','sni':sni,'groups':a.groups,'attempts':a.count,'warmup':a.warmup,'concurrency':a.concurrency,'successes':len(times),'failures':len(fail),'wall_time_s':round(wall,4),'throughput_per_s':round(a.count/wall,3) if wall else None,'mean_ms':round(statistics.mean(times),3) if times else None,'median_ms':round(statistics.median(times),3) if times else None,'p50_ms':round(percentile(times,.50),3) if times else None,'p95_ms':round(percentile(times,.95),3) if times else None,'p99_ms':round(percentile(times,.99),3) if times else None,'min_ms':round(min(times),3) if times else None,'max_ms':round(max(times),3) if times else None,'failure_samples':fail[:3]}
    data=json.dumps(result,ensure_ascii=False,indent=2);print(data)
    if a.out:Path(a.out).write_text(data+'\n')
    return 0 if not fail else 1
if __name__=='__main__':raise SystemExit(main())
