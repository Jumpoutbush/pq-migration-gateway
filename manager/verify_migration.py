#!/usr/bin/env python3
"""Verify online capabilities against every configured HTTP and Stream policy."""
from __future__ import annotations
import argparse,json,time
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from gateway.model import compatibility_view

def main()->int:
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--services',required=True);p.add_argument('--tls',required=True);p.add_argument('--out',required=True);a=p.parse_args()
    services=compatibility_view(json.loads(Path(a.services).read_text()));endpoints=json.loads(Path(a.tls).read_text()).get('endpoints',[]);index={(e.get('sni'),e.get('port')):e for e in endpoints};results=[]
    for s in services:
        endpoint=index.get((s['server_name'],s['listen_port']));expected={g for g in s.get('tls_groups','').split(':') if g};fail=[]
        if endpoint is None:fail.append('No matching TLS scan result.')
        else:
            supported=set(endpoint.get('supported_groups',[]))
            if 'X25519MLKEM768' in expected and 'X25519MLKEM768' not in supported:fail.append('Hybrid/PQC group was not negotiated.')
            if expected=={'X25519MLKEM768'} and 'X25519' in supported:fail.append('Strict service accepts classical fallback.')
            if 'X25519' in expected and 'X25519' not in supported:fail.append('Configured classical fallback was not available.')
        results.append({'service':s['name'],'protocol':s.get('protocol','http'),'application_protocol':s.get('application_protocol','http'),'server_name':s['server_name'],'port':s['listen_port'],'configured_groups':s.get('tls_groups',''),'status':'PASS' if not fail else 'FAIL','failures':fail})
    payload={'schema_version':3,'generated_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'summary':{'services':len(results),'passed':sum(x['status']=='PASS' for x in results),'failed':sum(x['status']=='FAIL' for x in results)},'results':results};Path(a.out).write_text(json.dumps(payload,ensure_ascii=False,indent=2)+'\n');print(json.dumps(payload['summary'],indent=2));return 0 if payload['summary']['failed']==0 else 1
if __name__=='__main__':raise SystemExit(main())
