#!/usr/bin/env python3
"""Aggregate persistent HTTP and Stream logs into real runtime migration metrics."""
from __future__ import annotations
import argparse,json,time
from collections import Counter,defaultdict
from datetime import datetime,timezone,timedelta
from pathlib import Path

def parse_ts(value:str):
    try:return datetime.fromisoformat(value.replace('Z','+00:00'))
    except ValueError:return None

def category(group:str)->str:
    u=group.upper()
    if 'MLKEM' in u or 'ML-KEM' in u:return 'hybrid_pqc'
    if group:return 'classical_fallback'
    return 'unknown'

def aggregate(paths:list[str],since:datetime|None=None,until:datetime|None=None)->dict:
    total=Counter();by_service=defaultdict(Counter);by_protocol=defaultdict(Counter);by_client=defaultdict(Counter);by_group=defaultdict(Counter);durations=defaultdict(lambda:{'sum':0.0,'count':0});invalid=0;first='';last=''
    for path in paths:
        p=Path(path)
        if not p.exists():continue
        for line in p.read_text(encoding='utf-8',errors='replace').splitlines():
            if not line.strip():continue
            try:item=json.loads(line)
            except json.JSONDecodeError:invalid+=1;continue
            ts=parse_ts(str(item.get('ts','')))
            if since and ts and ts<since:continue
            if until and ts and ts>until:continue
            stamp=str(item.get('ts',''));first=min(first,stamp) if first else stamp;last=max(last,stamp) if stamp else last
            group=str(item.get('ssl_curve','')) or 'unknown';cat=category('' if group=='unknown' else group);service=str(item.get('service','unknown'));proto=str(item.get('application_protocol') or item.get('protocol_type') or 'unknown');client=str(item.get('remote_addr','unknown'))
            total[cat]+=1;by_service[service][cat]+=1;by_protocol[proto][cat]+=1;by_client[client][cat]+=1;by_group[service][group]+=1
            raw_duration=item.get('request_time',item.get('session_time'))
            try:durations[service]['sum']+=float(raw_duration);durations[service]['count']+=1
            except (TypeError,ValueError):pass
    connections=sum(total.values())
    def rows(data):
        out={}
        for name,c in sorted(data.items()):
            n=sum(c.values());out[name]={**dict(c),'connections':n,'hybrid_adoption_rate':round(c['hybrid_pqc']/n,4) if n else None}
        return out
    return {'generated_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'window':{'first_event':first,'last_event':last,'since':since.isoformat() if since else None,'until':until.isoformat() if until else None},'summary':{'connections':connections,'hybrid_pqc':total['hybrid_pqc'],'classical_fallback':total['classical_fallback'],'unknown':total['unknown'],'hybrid_adoption_rate':round(total['hybrid_pqc']/connections,4) if connections else None,'invalid_log_lines':invalid},'services':rows(by_service),'tls_groups':{service:dict(groups) for service,groups in sorted(by_group.items())},'durations':dict(durations),'application_protocols':rows(by_protocol),'clients':rows(by_client)}

def main()->int:
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--log',action='append',required=True);p.add_argument('--out',required=True);p.add_argument('--since-hours',type=float,default=0);p.add_argument('--history',default='');a=p.parse_args()
    since=datetime.now(timezone.utc)-timedelta(hours=a.since_hours) if a.since_hours>0 else None;payload=aggregate(a.log,since)
    Path(a.out).parent.mkdir(parents=True,exist_ok=True);Path(a.out).write_text(json.dumps(payload,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    if a.history:
        Path(a.history).parent.mkdir(parents=True,exist_ok=True)
        with Path(a.history).open('a',encoding='utf-8') as h:h.write(json.dumps({'generated_at':payload['generated_at'],**payload['summary']},ensure_ascii=False)+'\n')
    print(json.dumps(payload['summary'],indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
