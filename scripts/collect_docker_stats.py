#!/usr/bin/env python3
"""Collect periodic docker stats samples until a stop file appears."""
from __future__ import annotations
import argparse,json,subprocess,time
from pathlib import Path

def main()->int:
    p=argparse.ArgumentParser();p.add_argument('--container',action='append',required=True);p.add_argument('--out',required=True);p.add_argument('--stop-file',required=True);p.add_argument('--interval',type=float,default=1.0);a=p.parse_args();out=Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
    while not Path(a.stop_file).exists():
        r=subprocess.run(['docker','stats','--no-stream','--format','{{json .}}',*a.container],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
        stamp=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
        with out.open('a',encoding='utf-8') as h:
            for line in r.stdout.decode().splitlines():
                try:item=json.loads(line);item['ts']=stamp;h.write(json.dumps(item)+'\n')
                except json.JSONDecodeError:pass
        time.sleep(max(.2,a.interval))
    return 0
if __name__=='__main__':raise SystemExit(main())
