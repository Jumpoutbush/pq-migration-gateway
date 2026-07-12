#!/usr/bin/env python3
"""Scheduled continuous TLS scanning with snapshots, diffs and retention."""
from __future__ import annotations
import argparse,json,shutil,subprocess,sys,time
from pathlib import Path

HERE=Path(__file__).resolve().parent

def load(path:Path)->dict:return json.loads(path.read_text(encoding='utf-8'))
def run(cmd:list[str])->None:subprocess.run(cmd,check=True)
def endpoint_index(data:dict)->dict:return {e['endpoint_id']:e for e in data.get('endpoints',[])}
def compact(e:dict)->dict:return {k:e.get(k) for k in ('status','pqc_supported','classical_supported','fallback_enabled','supported_groups','certificate')}
def diff(previous:dict,current:dict)->dict:
    old,new=endpoint_index(previous),endpoint_index(current);changes=[]
    for key in sorted(set(old)|set(new)):
        if key not in old:changes.append({'endpoint_id':key,'change':'added','after':compact(new[key])})
        elif key not in new:changes.append({'endpoint_id':key,'change':'removed','before':compact(old[key])})
        elif compact(old[key])!=compact(new[key]):changes.append({'endpoint_id':key,'change':'changed','before':compact(old[key]),'after':compact(new[key])})
    return {'generated_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'summary':{'changes':len(changes)},'changes':changes}
def one_scan(config:dict)->Path:
    out=Path(config['output_dir']);out.mkdir(parents=True,exist_ok=True);stamp=time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+f'-{time.time_ns()%1_000_000:06d}';run_dir=out/stamp;run_dir.mkdir()
    targets=list(config.get('targets_files',[]))+list(config.get('cmdb_files',[]))
    discovery=''
    if config.get('cidrs'):
        discovery=str(run_dir/'network-discovery.json')
        cmd=[sys.executable,str(HERE/'network_discovery.py'),'--ports',','.join(map(str,config.get('ports',[443]))),'--max-hosts',str(config.get('max_hosts',4096)),'--workers',str(config.get('workers',64)),'--timeout',str(config.get('timeout',2.0)),'--out-json',discovery]
        for cidr in config['cidrs']:cmd += ['--cidr',cidr]
        run(cmd);targets.append(discovery)
    scan_file=run_dir/'tls-inventory.json';cmd=[sys.executable,str(HERE/'tls_scanner.py'),'--groups',config.get('groups','X25519MLKEM768:X25519'),'--openssl',config.get('openssl','openssl'),'--cafile',config.get('cafile',''),'--workers',str(config.get('workers',16)),'--timeout',str(int(config.get('timeout',10))),'--allow-unreachable','--out-json',str(scan_file),'--out-csv',str(run_dir/'tls-inventory.csv')]
    for f in targets:cmd += ['--targets-file',f]
    run(cmd)
    latest=out/'latest.json';previous=load(latest) if latest.exists() else {'endpoints':[]};current=load(scan_file);(run_dir/'diff.json').write_text(json.dumps(diff(previous,current),ensure_ascii=False,indent=2)+'\n');shutil.copy2(scan_file,latest)
    dirs=sorted([p for p in out.iterdir() if p.is_dir()]);ret=int(config.get('retention',48))
    for old in dirs[:-ret]:shutil.rmtree(old)
    return run_dir

def main()->int:
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',required=True);p.add_argument('--once',action='store_true');a=p.parse_args();config=load(Path(a.config))
    while True:
        failed = False
        try:
            print(json.dumps({'event':'scan_complete','directory':str(one_scan(config))}),flush=True)
        except Exception as exc:
            failed = True
            print(json.dumps({'event':'scan_failed','error':str(exc)}),file=sys.stderr,flush=True)
        if a.once:
            return 1 if failed else 0
        time.sleep(max(60,int(config.get('interval_seconds',300))))
if __name__=='__main__':raise SystemExit(main())
