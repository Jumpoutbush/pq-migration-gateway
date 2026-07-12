#!/usr/bin/env python3
"""Import CSV/JSON CMDB exports into the normalized endpoint target schema."""
from __future__ import annotations
import argparse, csv, json, time
from pathlib import Path
from target_sources import deduplicate, load_file

def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input',action='append',required=True)
    p.add_argument('--out-json',required=True);p.add_argument('--out-csv',default='')
    a=p.parse_args();targets=deduplicate([t for f in a.input for t in load_file(f)])
    payload={'schema_version':1,'generated_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'summary':{'targets':len(targets),'sources':len(a.input)},'targets':targets}
    Path(a.out_json).write_text(json.dumps(payload,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    if a.out_csv:
        fields=['asset_id','name','host','port','sni','protocol','owner','environment','criticality','source']
        with Path(a.out_csv).open('w',encoding='utf-8',newline='') as h:
            w=csv.DictWriter(h,fieldnames=fields);w.writeheader();w.writerows({k:t.get(k,'') for k in fields} for t in targets)
    print(json.dumps(payload['summary'],indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
