#!/usr/bin/env python3
"""Import static, TLS, CMDB and risk results into a deduplicated SQLite inventory."""
from __future__ import annotations
import argparse,json,sqlite3,time
from pathlib import Path
SCHEMA='''
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS scans(scan_id INTEGER PRIMARY KEY AUTOINCREMENT,imported_at TEXT NOT NULL,source_type TEXT NOT NULL,source_path TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS assets(asset_id TEXT PRIMARY KEY,asset_type TEXT NOT NULL,path TEXT NOT NULL,algorithm TEXT,key_bits TEXT,risk TEXT,pq_status TEXT,deployment_status TEXT,data_json TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence(evidence_id TEXT PRIMARY KEY,path TEXT NOT NULL,line INTEGER,evidence_type TEXT,algorithm TEXT,risk TEXT,pq_status TEXT,data_json TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS endpoints(endpoint_id TEXT PRIMARY KEY,asset_id TEXT,name TEXT,host TEXT NOT NULL,port INTEGER NOT NULL,sni TEXT NOT NULL,application_protocol TEXT,owner TEXT,environment TEXT,criticality TEXT,status TEXT,pqc_supported INTEGER,classical_supported INTEGER,fallback_enabled INTEGER,certificate_algorithm TEXT,data_json TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cmdb_assets(asset_id TEXT PRIMARY KEY,name TEXT,host TEXT,port INTEGER,sni TEXT,protocol TEXT,owner TEXT,environment TEXT,criticality TEXT,data_json TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS risk_findings(finding_id TEXT PRIMARY KEY,category TEXT,target TEXT,risk TEXT,data_json TEXT NOT NULL,updated_at TEXT NOT NULL);
'''
def load(path:str)->dict:return json.loads(Path(path).read_text(encoding='utf-8'))
def stamp()->str:return time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
def mark(conn,kind,path,now):conn.execute('INSERT INTO scans(imported_at,source_type,source_path) VALUES(?,?,?)',(now,kind,str(Path(path).resolve())))
def main()->int:
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--db',required=True);p.add_argument('--static',default='');p.add_argument('--tls',default='');p.add_argument('--risk',default='');p.add_argument('--cmdb',action='append',default=[]);p.add_argument('--summary-json',default='');a=p.parse_args();db=Path(a.db);db.parent.mkdir(parents=True,exist_ok=True);now=stamp()
    with sqlite3.connect(db) as c:
        c.executescript(SCHEMA)
        if a.static:
            d=load(a.static);mark(c,'static',a.static,now)
            for x in d.get('assets',[]):c.execute('''INSERT INTO assets VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(asset_id) DO UPDATE SET asset_type=excluded.asset_type,path=excluded.path,algorithm=excluded.algorithm,key_bits=excluded.key_bits,risk=excluded.risk,pq_status=excluded.pq_status,deployment_status=excluded.deployment_status,data_json=excluded.data_json,updated_at=excluded.updated_at''',(x['asset_id'],x['asset_type'],x['path'],x.get('algorithm'),x.get('key_bits'),x.get('risk'),x.get('pq_status'),x.get('deployment_status'),json.dumps(x,ensure_ascii=False),now))
            for x in d.get('evidence',[]):c.execute('''INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(evidence_id) DO UPDATE SET path=excluded.path,line=excluded.line,evidence_type=excluded.evidence_type,algorithm=excluded.algorithm,risk=excluded.risk,pq_status=excluded.pq_status,data_json=excluded.data_json,updated_at=excluded.updated_at''',(x['evidence_id'],x['path'],x.get('line'),x.get('evidence_type'),x.get('algorithm'),x.get('risk'),x.get('pq_status'),json.dumps(x,ensure_ascii=False),now))
        if a.tls:
            d=load(a.tls);mark(c,'tls',a.tls,now)
            for x in d.get('endpoints',[]):
                alg=x.get('certificate',{}).get('public_key_algorithm','')
                c.execute('''INSERT INTO endpoints VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(endpoint_id) DO UPDATE SET asset_id=excluded.asset_id,name=excluded.name,host=excluded.host,port=excluded.port,sni=excluded.sni,application_protocol=excluded.application_protocol,owner=excluded.owner,environment=excluded.environment,criticality=excluded.criticality,status=excluded.status,pqc_supported=excluded.pqc_supported,classical_supported=excluded.classical_supported,fallback_enabled=excluded.fallback_enabled,certificate_algorithm=excluded.certificate_algorithm,data_json=excluded.data_json,updated_at=excluded.updated_at''',(x['endpoint_id'],x.get('asset_id'),x.get('name'),x['host'],x['port'],x['sni'],x.get('application_protocol'),x.get('owner'),x.get('environment'),x.get('criticality'),x.get('status'),int(bool(x.get('pqc_supported'))),int(bool(x.get('classical_supported'))),int(bool(x.get('fallback_enabled'))),alg,json.dumps(x,ensure_ascii=False),now))
        for cmdb in a.cmdb:
            d=load(cmdb);mark(c,'cmdb',cmdb,now)
            for x in d.get('targets',[]):c.execute('''INSERT INTO cmdb_assets VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(asset_id) DO UPDATE SET name=excluded.name,host=excluded.host,port=excluded.port,sni=excluded.sni,protocol=excluded.protocol,owner=excluded.owner,environment=excluded.environment,criticality=excluded.criticality,data_json=excluded.data_json,updated_at=excluded.updated_at''',(x['asset_id'],x.get('name'),x.get('host'),x.get('port'),x.get('sni'),x.get('protocol'),x.get('owner'),x.get('environment'),x.get('criticality'),json.dumps(x,ensure_ascii=False),now))
        if a.risk:
            d=load(a.risk);mark(c,'risk',a.risk,now)
            for x in d.get('findings',[]):c.execute('''INSERT INTO risk_findings VALUES(?,?,?,?,?,?) ON CONFLICT(finding_id) DO UPDATE SET category=excluded.category,target=excluded.target,risk=excluded.risk,data_json=excluded.data_json,updated_at=excluded.updated_at''',(x['finding_id'],x.get('category'),x.get('target'),x.get('risk'),json.dumps(x,ensure_ascii=False),now))
        c.commit();summary={'database':str(db.resolve()),'assets':c.execute('SELECT COUNT(*) FROM assets').fetchone()[0],'evidence':c.execute('SELECT COUNT(*) FROM evidence').fetchone()[0],'endpoints':c.execute('SELECT COUNT(*) FROM endpoints').fetchone()[0],'cmdb_assets':c.execute('SELECT COUNT(*) FROM cmdb_assets').fetchone()[0],'risk_findings':c.execute('SELECT COUNT(*) FROM risk_findings').fetchone()[0],'scans':c.execute('SELECT COUNT(*) FROM scans').fetchone()[0]}
    if a.summary_json:Path(a.summary_json).write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(summary,indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
