#!/usr/bin/env python3
"""Concurrent TLS 1.3/PQC scanner with batch, CMDB and discovery inputs."""
from __future__ import annotations
import argparse,csv,hashlib,json,re,subprocess,tempfile,time
from concurrent.futures import ThreadPoolExecutor,as_completed
from dataclasses import asdict,dataclass
from pathlib import Path
from target_sources import deduplicate,load_file,parse_endpoint

DEFAULT_GROUPS=['X25519MLKEM768','X25519']

@dataclass
class Probe:
    requested_group:str;success:bool;return_code:int;elapsed_ms:float;protocol:str='';cipher_suite:str='';negotiated_group:str='';verification:str='';error_tail:str=''
@dataclass
class EndpointResult:
    endpoint_id:str;asset_id:str;name:str;host:str;port:int;sni:str;application_protocol:str;owner:str;environment:str;criticality:str;source:str;status:str;pqc_supported:bool;classical_supported:bool;fallback_enabled:bool;supported_groups:list[str];certificate:dict;probes:list[dict]

def run(cmd:list[str],timeout:int)->tuple[int,str,float]:
    start=time.perf_counter()
    try:p=subprocess.run(cmd,input=b'',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:return 124,str(exc),(time.perf_counter()-start)*1000
    return p.returncode,(p.stdout+b'\n'+p.stderr).decode('utf-8','replace'),(time.perf_counter()-start)*1000

def match(pattern:str,text:str)->str:
    m=re.search(pattern,text,re.I|re.M);return m.group(1).strip() if m else ''

def first_certificate(text:str)->str:
    m=re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',text,re.S);return m.group(0) if m else ''

def cert_info(openssl_bin:str,pem:str,timeout:int)->dict:
    if not pem:return {}
    with tempfile.NamedTemporaryFile('w',delete=False) as f:f.write(pem);name=f.name
    try:
        rc,text,_=run([openssl_bin,'x509','-in',name,'-noout','-subject','-issuer','-dates','-serial','-fingerprint','-sha256','-text'],timeout)
    finally:Path(name).unlink(missing_ok=True)
    if rc:return {}
    alg=match(r'Public Key Algorithm:\s*([^\n]+)',text);sig=match(r'Signature Algorithm:\s*([^\n]+)',text);bits=match(r'Public-Key:\s*\((\d+)\s+bit',text)
    blob=f'{alg} {sig}';vulnerable=bool(re.search(r'RSA|ECDSA|id-ecPublicKey|DSA',blob,re.I))
    return {'subject':match(r'^subject=(.*)$',text),'issuer':match(r'^issuer=(.*)$',text),'not_before':match(r'^notBefore=(.*)$',text),'not_after':match(r'^notAfter=(.*)$',text),'serial':match(r'^serial=(.*)$',text),'sha256_fingerprint':match(r'SHA256 Fingerprint=(.*)$',text),'public_key_algorithm':alg,'signature_algorithm':sig,'public_key_bits':bits,'quantum_vulnerable_authentication':vulnerable}

def probe(openssl_bin:str,target:dict,group:str,cafile:str,no_verify:bool,timeout:int)->tuple[Probe,str]:
    cmd=[openssl_bin,'s_client','-connect',f"{target['host']}:{target['port']}",'-servername',target['sni'],'-tls1_3','-groups',group,'-showcerts','-brief']
    cert=target.get('client_certificate','');key=target.get('client_key','')
    if cert and key:cmd += ['-cert',cert,'-key',key]
    if cafile:cmd += ['-CAfile',cafile,'-verify_return_error']
    elif no_verify:cmd += ['-verify_quiet']
    rc,text,elapsed=run(cmd,timeout)
    protocol=match(r'Protocol version:\s*([^\n]+)',text) or match(r'Protocol\s*:\s*([^\n]+)',text)
    negotiated=match(r'Negotiated TLS1\.3 group:\s*([^\n]+)',text) or match(r'(?:Server|Peer) Temp Key:\s*([^,\n]+)',text)
    verification=match(r'Verification:\s*([^\n]+)',text)
    # Stream protocols may complete the TLS handshake and then close without an
    # application response, which can make s_client return non-zero.  Treat the
    # endpoint as TLS-capable when negotiation and certificate verification
    # succeeded; retain return_code for diagnostics.
    verified = no_verify or not cafile or verification.upper() == 'OK'
    success=bool(protocol) and bool(negotiated) and verified
    return Probe(group,success,rc,round(elapsed,3),protocol,match(r'Ciphersuite:\s*([^\n]+)',text) or match(r'Cipher\s*:\s*([^\n]+)',text),negotiated,verification,'\n'.join(text.splitlines()[-8:]) if not success else ''),first_certificate(text)

def scan_target(openssl_bin:str,target:dict,groups:list[str],cafile:str,no_verify:bool,timeout:int)->EndpointResult:
    probes=[];pem=''
    for group in groups:
        item,cert=probe(openssl_bin,target,group,cafile,no_verify,timeout);probes.append(item);pem=pem or cert
    supported=[p.requested_group for p in probes if p.success]
    pqc=any('MLKEM' in g.upper() or 'ML-KEM' in g.upper() for g in supported);classical='X25519' in supported
    digest=hashlib.sha256(f"{target['host']}:{target['port']}:{target['sni']}".encode()).hexdigest()[:20]
    return EndpointResult('endpoint-'+digest,target.get('asset_id',''),target.get('name',''),target['host'],int(target['port']),target['sni'],target.get('protocol','tls'),target.get('owner',''),target.get('environment',''),target.get('criticality',''),target.get('source',''),'reachable' if supported else 'unreachable_or_incompatible',pqc,classical,pqc and classical,supported,cert_info(openssl_bin,pem,timeout),[asdict(p) for p in probes])

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--endpoint',action='append',default=[]);p.add_argument('--targets-file',action='append',default=[]);p.add_argument('--cmdb-file',action='append',default=[]);p.add_argument('--discovery-file',action='append',default=[])
    p.add_argument('--groups',default=':'.join(DEFAULT_GROUPS));p.add_argument('--openssl',default='openssl');p.add_argument('--cafile',default='');p.add_argument('--no-verify',action='store_true');p.add_argument('--timeout',type=int,default=10);p.add_argument('--workers',type=int,default=16);p.add_argument('--allow-unreachable',action='store_true');p.add_argument('--out-json',required=True);p.add_argument('--out-csv',default='')
    a=p.parse_args();targets=[parse_endpoint(x) for x in a.endpoint]
    for f in a.targets_file+a.cmdb_file+a.discovery_file:targets.extend(load_file(f))
    targets=deduplicate(targets)
    if not targets:p.error('at least one endpoint or target file is required')
    groups=[x for x in a.groups.split(':') if x];results=[]
    with ThreadPoolExecutor(max_workers=max(1,a.workers)) as pool:
        futures={pool.submit(scan_target,a.openssl,t,groups,a.cafile,a.no_verify,a.timeout):t for t in targets}
        for f in as_completed(futures):
            try:results.append(f.result())
            except Exception as exc:
                t=futures[f];digest=hashlib.sha256(f"{t['host']}:{t['port']}:{t['sni']}".encode()).hexdigest()[:20]
                results.append(EndpointResult('endpoint-'+digest,t.get('asset_id',''),t.get('name',''),t['host'],t['port'],t['sni'],t.get('protocol','tls'),t.get('owner',''),t.get('environment',''),t.get('criticality',''),t.get('source',''),'scanner_error',False,False,False,[],{},[{'error':str(exc)}]))
    results.sort(key=lambda x:(x.host,x.port,x.sni))
    payload={'schema_version':3,'generated_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'groups_tested':groups,'summary':{'endpoints':len(results),'reachable':sum(x.status=='reachable' for x in results),'pqc_supported':sum(x.pqc_supported for x in results),'fallback_enabled':sum(x.fallback_enabled for x in results),'unreachable':sum(x.status!='reachable' for x in results)},'endpoints':[asdict(x) for x in results]}
    Path(a.out_json).write_text(json.dumps(payload,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    if a.out_csv:
        fields=['endpoint_id','asset_id','name','host','port','sni','application_protocol','owner','environment','criticality','source','status','pqc_supported','classical_supported','fallback_enabled','supported_groups','certificate_algorithm','certificate_bits']
        with Path(a.out_csv).open('w',encoding='utf-8',newline='') as h:
            w=csv.DictWriter(h,fieldnames=fields);w.writeheader()
            for e in results:w.writerow({'endpoint_id':e.endpoint_id,'asset_id':e.asset_id,'name':e.name,'host':e.host,'port':e.port,'sni':e.sni,'application_protocol':e.application_protocol,'owner':e.owner,'environment':e.environment,'criticality':e.criticality,'source':e.source,'status':e.status,'pqc_supported':e.pqc_supported,'classical_supported':e.classical_supported,'fallback_enabled':e.fallback_enabled,'supported_groups':':'.join(e.supported_groups),'certificate_algorithm':e.certificate.get('public_key_algorithm',''),'certificate_bits':e.certificate.get('public_key_bits','')})
    print(json.dumps(payload['summary'],indent=2));return 0 if a.allow_unreachable or payload['summary']['unreachable']==0 else 1
if __name__=='__main__':raise SystemExit(main())
