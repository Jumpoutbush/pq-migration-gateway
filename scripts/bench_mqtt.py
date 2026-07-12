#!/usr/bin/env python3
"""Batch MQTT publish/subscribe throughput benchmark through the TLS gateway."""
from __future__ import annotations
import argparse,json,subprocess,tempfile,time
from pathlib import Path

def main()->int:
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--host',default='localhost');p.add_argument('--port',type=int,default=8883);p.add_argument('--cafile',required=True);p.add_argument('--count',type=int,default=100);p.add_argument('--topic',default='pqc/performance');p.add_argument('--out',required=True);a=p.parse_args()
    common=['-h',a.host,'-p',str(a.port),'--cafile',a.cafile,'--tls-version','tlsv1.3']
    with tempfile.NamedTemporaryFile('w',delete=False) as f:
        for i in range(a.count):f.write(f'message-{i}\n')
        lines=f.name
    sub=subprocess.Popen(['mosquitto_sub',*common,'-t',a.topic,'-C',str(a.count),'-W','60'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    time.sleep(.5);start=time.perf_counter();pub=subprocess.run(['mosquitto_pub',*common,'-t',a.topic,'-l'],stdin=open(lines,'rb'),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60);stdout,stderr=sub.communicate(timeout=65);elapsed=time.perf_counter()-start;received=len(stdout.splitlines());Path(lines).unlink(missing_ok=True)
    result={'test':'mqtt_pubsub','target':f'{a.host}:{a.port}','messages':a.count,'received':received,'failures':0 if pub.returncode==0 and sub.returncode==0 and received==a.count else 1,'elapsed_s':round(elapsed,4),'messages_per_s':round(a.count/elapsed,3) if elapsed else None,'publisher_error':pub.stderr.decode('utf-8','replace')[-500:],'subscriber_error':stderr.decode('utf-8','replace')[-500:]};Path(a.out).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2));return 0 if result['failures']==0 else 1
if __name__=='__main__':raise SystemExit(main())
