#!/usr/bin/env python3
"""Benchmark HTTP, generic TCP and legacy protocols through the TLS gateway."""
from __future__ import annotations
import argparse,json,statistics,subprocess,time
from concurrent.futures import ThreadPoolExecutor,as_completed
from pathlib import Path
import argparse
import json
import selectors
import statistics
import subprocess
import time

def pct(v,p):
    s=sorted(v);return s[min(len(s)-1,int((len(s)-1)*p))] if s else None
def payload(mode,path,sni):
    if mode=='http':return f'GET {path} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n'.encode(),'200 OK'
    if mode=='tcp':return b'performance-payload\n','ECHO performance-payload'
    return b'PING\r\nQUIT\r\n','PONG'
def one(a) -> tuple[bool, float, str]:
    data, expect = payload(a.mode, a.path, a.sni)

    cmd = [
        a.openssl,
        "s_client",
        "-quiet",
        "-connect",
        f"{a.host}:{a.port}",
        "-servername",
        a.sni,
        "-tls1_3",
        "-groups",
        a.groups,
        "-CAfile",
        a.cafile,
        "-verify_return_error",
    ]

    if a.cert and a.key:
        cmd += ["-cert", a.cert, "-key", a.key]

    start = time.perf_counter()
    process = None
    selector = selectors.DefaultSelector()
    output = bytearray()
    error = ""

    try:
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )

        assert process.stdin is not None
        assert process.stdout is not None

        process.stdin.write(data)
        process.stdin.flush()

        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + a.timeout
        expected = expect.encode()

        while time.monotonic() < deadline:
            if expected in output:
                break

            remaining = deadline - time.monotonic()
            events = selector.select(timeout=min(0.1, remaining))

            if not events:
                if process.poll() is not None:
                    break
                continue

            for key, _ in events:
                chunk = key.fileobj.read(65536)
                if chunk:
                    output.extend(chunk)
                elif process.poll() is not None:
                    break

        success = expected in output

        if not success:
            if process.poll() is None:
                error = f"timed out after {a.timeout} seconds"
            else:
                error = f"s_client exited with code {process.returncode}"

    except (OSError, BrokenPipeError) as exc:
        success = False
        error = str(exc)

    finally:
        selector.close()

        if process is not None:
            if process.stdin is not None:
                try:
                    process.stdin.close()
                except OSError:
                    pass

            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)

    elapsed = (time.perf_counter() - start) * 1000
    text = output.decode("utf-8", "replace")

    if error:
        text = f"{text}\n{error}".strip()

    return success, elapsed, text

def main()->int:
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--mode',choices=['http','tcp','legacy'],required=True);p.add_argument('--host',required=True);p.add_argument('--port',type=int,required=True);p.add_argument('--sni',required=True);p.add_argument('--path',default='/service-info');p.add_argument('--groups',required=True);p.add_argument('--openssl',default='openssl');p.add_argument('--cafile',required=True);p.add_argument('--count',type=int,default=100);p.add_argument('--warmup',type=int,default=5);p.add_argument('--concurrency',type=int,default=5);p.add_argument('--timeout',type=int,default=15);p.add_argument('--cert',default='');p.add_argument('--key',default='');p.add_argument('--out',required=True);a=p.parse_args()
    for _ in range(a.warmup):one(a)
    start=time.perf_counter();times=[];fail=[]
    with ThreadPoolExecutor(max_workers=max(1,a.concurrency)) as pool:
        fs=[pool.submit(one,a) for _ in range(a.count)]
        for f in as_completed(fs):
            ok,e,text=f.result();times.append(e) if ok else fail.append('\n'.join(text.splitlines()[-8:]))
    wall=time.perf_counter()-start;result={'test':f'{a.mode}_roundtrip','target':f'{a.host}:{a.port}','sni':a.sni,'groups':a.groups,'attempts':a.count,'concurrency':a.concurrency,'successes':len(times),'failures':len(fail),'wall_time_s':round(wall,4),'throughput_per_s':round(a.count/wall,3) if wall else None,'mean_ms':round(statistics.mean(times),3) if times else None,'p50_ms':round(pct(times,.5),3) if times else None,'p95_ms':round(pct(times,.95),3) if times else None,'p99_ms':round(pct(times,.99),3) if times else None,'min_ms':round(min(times),3) if times else None,'max_ms':round(max(times),3) if times else None,'failure_samples':fail[:3]};Path(a.out).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2));return 0 if not fail else 1
if __name__=='__main__':raise SystemExit(main())
