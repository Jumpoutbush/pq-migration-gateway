from __future__ import annotations
import importlib.util,json,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);assert spec and spec.loader;m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

class RendererTests(unittest.TestCase):
    def test_http_and_stream_render(self):
        m=load('renderer',ROOT/'scripts/render_gateway_config.py');cfg=json.loads((ROOT/'config/services.json').read_text());text=m.render(cfg)
        self.assertIn('listen 8443 ssl;',text);self.assertIn('listen 8883 ssl;',text);self.assertIn('listen 127.0.0.1:18081;',text);self.assertIn('stub_status;',text);self.assertIn('proxy_pass mqtt-broker:1883;',text);self.assertIn('proxy_ssl_certificate /etc/pq-gateway/certs/upstream/client.crt;',text);self.assertIn('pq_stream_mqtt_tls_gateway',text);self.assertNotIn('$pq_application_protocol',text.split('stream {',1)[1])
    def test_injection_rejected(self):
        m=load('renderer_bad',ROOT/'scripts/render_gateway_config.py');cfg=json.loads((ROOT/'config/services.json').read_text());cfg['services'][0]['listen']['server_name']='bad;include';self.assertRaises(m.ConfigError,m.render,cfg)
    def test_duplicate_port_rejected(self):
        m=load('renderer_dup',ROOT/'scripts/render_gateway_config.py');cfg=json.loads((ROOT/'config/services.json').read_text());cfg['services'][1]['listen']['port']=cfg['services'][0]['listen']['port'];self.assertRaises(m.ConfigError,m.render,cfg)

class SourceTests(unittest.TestCase):
    def test_cmdb_import(self):
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/'cmdb.json';subprocess.run([sys.executable,str(ROOT/'scanner/cmdb_import.py'),'--input',str(ROOT/'config/cmdb/sample-assets.csv'),'--out-json',str(out)],check=True,stdout=subprocess.PIPE,env={'PYTHONPATH':str(ROOT/'scanner')});d=json.loads(out.read_text());self.assertEqual(d['summary']['targets'],3);self.assertEqual(d['targets'][0]['environment'],'test')
    def test_cidr_limit(self):
        sys.path.insert(0,str(ROOT/'scanner'));import target_sources
        with self.assertRaises(ValueError):target_sources.expand_cidrs(['10.0.0.0/24'],[443],10)

class ProtocolEncodingTests(unittest.TestCase):
    def test_mqtt_packets(self):
        m=load('mqtt_bench',ROOT/'scripts/bench_mqtt_openssl.py')
        self.assertEqual(m.encode_remaining(0), b'\x00')
        self.assertEqual(m.encode_remaining(128), b'\x80\x01')
        self.assertTrue(m.connect_packet('client').startswith(b'\x10'))
        self.assertTrue(m.subscribe_packet('topic').startswith(b'\x82'))
        self.assertIn(b'payload',m.publish_packet('topic',b'payload'))

class ManagerTests(unittest.TestCase):
    def test_persistent_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            td=Path(td);h=td/'http.log';s=td/'stream.log';h.write_text(json.dumps({'ts':'2026-07-10T00:00:00+00:00','service':'a','application_protocol':'http','remote_addr':'1.1.1.1','ssl_curve':'X25519MLKEM768'})+'\n');s.write_text(json.dumps({'ts':'2026-07-10T00:01:00+00:00','service':'b','application_protocol':'mqtt','remote_addr':'2.2.2.2','ssl_curve':'X25519'})+'\n');out=td/'report.json';subprocess.run([sys.executable,str(ROOT/'manager/fallback_report.py'),'--log',str(h),'--log',str(s),'--out',str(out)],check=True,stdout=subprocess.PIPE);d=json.loads(out.read_text());self.assertEqual(d['summary']['connections'],2);self.assertEqual(d['application_protocols']['mqtt']['classical_fallback'],1)
    def test_migration_verify_all_services(self):
        cfg=json.loads((ROOT/'config/services.json').read_text());sys.path.insert(0,str(ROOT));from gateway.model import compatibility_view;eps=[]
        for x in compatibility_view(cfg):
            groups=x['tls_groups'].split(':');eps.append({'sni':x['server_name'],'port':x['listen_port'],'supported_groups':groups})
        with tempfile.TemporaryDirectory() as td:
            td=Path(td);tls=td/'tls.json';out=td/'out.json';tls.write_text(json.dumps({'endpoints':eps}));subprocess.run([sys.executable,str(ROOT/'manager/verify_migration.py'),'--services',str(ROOT/'config/services.json'),'--tls',str(tls),'--out',str(out)],check=True,stdout=subprocess.PIPE);d=json.loads(out.read_text());self.assertEqual(d['summary']['services'],10);self.assertEqual(d['summary']['failed'],0)

if __name__=='__main__':unittest.main()
