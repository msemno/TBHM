import importlib.util
import json
from pathlib import Path
import threading
import unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('connection_doctor',ROOT/'scripts/tbhm_connection_doctor.py')
doctor=importlib.util.module_from_spec(spec);spec.loader.exec_module(doctor)


class DoctorTests(unittest.TestCase):
    def test_inventory_generation_embeddings_and_gpu_are_separate(self):
        class Handler(BaseHTTPRequestHandler):
            vram=0
            def respond(self,data):
                raw=json.dumps(data).encode();self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            def do_GET(self):
                self.respond({'models':[{'name':'fixture:latest'},{'name':'embed:latest'}]} if self.path=='/api/tags' else {'models':[{'name':'fixture:latest','size_vram':type(self).vram}]})
            def do_POST(self):
                self.rfile.read(int(self.headers.get('Content-Length',0)))
                self.respond({'response':'READY','done':True} if self.path=='/api/generate' else {'embedding':[1.,0.,.25]})
            def log_message(self,*unused):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            url=f'http://127.0.0.1:{server.server_port}'
            result=doctor.diagnose(url,model='fixture',embedding_model='embed')
            self.assertEqual(result['service']['status'],'RESPONSIVE')
            self.assertTrue(result['advisor_model_installed'])
            self.assertEqual(result['generation']['status'],'NOT_PROBED')
            self.assertEqual(result['loaded_model_placement'][0]['placement'],'CPU_OBSERVED')
            Handler.vram=4096
            result=doctor.diagnose(url,model='fixture',embedding_model='embed',probe=True)
            self.assertEqual(result['loaded_model_placement'][0]['placement'],'GPU_OBSERVED')
            self.assertTrue(result['generation']['ready_reply']);self.assertEqual(result['embedding']['dimension'],3)
            self.assertFalse(result['security_reasoning_accepted'])
        finally:server.shutdown();server.server_close();thread.join(2)

    def test_external_or_credentialed_endpoints_are_rejected(self):
        for endpoint in ['https://example.test','http://name:secret@127.0.0.1:11435','http://127.0.0.1:11435/other']:
            with self.subTest(endpoint=endpoint),self.assertRaises(ValueError):doctor.diagnose(endpoint,model='fixture',embedding_model='embed')


if __name__=='__main__':unittest.main(verbosity=2)
