"""SSRF candidate handling is fail-closed; opt-in experiments stay loopback."""
import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
from urllib.request import urlopen
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from phases import waf_evasion_ssrf


class SSRFFixture(BaseHTTPRequestHandler):
    hit_count = 0
    follow_callback = True
    def do_GET(self):
        self.__class__.hit_count += 1
        candidate = parse_qs(urlsplit(self.path).query).get('url', [''])[0]
        if self.follow_callback and candidate.startswith('http://127.0.0.1:'):
            try:
                with urlopen(candidate, timeout=2): pass
            except Exception:
                pass
        self.send_response(200)
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'ok')
    def log_message(self, *_): pass


class FakeStore:
    def __init__(self): self.observations = []
    def save_observation(self, **kw): self.observations.append(kw)


class SSRFSafetyTest(unittest.TestCase):
    def setUp(self):
        SSRFFixture.hit_count = 0
        SSRFFixture.follow_callback = True
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), SSRFFixture)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        (self.root / 'recon').mkdir()
        self.url = f'http://127.0.0.1:{self.server.server_port}/preview?url=abc'
        (self.root / 'recon' / 'crawl_urls.txt').write_text(self.url+'\n')
    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)
        self.tempdir.cleanup()
    def ctx(self, enabled=False, offline=False):
        class ReadLines:
            @staticmethod
            def read_lines(path): return path.read_text().splitlines()
        return SimpleNamespace(profile={'ssrf_local_oast_approved': enabled},
                               output=self.root, args=SimpleNamespace(offline=offline),
                               runner=ReadLines(), storage=FakeStore(),
                               log=lambda *_: None)
    def test_disabled_and_offline_generate_no_traffic(self):
        for enabled, offline in [(False, False), (True, True)]:
            with self.subTest(enabled=enabled, offline=offline):
                with patch('core.targets.target_scope_allows', return_value=True):
                    waf_evasion_ssrf.run(self.ctx(enabled, offline))
                self.assertEqual(SSRFFixture.hit_count, 0)
                data = json.loads((self.root/'evidence'/'ssrf_candidate_review.json').read_text())
                self.assertEqual(len(data['not_tested']), 1)
    def test_scope_denial_blocks_network(self):
        with patch('core.targets.target_scope_allows', return_value=False):
            waf_evasion_ssrf.run(self.ctx(True))
        self.assertEqual(SSRFFixture.hit_count, 0)
    def test_local_callback_correlated_as_observation_only(self):
        ctx = self.ctx(True)
        with patch('core.targets.target_scope_allows', return_value=True):
            waf_evasion_ssrf.run(ctx)
        self.assertEqual(SSRFFixture.hit_count, 2)
        self.assertEqual(len(ctx.storage.observations), 1)
        obs = ctx.storage.observations[0]['evidence']
        self.assertEqual(obs['callbacks_observed'], 2)
        self.assertEqual(obs['validation_state'], 'supported_candidate_requires_manual_review')
        self.assertEqual(len(list((self.root/'evidence'/'oast').glob('session-*.json'))), 1)
    def test_benign_local_endpoint_stays_inconclusive(self):
        SSRFFixture.follow_callback = False
        ctx = self.ctx(True)
        with patch('core.targets.target_scope_allows', return_value=True):
            waf_evasion_ssrf.run(ctx)
        self.assertEqual(ctx.storage.observations[0]['evidence']['callbacks_observed'], 0)
        self.assertEqual(ctx.storage.observations[0]['evidence']['validation_state'], 'inconclusive')


if __name__ == '__main__': unittest.main()
