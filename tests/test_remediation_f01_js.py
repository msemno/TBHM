"""F01 caller extension: JS recovery must use the same no-follow writer."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from phases import js_analysis


class JsRecoveryBoundaryTests(unittest.TestCase):
    def test_preplanted_recovery_directory_link(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); out = root/'run'; (out/'recon').mkdir(parents=True)
            (out/'recon/javascript.txt').write_text('https://allowed.invalid/app.js\n')
            text = json.dumps({'sources': ['safe.js'], 'sourcesContent': ['safe']})
            digest = hashlib.sha256(text.encode()).hexdigest()
            recovered = out/'js_analysis/recovered_sources'; recovered.mkdir(parents=True)
            outside = root/'outside'; outside.mkdir(); (outside/'safe.js').write_text('original')
            (recovered/digest).symlink_to(outside, target_is_directory=True)
            def fetch(ctx, url, limiter, timeout):
                body = text if url.endswith('.map') else '//# sourceMappingURL=app.js.map'
                response = SimpleNamespace(status_code=200, content=body.encode(),
                    encoding='utf-8', headers={})
                return response, url, [url]
            class Files:
                def write_lines(self, p, lines): Path(p).write_text('\n'.join(lines))
            ctx = SimpleNamespace(output=out, args=SimpleNamespace(), targets=['allowed.invalid'],
                scope_excludes=[], profile={'active_probes': True, 'rate_limit': {'global_rps': 1}},
                runner=Files(), log=lambda *a: None, save_finding=lambda f: None)
            with patch.object(js_analysis, '_fetch', side_effect=fetch): js_analysis.run(ctx)
            self.assertEqual((outside/'safe.js').read_text(), 'original')
            self.assertFalse((outside/'safe.js.analysis.json').exists())
            index = json.loads((out/'js_analysis/JS_USEFULNESS_INDEX.json').read_text())
            sources = index['records'][0]['source_map_recovery'][0]['sources']
            self.assertEqual(sources[0]['classification'], 'recovery_write_blocked')


if __name__ == '__main__': unittest.main(verbosity=2)
