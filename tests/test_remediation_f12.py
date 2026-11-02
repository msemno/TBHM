"""F12: advisory authorization uses the parser's actual destination."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from core.ai_plane.sanitizer import controlled_state


class AuthorizationSnapshotTests(unittest.TestCase):
    def test_real_flag_pair(self):
        with tempfile.TemporaryDirectory() as td:
            for authorized in [False, True]:
                ctx = SimpleNamespace(args=SimpleNamespace(yes_i_am_authorized=authorized),
                    output=Path(td), targets=[], profile={},
                    storage=SimpleNamespace(all_findings=lambda: []))
                self.assertEqual(controlled_state(ctx)['authorization']['confirmed'], authorized)


if __name__ == '__main__': unittest.main(verbosity=2)
