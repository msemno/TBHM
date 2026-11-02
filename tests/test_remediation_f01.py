"""F01: hostile source-map paths must never create or replace outside files."""
import json
import tempfile
import unittest
from pathlib import Path
from core.sourcemaps import extract_from_map, reconstruct_dir


class SourceMapBoundaryTests(unittest.TestCase):
    def test_normalized_paths(self):
        hostile = [r'..\..\escape', '../escape', '/absolute', r'C:\escape',
                   r'\\host\share', 'src/../escape', 'src/\x00bad']
        for name in hostile:
            with self.subTest(name=name):
                self.assertEqual(extract_from_map(json.dumps({
                    'sources': [name], 'sourcesContent': ['sentinel']})), {})
        self.assertEqual(extract_from_map(json.dumps({
            'sources': ['webpack://src/safe.js'], 'sourcesContent': ['safe']})),
            {'src/safe.js': 'safe'})

    def test_traversal_and_symlink_preserve_outside(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); src = root/'src'; src.mkdir()
            out = root/'out'/'nested'; out.mkdir(parents=True)
            outside = root/'outside'; outside.mkdir()
            (outside/'keep.js').write_text('original')
            (out/'linked').symlink_to(outside, target_is_directory=True)
            (out/'hard.js').hardlink_to(outside/'keep.js')
            (src/'app.map').write_text(json.dumps({
                'sources': [r'..\..\escape', 'linked/keep.js', 'hard.js', 'src/safe.js'],
                'sourcesContent': ['bad', 'bad', 'bad', 'safe']}))
            self.assertEqual(reconstruct_dir(src, out), 1)
            self.assertFalse((root/'escape').exists())
            self.assertEqual((outside/'keep.js').read_text(), 'original')
            self.assertEqual((out/'src/safe.js').read_text(), 'safe')


if __name__ == '__main__':
    unittest.main(verbosity=2)
