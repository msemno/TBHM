"""F11: response status and browser URL resolution control redirect findings."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from phases import injections


class RedirectTests(unittest.TestCase):
    def test_status_and_destination_pairs(self):
        for status, location, count in [
            (200, 'https://evil.example.com/x', 0),
            (304, 'https://evil.example.com/x', 0),
            (302, 'evil.example.com/x', 0),
            (302, '/next?u=https://evil.example.com', 0),
            (302, 'https://evil.example.com.allowed.invalid/x', 0),
            (302, '//evil.example.com/x', 1),
            (307, 'https://evil.example.com/x', 1),
        ]:
            with self.subTest(status=status, location=location):
                found = []
                ctx = SimpleNamespace(targets=['allowed.invalid'], log=lambda *a: None,
                    save_finding=found.append)
                response = SimpleNamespace(status_code=status, headers={'Location': location},
                    url='https://allowed.invalid/account?next=/home')
                with patch.object(injections.requests, 'get', return_value=response):
                    injections._open_redirect(ctx, [response.url])
                self.assertEqual(len(found), count)

    def test_optional_base_keeps_existing_one_argument_calls(self):
        self.assertEqual(injections._redirect_host('evil.example.com/x'), '')
        self.assertEqual(injections._redirect_host('evil.example.com/x',
                         'https://allowed.invalid/account'), 'allowed.invalid')


if __name__ == '__main__': unittest.main(verbosity=2)
