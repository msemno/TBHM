"""Synthetic persistence and stream credentials; no real provider credentials."""
import json
import unittest
from core import evidence_redaction as er


class RedactionBoundaryTests(unittest.TestCase):
    def test_structured_credentials_and_url_keep_hashes(self):
        digest = 'a' * 64
        value = {'jwt': 'opaque.synthetic.jwt', 'nested': {'github_token': 'synthetic-pat'},
                 'artifact_sha256': digest, 'url': 'https://synthetic-userinfo@example.invalid/p?token=synthetic-query&ok=1'}
        result = er.redact_value(value)
        text = json.dumps(result)
        for secret in ('opaque.synthetic.jwt', 'synthetic-pat', 'synthetic-userinfo', 'synthetic-query'):
            self.assertNotIn(secret, text)
        self.assertEqual(result['artifact_sha256'], digest)
        self.assertIn('ok=1', result['url'])

    def test_actual_short_provider_flags_and_inline_flags(self):
        for cmd, secret in ((['chaos', '-key', 'synthetic-chaos'], 'synthetic-chaos'),
                            (['github-subdomains', '-t', 'synthetic-github'], 'synthetic-github'),
                            (['tool', '--jwt=synthetic-jwt'], 'synthetic-jwt')):
            self.assertNotIn(secret, ' '.join(er.safe_argv(cmd)))

    def test_every_split_of_known_secret_and_url(self):
        secret = 'synthetic-value-123456'
        raw = ('prefix https://example.invalid/?token=' + secret + ' suffix\n').encode()
        for split in range(len(raw) + 1):
            stream = er.StreamRedactor(secrets=[secret])
            output = stream.feed(raw[:split]) + stream.feed(raw[split:]) + stream.finish()
            self.assertNotIn(secret.encode(), output)
            self.assertIn(b'prefix', output)
        clean = er.StreamRedactor()
        self.assertEqual(clean.feed(b'clean\n') + clean.finish(), b'clean\n')

    def test_multiline_private_key_and_oversize_line_fail_closed(self):
        raw = b'-----BEGIN PRIVATE KEY-----\nSYNTHETIC-PRIVATE-MATERIAL\n-----END PRIVATE KEY-----\nclean\n'
        stream = er.StreamRedactor()
        result = b''.join(stream.feed(bytes([b])) for b in raw) + stream.finish()
        self.assertNotIn(b'SYNTHETIC-PRIVATE-MATERIAL', result)
        self.assertIn(b'clean', result)
        stream = er.StreamRedactor(max_line_bytes=64)
        result = stream.feed(b'x' * 100 + b'synthetic-secret\nclean\n') + stream.finish()
        self.assertNotIn(b'synthetic-secret', result)
        self.assertIn(b'clean', result)


if __name__ == '__main__':
    unittest.main(verbosity=2)
