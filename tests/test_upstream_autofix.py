"""Prevent automatic rewrites that previously broke authentication/crypto APIs."""
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1] / 'packs' / 'semgrep-rules' / 'rules'

class UpstreamAutofixSafetyTests(unittest.TestCase):
    def test_context_dependent_security_changes_require_review(self):
        paths = [
            'python/django/security/audit/unvalidated-password.yaml',
            'python/cryptography/security/insecure-cipher-mode-ecb.yaml',
            'go/lang/security/audit/crypto/math_random.yaml',
        ]
        for relative in paths:
            with self.subTest(rule=relative):
                rule = yaml.safe_load((ROOT / relative).read_text())['rules'][0]
                self.assertNotIn('fix', rule)
                self.assertNotIn('fix-regex', rule)

if __name__ == '__main__':
    unittest.main()
