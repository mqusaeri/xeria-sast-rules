"""Do not promote a boolean return heuristic into a proven access bypass."""
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1] / 'packs/xeria-rules/rules/security-boundaries'


class BoundaryClassificationTests(unittest.TestCase):
    def test_fail_open_heuristics_require_caller_review(self):
        for filename in ('pyjwt-fail-open.yaml', 'node-jwt-fail-open.yaml',
                         'stripe-webhook-fail-open.yaml'):
            rule = yaml.safe_load((ROOT / filename).read_text())['rules'][0]
            with self.subTest(rule=rule['id']):
                self.assertEqual(rule['severity'], 'WARNING')
                self.assertEqual(rule['metadata']['confidence'], 'MEDIUM')
                self.assertIn('audit', rule['metadata']['subcategory'])
                self.assertNotIn('vuln', rule['metadata']['subcategory'])
                self.assertTrue(rule['metadata']['limitations'])

    def test_explicit_trust_switches_are_review_findings(self):
        for filename in ('pytorch-unsafe-load.yaml', 'transformers-remote-code.yaml',
                         'pyjwt-audience-disabled.yaml', 'pyjwt-issuer-disabled.yaml',
                         'tarfile-fully-trusted.yaml'):
            rule = yaml.safe_load((ROOT / filename).read_text())['rules'][0]
            with self.subTest(rule=rule['id']):
                self.assertEqual(rule['severity'], 'WARNING')
                self.assertIn('audit', rule['metadata']['subcategory'])
                self.assertNotIn('vuln', rule['metadata']['subcategory'])
                self.assertTrue(rule['metadata']['limitations'])


if __name__ == '__main__':
    unittest.main()
