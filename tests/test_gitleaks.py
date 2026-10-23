"""Gitleaks regression tests use synthetic data and never authenticate to providers."""
from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT/'packs/gitleaks/upstream/gitleaks.toml'
spec = importlib.util.spec_from_file_location('gitleaks_profile', ROOT/'scripts/gitleaks_profile.py')
profile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profile)

class ProfileTests(unittest.TestCase):
    def test_only_selected_paths_change(self):
        source = CONFIG.read_text()
        before = tomllib.loads(source)
        after = tomllib.loads(profile.deep_profile(source))
        self.assertEqual(before['rules'], after['rules'])
        self.assertEqual(222,len(after['rules']))
        self.assertEqual(before['allowlist']['regexes'],after['allowlist']['regexes'])
        self.assertEqual(before['allowlist']['stopwords'],after['allowlist']['stopwords'])
        self.assertNotIn(profile.RASTER_AND_SVG,after['allowlist']['paths'])
        self.assertIn(profile.RASTER_ONLY,after['allowlist']['paths'])
        self.assertTrue(profile.REMOVE_PATHS.isdisjoint(after['allowlist']['paths']))

    def test_changed_base_fails_closed(self):
        with self.assertRaises(ValueError):
            profile.deep_profile(CONFIG.read_text().replace('node_modules','vendor_modules'))

    def test_boolean_allowlist_has_grouped_anchors(self):
        config=tomllib.loads(CONFIG.read_text())
        self.assertIn(r'(?i)^(?:true|false|null)$', config['allowlist']['regexes'])
        self.assertNotIn(r'(?i)^true|false|null$', config['allowlist']['regexes'])

class GitleaksTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = os.environ.get('GITLEAKS_BIN') or shutil.which('gitleaks')
        if not cls.engine:
            raise unittest.SkipTest('Set GITLEAKS_BIN to a Gitleaks 8.30.1 binary to run engine tests')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='xeria-gitleaks-')
        self.root = Path(self.tmp.name)
        self.targets = self.root/'targets'
        self.targets.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, path, text):
        p=self.targets/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)

    def scan(self, config=CONFIG, depth=0):
        report=self.root/'report.json'
        cmd=[self.engine,'dir',str(self.targets),'--config',str(config),'--report-format','json','--report-path',str(report),'--redact=100','--no-banner','--max-archive-depth',str(depth)]
        result=subprocess.run(cmd,text=True,capture_output=True,timeout=45)
        self.assertIn(result.returncode,(0,1),msg='Gitleaks failed to scan; see engine stderr locally')
        findings=json.loads(report.read_text())
        self.assertEqual(result.returncode,1 if findings else 0)
        # Verify output redaction without ever printing synthetic secret values.
        self.assertTrue(all(not f.get('Secret') or set(f['Secret']) <= {'*'} or f['Secret']=='REDACTED' for f in findings))
        return [(f['RuleID'],f['File']) for f in findings]

    def test_pat_boolean_substrings_remain_findings(self):
        suffix='A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'
        tokens=[suffix,suffix[:10]+'false'+suffix[15:],suffix[:10]+'true'+suffix[14:],suffix[:10]+'null'+suffix[14:]]
        for i,token in enumerate(tokens):self.put(f'pat-{i}.txt','value = "ghp_'+token+'"\n')
        hits=self.scan()
        self.assertEqual(4,sum(rule=='github-pat' for rule,_ in hits))

    def test_airtable_does_not_require_provider_keyword(self):
        token='patAbCdEfGhIjKlMn.'+'a1b2c3d4'*8
        self.put('data.txt','data = "'+token+'"\n')
        self.assertIn('airtable-personnal-access-token',[rule for rule,_ in self.scan()])

    def test_boolean_literals_and_short_prefix_are_not_secrets(self):
        self.put('safe.txt','password = true\nsecret = false\napi_key = null\nvalue = "patAbCd"\n')
        self.assertEqual([],self.scan())

    def test_default_vs_deep_profile_paths(self):
        token='ghp_'+'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'
        for path in ['artifact.svg','package-lock.json','node_modules/first-party/config.txt']:
            self.put(path,'value = "'+token+'"\n')
        self.assertEqual([],self.scan())
        config=self.root/'deep.toml';config.write_text(profile.deep_profile(CONFIG.read_text()))
        self.assertEqual(3,sum(rule=='github-pat' for rule,_ in self.scan(config)))

    def test_archive_depth_is_explicit(self):
        token='ghp_'+'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'
        with zipfile.ZipFile(self.targets/'nested.zip','w',zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('inner.txt','value = "'+token+'"\n')
        self.assertEqual([],self.scan(depth=0))
        self.assertIn('github-pat',[rule for rule,_ in self.scan(depth=1)])

if __name__ == '__main__':
    unittest.main()
