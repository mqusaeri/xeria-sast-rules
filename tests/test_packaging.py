"""Fault-injection tests for release integrity and the default suppression policy."""
import importlib.util
import json
import sys
import stat
from pathlib import Path
import tempfile
import unittest
import zipfile
import yaml

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from rule_yaml import load as load_yaml
spec=importlib.util.spec_from_file_location('build_packs',ROOT/'scripts/build_packs.py')
build=importlib.util.module_from_spec(spec);spec.loader.exec_module(build)

class PackagingTests(unittest.TestCase):
 def fixture(self,extra=False,corrupt=False):
  data=b'rules: []\n';manifest={'files':[{'path':'rules/example.yaml','sha256':build.sha256(data),'size':len(data)}]}
  tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);p=Path(tmp.name)/'bundle.zip'
  with zipfile.ZipFile(p,'w') as z:
   z.writestr('manifest.json',json.dumps(manifest));z.writestr('rules/example.yaml',b'changed' if corrupt else data)
   if extra:z.writestr('unexpected.zip',b'unlisted')
  return p
 def test_rejects_unlisted_payload(self):
  with self.assertRaises(ValueError):build.verify_archive(self.fixture(extra=True))
 def test_rejects_tampered_payload(self):
  with self.assertRaisesRegex(ValueError,'Integrity'):build.verify_archive(self.fixture(corrupt=True))
 def test_valid_archive_passes(self):build.verify_archive(self.fixture())
 def test_deterministic_archive_bytes(self):
  files={'rules/r.yaml':b'rules: []\n'}
  self.assertEqual(build.archive_bytes(files,b'{}','2026-10-23'),build.archive_bytes(files,b'{}','2026-10-23'))
 def test_nested_payload_source_rejected(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp);(p/'nested.zip').write_bytes(b'zip')
   with self.assertRaisesRegex(ValueError,'Nested'):build.payloads(p)
 def test_global_suppression_is_empty_and_history_preserved(self):
  active=yaml.safe_load((ROOT/'packs/xeria-rules/suppress/aturan-paket-lain.yaml').read_text())
  self.assertEqual(active,{'suppress':[]})
  historical=json.loads((ROOT/'docs/suppression-review.json').read_text())
  self.assertEqual(len(historical['entries']),31)
  self.assertEqual(historical['status'],'historical-only-not-loaded')
 def test_duplicate_yaml_keys_rejected(self):
  for document in (
   'rules: [one]\nrules: []\n',
   'rule: {<<: {severity: WARNING, severity: ERROR}}',
   'rule: {<<: [{id: x}, {severity: WARNING, severity: ERROR}]}',
  ):
   with self.subTest(document=document), self.assertRaises(yaml.YAMLError):load_yaml(document)
 def test_yaml_aliases_and_explicit_merge_overrides_work(self):
  doc=load_yaml('base: &base {severity: WARNING}\nrule: {<<: *base, severity: ERROR}\n')
  self.assertEqual(doc['rule']['severity'],'ERROR')
  inline=load_yaml('rule: {<<: {severity: WARNING}, severity: ERROR}')
  self.assertEqual(inline['rule']['severity'],'ERROR')
  reused=load_yaml('base: &base {<<: {severity: WARNING}, severity: ERROR}\nfirst: {<<: *base}\nsecond: {<<: *base}')
  self.assertEqual(reused['first']['severity'],'ERROR')
  self.assertEqual(reused['second']['severity'],'ERROR')
 def test_traversal_symlink_duplicate_manifest_rejected(self):
  for kind in ('traversal','symlink','duplicate-manifest'):
   with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
    path=Path(tmp)/'bad.zip';name='../outside.yaml' if kind=='traversal' else 'rules/r.yaml';data=b'x'
    entry={'path':name,'sha256':build.sha256(data),'size':1}
    entries=[entry,entry] if kind=='duplicate-manifest' else [entry]
    with zipfile.ZipFile(path,'w') as z:
     z.writestr('manifest.json',json.dumps({'files':entries}))
     info=zipfile.ZipInfo(name)
     if kind=='symlink':info.external_attr=(stat.S_IFLNK|0o777)<<16
     z.writestr(info,data)
    with self.assertRaises(ValueError):build.verify_archive(path)
 def test_baseline_does_not_import_nested_jdbc_sanitizers(self):
  for filename in ['java-sql.yaml','java-desktop.yaml']:
   doc=yaml.safe_load((ROOT/'packs/xeria-rules/rules/java'/filename).read_text())
   for rule in doc['rules']:
    self.assertNotIn('ResultSet',json.dumps(rule.get('pattern-sanitizers',[])))

if __name__=='__main__':unittest.main()
