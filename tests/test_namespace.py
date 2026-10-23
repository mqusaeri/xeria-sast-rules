import importlib.util
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
spec=importlib.util.spec_from_file_location('export_engine',ROOT/'scripts/export_engine_config.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class NamespaceTests(unittest.TestCase):
 def test_file_identity_prevents_native_directory_collisions(self):
  rules,index=module.collect()
  self.assertEqual(len(rules),1741)
  self.assertEqual(len(rules),len({r['id'] for r in rules}))
  ssrf=[r for r in index if r['sourceId']=='ssrf' and '/csharp/' in r['file']]
  self.assertEqual(len(ssrf),4)
  self.assertEqual(len({r['id'] for r in ssrf}),4)
if __name__=='__main__':unittest.main()
