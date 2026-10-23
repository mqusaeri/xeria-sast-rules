"""Guard against vacuous fixtures that let a match-nothing rule pass its suite."""
from collections import defaultdict
import json
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
class RegressionCoverageTests(unittest.TestCase):
 def test_every_selected_rule_has_positive_assertion(self):
  selected=set();positive=set();names=[]
  for p in (ROOT/'tests/regression').glob('*.json'):
   for case in json.loads(p.read_text()):
    names.append(case['name'])
    for rid in case['rule_ids']:selected.add((case['pack'],case['rule_file'],rid))
    for expected in case['expect']:positive.add((case['pack'],case['rule_file'],expected['id']))
  self.assertTrue(selected)
  self.assertEqual(len(names),len(set(names)))
  self.assertFalse(selected-positive,sorted(selected-positive))
if __name__=='__main__':unittest.main()
