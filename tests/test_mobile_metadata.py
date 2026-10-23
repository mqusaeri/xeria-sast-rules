"""Risk classification is part of the mobile scanner's release contract."""
from pathlib import Path
import unittest
import yaml
ROOT=Path(__file__).resolve().parents[1]/'packs/mobsfscan-rules/rules/mobsfscan/rules/semgrep'

def rule(path,id):
    return next(r for r in yaml.safe_load((ROOT/path).read_text())['rules'] if r['id']==id)

class MobileClassificationTests(unittest.TestCase):
    def test_normal_ui_and_tls12_are_informational(self):
        for path,id in [('java/android/hidden_ui.yaml','android_hidden_ui'),('kotlin/android.yaml','android_kotlin_hiddenui'),('swift/network.yaml','ios_tls12_used')]:
            with self.subTest(rule=id):
                r=rule(path,id)
                self.assertEqual('INFO',r['severity'])
                self.assertIn('audit',r['metadata']['subcategory'])
                self.assertEqual('LOW',r['metadata']['confidence'])

    def test_sql_reports_sql_cwe(self):
        for path,id in [('java/injection/sqlite_injection.yaml','sqlite_injection'),('kotlin/injection.yaml','android_kotlin_sql_raw_query')]:
            with self.subTest(rule=id):
                self.assertEqual('cwe-89',rule(path,id)['metadata']['cwe'])

    def test_cbc_api_is_review_not_confirmed_oracle(self):
        for path,id in [('java/crypto/cbc_padding_oracle.yaml','cbc_padding_oracle'),('kotlin/crypto.yaml','cbc_kotlin_padding_oracle')]:
            with self.subTest(rule=id):
                r=rule(path,id)
                self.assertEqual('WARNING',r['severity'])
                self.assertEqual('LOW',r['metadata']['confidence'])
                self.assertIn('audit',r['metadata']['subcategory'])

if __name__=='__main__':unittest.main()
