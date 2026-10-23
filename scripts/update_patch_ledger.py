#!/usr/bin/env python3
"""Record actual rule/file changes against the pinned original repository bundles."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tomllib
import zipfile
import yaml
from rule_yaml import load as load_yaml

ROOT=Path(__file__).resolve().parents[1]

def digest(data):return hashlib.sha256(data).hexdigest()
def load_rules(files):
 result={}
 for name,data in files.items():
  if name.startswith('rules/') and name.endswith(('.yaml','.yml')):
   doc=load_yaml(data)
  elif name=='upstream/gitleaks.toml':doc=tomllib.loads(data.decode())
  else:continue
  for rule in doc['rules']:result[(name,rule['id'])]=rule
 return result

def main():
 cfg=json.loads((ROOT/'release-config.json').read_text());packs=[]
 for pack,versions in cfg['packs'].items():
  filename=f'{pack}-{versions["previousVersion"]}.zip'
  raw=subprocess.run(['git','show',f'{cfg["baselineCommit"]}:{filename}'],cwd=ROOT,capture_output=True,check=True).stdout
  with zipfile.ZipFile(io.BytesIO(raw)) as z:before={n:z.read(n) for n in z.namelist() if not n.endswith('/') and n!='manifest.json'}
  after={p.relative_to(ROOT/'packs'/pack).as_posix():p.read_bytes() for p in (ROOT/'packs'/pack).rglob('*') if p.is_file() and p.name!='manifest.json'}
  old=load_rules(before);new=load_rules(after);modified=[]
  for key in sorted(old.keys()&new.keys()):
   if old[key]!=new[key]:
    keys=[k for k in old[key].keys()|new[key].keys() if old[key].get(k)!=new[key].get(k)]
    modified.append({'file':key[0],'id':key[1],'fields':sorted(keys)})
  added=[{'file':p,'id':i} for p,i in sorted(new.keys()-old.keys())]
  removed=[{'file':p,'id':i} for p,i in sorted(old.keys()-new.keys())]
  changed_files=[{'path':n,'before_sha256':digest(before[n]) if n in before else None,'after_sha256':digest(after[n]) if n in after else None} for n in sorted(before.keys()|after.keys()) if before.get(n)!=after.get(n)]
  packs.append({'id':pack,'version':versions['version'],'baselineArchive':filename,'baselineArchiveSha256':digest(raw),'baselineRules':len(old),'currentRules':len(new),'modifiedRules':modified,'addedRules':added,'removedRules':removed,'changedFiles':changed_files})
 ledger={'schema':1,'baselineCommit':cfg['baselineCommit'],'releaseDate':cfg['releaseDate'],'summary':{'baselineRules':sum(p['baselineRules'] for p in packs),'currentRules':sum(p['currentRules'] for p in packs),'modifiedRules':sum(len(p['modifiedRules']) for p in packs),'addedRules':sum(len(p['addedRules']) for p in packs),'removedRules':sum(len(p['removedRules']) for p in packs)},'configurationChanges':['31 historical global suppressions moved to review documentation; active suppress list is empty.','Gitleaks global boolean/null allowlist anchoring fixed; default path exclusions retained.','Optional deep secret profile has explicit scope; archive depth remains a runtime option.'],'packages':packs}
 (ROOT/'PATCHES.json').write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps(ledger['summary'],indent=2))

if __name__=='__main__':main()
