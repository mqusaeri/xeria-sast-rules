#!/usr/bin/env python3
"""Export code rules with explicit stable IDs including pack, file and source ID.

Optional integration adapter: native engine path-prefixing can collapse rules from
separate files in the same directory. Original package IDs stay unchanged. Use
--no-rewrite-rule-ids with this config. This does not implement XERIA's proprietary
postprocessing, file requirements, suppression or finding deduplication.
"""
import argparse
import json
from pathlib import Path
import re
import sys
import yaml
from rule_yaml import load

ROOT=Path(__file__).resolve().parents[1]

def collect():
 rules=[];index=[];seen=set()
 for pack in sorted((ROOT/'packs').iterdir()):
  for file in sorted((pack/'rules').rglob('*')):
   if file.suffix not in ('.yaml','.yml'):continue
   relative=file.relative_to(pack).as_posix()
   for rule in load(file.read_text())['rules']:
    original=rule['id']
    stable=f'{pack.name}.{relative.rsplit(".",1)[0].replace("/",".")}.{original}'
    if not re.fullmatch(r'[A-Za-z0-9_.-]+',stable):raise ValueError(f'Unsupported ID characters: {stable}')
    if stable in seen:raise ValueError(f'Explicit ID collision: {stable}')
    seen.add(stable)
    rule['id']=stable
    rules.append(rule)
    index.append({'id':stable,'pack':pack.name,'file':relative,'sourceId':original})
 return rules,index

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,default=ROOT/'.build/engine/rules.yaml');args=p.parse_args()
 rules,index=collect();args.output.parent.mkdir(parents=True,exist_ok=True)
 args.output.write_text(yaml.safe_dump({'rules':rules},sort_keys=False,allow_unicode=True))
 args.output.with_suffix('.index.json').write_text(json.dumps(index,ensure_ascii=False,indent=2)+'\n')
 print(f'Exported {len(rules)} code rules with {len({r["id"] for r in rules})} unique IDs to {args.output}')

if __name__=='__main__':main()
