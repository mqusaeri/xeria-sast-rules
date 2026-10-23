#!/usr/bin/env python3
"""Restore upstream Semgrep fixture files from the checksum-pinned source snapshot.

Fetch only: old upstream expectations are retained unchanged for compatibility
review. They are not claimed to pass against locally patched rules.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path,PurePosixPath
import urllib.request
import zipfile

ROOT=Path(__file__).resolve().parents[1]
COMMIT='40b8c63f75dc7c22c8a77482d73bfb864b146f7e'
URL=f'https://codeload.github.com/semgrep/semgrep-rules/zip/{COMMIT}'
SHA='1f3ccc77580e08b07a596bc33570dcb6922be94ae19868de7295afa81c006c5e'

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--archive',type=Path);p.add_argument('--destination',type=Path,default=ROOT/'.build/upstream-fixtures');args=p.parse_args()
 if args.archive:data=args.archive.read_bytes()
 else:
  with urllib.request.urlopen(URL,timeout=60) as r:data=r.read()
 if hashlib.sha256(data).hexdigest()!=SHA:raise SystemExit('Upstream snapshot SHA-256 mismatch')
 args.destination.mkdir(parents=True,exist_ok=True)
 with zipfile.ZipFile(io.BytesIO(data)) as z:
  if z.testzip() is not None:raise SystemExit('Corrupt source snapshot')
  names=z.namelist();prefix=f'semgrep-rules-{COMMIT}/';selected={}
  for rule in (ROOT/'packs/semgrep-rules/rules').rglob('*'):
   if rule.suffix not in ('.yaml','.yml'):continue
   relative=rule.relative_to(ROOT/'packs/semgrep-rules/rules').as_posix()
   base=prefix+relative.rsplit('.',1)[0]+'.'
   for name in names:
    if not name.startswith(base) or name==prefix+relative or name.endswith('/'):continue
    content=z.read(name)
    if b'ruleid:' not in content and b'ok:' not in content and '.fixed.' not in name:continue
    rel=name[len(prefix):];path=PurePosixPath(rel)
    if path.is_absolute() or '..' in path.parts or '\\' in rel:raise ValueError('Unsafe snapshot filename')
    selected[rel]=content
  for rel,content in selected.items():
   path=args.destination/rel;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(content)
 index={'source':URL,'sha256':SHA,'fileCount':len(selected),'testsExecuted':False,'files':[{'path':name,'sha256':hashlib.sha256(content).hexdigest()} for name,content in sorted(selected.items())]}
 (args.destination/'fixture-index.json').write_text(json.dumps(index,indent=2)+'\n')
 print(f'Restored {len(selected)} upstream fixture files; these are not counted as executed tests.')

if __name__=='__main__':main()
