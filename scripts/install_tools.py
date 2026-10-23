#!/usr/bin/env python3
"""Install pinned audit engines for Linux x86_64 with TLS and SHA-256 checks."""
import argparse
import hashlib
import io
import os
from pathlib import Path
import platform
import tarfile
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
ASSETS={
 'opengrep':('https://github.com/opengrep/opengrep/releases/download/v1.29.0/opengrep_manylinux_x86','3365ef49d04893e01338d85d9bbd49b2bd5261ad4c9c0df0a6a0f8d44232ae13'),
 'gitleaks':('https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz','551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb')}

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--destination',type=Path,default=ROOT/'.build/tools');args=ap.parse_args()
 if platform.system()!='Linux' or platform.machine() not in ('x86_64','AMD64'):
  raise SystemExit('Pinned installer supports Linux x86_64 only; supply verified OPENGREP_BIN and GITLEAKS_BIN on other platforms.')
 args.destination.mkdir(parents=True,exist_ok=True)
 for name,(url,expected) in ASSETS.items():
  cache=args.destination/(name+'.download')
  data=cache.read_bytes() if cache.exists() else b''
  if hashlib.sha256(data).hexdigest()!=expected:
   with urllib.request.urlopen(url,timeout=90) as response:data=response.read()
   if hashlib.sha256(data).hexdigest()!=expected:raise SystemExit(f'{name}: download SHA-256 mismatch')
   cache.write_bytes(data)
  executable=data
  if name=='gitleaks':
   with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
    member=archive.getmember('gitleaks')
    if not member.isfile():raise SystemExit('Expected regular gitleaks executable')
    executable=archive.extractfile(member).read()
  dest=args.destination/name;tmp=args.destination/(name+'.new');tmp.write_bytes(executable);tmp.chmod(0o755);os.replace(tmp,dest)
  print(f'{name}: verified and installed at {dest}')

if __name__=='__main__':main()
