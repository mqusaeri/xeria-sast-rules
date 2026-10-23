#!/usr/bin/env python3
"""Load all code rules together and exercise three positive integration targets."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from export_engine_config import collect
import yaml

ROOT=Path(__file__).resolve().parents[1]

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--engine',default=os.environ.get('OPENGREP_BIN') or shutil.which('opengrep'));args=ap.parse_args()
 if not args.engine:ap.error('Set OPENGREP_BIN or --engine')
 engine=str(Path(args.engine).resolve());work=ROOT/'.build/smoke';targets=work/'targets';targets.mkdir(parents=True,exist_ok=True)
 samples={
  'probe.py':'import os\nfrom flask import request\ndef f():\n    os.system(request.args.get("cmd"))\n',
  'probe.js':'const cp = require("child_process");\nfunction f(req,res){ cp.exec(req.query.cmd); }\n',
  'probe.php':'<?php\nsystem($_GET["cmd"]);\n'}
 for name,code in samples.items():(targets/name).write_text(code)
 rules,index=collect();config=work/'rules.yaml';config.write_text(yaml.safe_dump({'rules':rules},sort_keys=False,allow_unicode=True))
 env=os.environ.copy();env.setdefault('XDG_CACHE_HOME',str(ROOT/'.build/cache'))
 for prefix in ('OPENGREP','SEMGREP'):
  env[prefix+'_LOG_FILE']=str(work/(prefix.lower()+'.log'));env[prefix+'_SETTINGS_FILE']=str(work/'settings.yaml')
 cmd=[engine,'scan','--config',str(config),'--no-rewrite-rule-ids','--no-git-ignore','--strict','--json','--disable-version-check','--jobs','2',str(targets)]
 try:p=subprocess.run(cmd,env=env,cwd=ROOT,capture_output=True,text=True,timeout=180)
 except subprocess.TimeoutExpired:raise SystemExit('Combined smoke scan timed out; no success claimed')
 (work/'result.json').write_text(p.stdout);(work/'stderr.txt').write_text(p.stderr)
 d=json.loads(p.stdout);wanted={str((targets/n).resolve()) for n in samples};scanned={str(Path(s).resolve()) for s in d.get('paths',{}).get('scanned',[])}
 found={str(Path(f['path']).resolve()) for f in d.get('results',[])}
 version=json.loads((ROOT/'release-config.json').read_text())['engines']['opengrep']
 ok=p.returncode==0 and not d.get('errors') and wanted<=scanned and wanted<=found and d.get('version')==version
 summary={'passed':ok,'engineVersion':d.get('version'),'rulesLoaded':len(rules),'targetsScanned':len(scanned),'findings':len(d.get('results',[])),'exit':p.returncode,'errors':d.get('errors',[]),'command':cmd,'limitation':'Only rules relevant to the three target languages execute; this is not full behavioral coverage or XERIA application integration.'}
 (work/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2));return not ok

if __name__=='__main__':sys.exit(main())
