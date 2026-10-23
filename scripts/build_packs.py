#!/usr/bin/env python3
"""Build deterministic rule bundles, or check existing bundles without changing them."""
import argparse
from collections import Counter
from datetime import date
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import sys
import stat
import tomllib
import zipfile
import yaml
from rule_yaml import load as load_yaml

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / 'release-config.json'

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def payloads(pack):
    result = {}
    for p in sorted(pack.rglob('*')):
        if p.is_symlink():raise ValueError(f'Symlinks are forbidden in release packs: {p}')
        if not p.is_file() or p == pack/'manifest.json':continue
        if p.name == 'manifest.json':raise ValueError(f'Nested manifest forbidden: {p}')
        relative = p.relative_to(pack).as_posix()
        if p.suffix.lower() == '.zip':raise ValueError(f'Nested archive forbidden: {p}')
        if any(part.startswith('.') for part in p.relative_to(pack).parts):raise ValueError(f'Hidden payload: {p}')
        result[relative] = p.read_bytes()
    if not result:raise ValueError(f'Empty pack: {pack}')
    return result

def validate_payloads(files, pack_id):
    rules = []
    effective_ids = set()
    for name,data in files.items():
        ext = Path(name).suffix
        if ext in ('.yaml','.yml'):
            doc = load_yaml(data)
            if name.startswith('rules/'):
                if not isinstance(doc,dict) or not isinstance(doc.get('rules'),list) or not doc['rules']:
                    raise ValueError(f'{pack_id}/{name}: missing rule definitions')
                for rule in doc['rules']:
                    for key in ('id','languages','message','severity'):
                        if not rule.get(key):raise ValueError(f'{pack_id}/{name}: missing {key}')
                    identity = (name,rule['id'])
                    if identity in effective_ids:raise ValueError(f'Duplicate rule ID within file: {identity}')
                    effective_ids.add(identity);rules.append(rule)
            elif name.startswith('suppress/'):
                if not isinstance(doc,dict) or not isinstance(doc.get('suppress'),list):
                    raise ValueError(f'{pack_id}/{name}: invalid suppression schema')
                for item in doc['suppress']:
                    if not item.get('id') or not item.get('reason'):raise ValueError(f'Invalid suppression: {item}')
        elif ext == '.toml':
            doc = tomllib.loads(data.decode())
            if name == 'upstream/gitleaks.toml':
                seen=set()
                for rule in doc['rules']:
                    if rule['id'] in seen:raise ValueError(f'Duplicate secret rule {rule["id"]}')
                    seen.add(rule['id']);rules.append(rule)
        elif ext == '.json':json.loads(data)
    if not rules:raise ValueError(f'No rules in {pack_id}')
    return rules

def make_manifest(pack_id, cfg, files, rules):
    pack = ROOT/'packs'/pack_id
    manifest = json.loads((pack/'manifest.json').read_text())
    manifest['version'] = cfg['packs'][pack_id]['version']
    manifest['createdAt'] = cfg['releaseDate']
    count = len(rules)
    if pack_id == 'xeria-rules':
        manifest['description'] = f'{count} aturan keamanan XERIA dengan pesan Bahasa Indonesia dan katalog cakupan teknologi; termasuk regression perbaikan audit 2026-10-23.'
        manifest['source']['revision'] = manifest['version']
        manifest['source']['notes'] = 'Rule custom XERIA. Regression positif/negatif disimpan di repository; pengujian terarah tidak menjamin coverage seluruh aplikasi. Tidak memakai sanitizer JDBC ResultSet tambahan dari paket tersarang 0.10.5.'
    elif pack_id == 'gitleaks':
        manifest['description'] = f'{count} aturan deteksi secret Gitleaks 8.30.1 dengan patch lokal XERIA; versi paket bukan versi binary engine.'
    elif pack_id == 'mobsfscan-rules':
        manifest['description'] = f'{count} aturan mobile Android Java/Kotlin dan iOS Swift, dengan perbaikan lokal XERIA dan regression tests.'
    else:
        manifest['description'] = f'{count} aturan keamanan Semgrep upstream dengan patch lokal XERIA; sumber dan lisensi upstream dipertahankan.'
    marker = ' [XERIA patch 2026-10-23:'
    if pack_id != 'xeria-rules':
        notes=manifest['source'].get('notes','').split(marker)[0]
        manifest['source']['notes'] = notes + marker + ' perbaikan deteksi/metadata/autofix; tidak identik dengan upstream. Lihat PATCHES.json dan tests/ di repository. Engine audit OpenGrep 1.29.0 / Gitleaks 8.30.1.]'
    manifest['files'] = [{'path':name,'sha256':sha256(data),'size':len(data)} for name,data in sorted(files.items())]
    return (json.dumps(manifest,ensure_ascii=False,indent=2)+'\n').encode()

def archive_bytes(files, manifest, release_date):
    d=date.fromisoformat(release_date)
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for name,data in sorted({**files,'manifest.json':manifest}.items()):
            info=zipfile.ZipInfo(name,(d.year,d.month,d.day,0,0,0))
            info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=0o100644<<16
            z.writestr(info,data,compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
    return output.getvalue()

def verify_archive(path):
    with zipfile.ZipFile(path) as z:
        names=z.namelist()
        if len(names)!=len(set(names)) or z.testzip() is not None:raise ValueError(f'Corrupt/duplicate ZIP: {path}')
        for item in z.infolist():
            path=PurePosixPath(item.filename)
            mode=(item.external_attr >> 16) & 0o170000
            if path.is_absolute() or '..' in path.parts or '\\' in item.filename or path.as_posix()!=item.filename or item.is_dir():
                raise ValueError(f'Unsafe archive path: {item.filename}')
            if mode not in (0,stat.S_IFREG):raise ValueError(f'Unsafe archive entry type: {item.filename}')
            if path.suffix.lower()=='.zip':raise ValueError(f'Nested archive forbidden: {item.filename}')
        manifest=json.loads(z.read('manifest.json'))
        listed=[entry['path'] for entry in manifest['files']]
        if len(listed)!=len(set(listed)) or 'manifest.json' in listed:raise ValueError('Duplicate/reserved manifest path')
        expected={'manifest.json'}|set(listed)
        if set(names)!=expected:raise ValueError(f'Unaccounted/missing payload in {path}')
        for entry in manifest['files']:
            data=z.read(entry['path'])
            if len(data)!=entry['size'] or sha256(data)!=entry['sha256']:raise ValueError(f'Integrity mismatch {path}:{entry["path"]}')
    return manifest

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--check',action='store_true');args=ap.parse_args()
    cfg=json.loads(CONFIG.read_text());entries=[]
    for pack_id,version in cfg['packs'].items():
        pack=ROOT/'packs'/pack_id;files=payloads(pack);rules=validate_payloads(files,pack_id)
        manifest=make_manifest(pack_id,cfg,files,rules)
        archive=archive_bytes(files,manifest,cfg['releaseDate'])
        name=f'{pack_id}-{version["version"]}.zip';dest=ROOT/name
        if args.check:
            if (pack/'manifest.json').read_bytes()!=manifest:raise ValueError(f'Manifest stale: {pack_id}; run build')
            if not dest.exists() or dest.read_bytes()!=archive:raise ValueError(f'Archive missing/stale/non-deterministic: {name}')
        else:
            (pack/'manifest.json').write_bytes(manifest);dest.write_bytes(archive)
        verify_archive(dest)
        entries.append({'id':pack_id,'version':version['version'],'file':name,'sha256':sha256(archive),'bytes':len(archive),'ruleCount':len(rules),'upstreamRevision':json.loads(manifest)['source']['revision']})
        print(f'{pack_id}: {len(rules)} rules; {len(files)} payloads; {name}')
    index=(json.dumps({'schema':1,'releaseDate':cfg['releaseDate'],'engines':cfg['engines'],'totalRules':sum(e['ruleCount'] for e in entries),'packages':entries},ensure_ascii=False,indent=2)+'\n').encode()
    path=ROOT/'release-index.json'
    if args.check:
        if not path.exists() or path.read_bytes()!=index:raise ValueError('Release index stale')
    else:path.write_bytes(index)
    return 0

if __name__=='__main__':
    try:sys.exit(main())
    except (ValueError,KeyError,yaml.YAMLError,zipfile.BadZipFile) as exc:
        print(str(exc),file=sys.stderr);sys.exit(1)
