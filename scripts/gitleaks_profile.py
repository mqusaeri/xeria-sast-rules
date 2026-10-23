#!/usr/bin/env python3
"""Generate the opt-in deep-text profile without altering the default config.

The deep profile re-enables SVG, JavaScript ecosystem lockfiles and node_modules.
Scope scans to the artifacts or first-party vendor paths that need inspection;
this does not enable archive traversal (use an explicit bounded CLI depth).
All credential patterns, entropy thresholds and value allowlists remain intact.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import tomllib

RASTER_AND_SVG = r'(?i)\.(?:bmp|gif|jpe?g|png|svg|tiff?)$'
RASTER_ONLY = r'(?i)\.(?:bmp|gif|jpe?g|png|tiff?)$'
REMOVE_PATHS = {
    r'(?:^|/)node_modules(?:/.*)?$',
    r'(?:^|/)(?:deno\.lock|npm-shrinkwrap\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$',
}

def deep_profile(source: str) -> str:
    original = tomllib.loads(source)
    paths = original['allowlist']['paths']
    required = REMOVE_PATHS | {RASTER_AND_SVG}
    missing = required - set(paths)
    if missing:
        raise ValueError('Base configuration changed: expected path entries are missing')
    updated_paths = [RASTER_ONLY if p == RASTER_AND_SVG else p for p in paths if p not in REMOVE_PATHS]
    block = re.search(r'(?ms)(^\[allowlist\]\s*\n.*?^paths\s*=\s*)\[.*?^\]', source)
    if not block:
        raise ValueError('Cannot locate the global allowlist paths array')
    replacement = block.group(1) + '[\n' + ''.join('    '+json.dumps(p)+',\n' for p in updated_paths) + ']'
    output = source[:block.start()] + replacement + source[block.end():]
    expected = dict(original)
    expected['allowlist'] = dict(original['allowlist'], paths=updated_paths)
    if tomllib.loads(output) != expected:
        raise ValueError('Generated profile unexpectedly changes another setting')
    return '# XERIA opt-in deep-text profile: SVG, JS lockfiles, node_modules included.\n' + output

def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=root/'packs/gitleaks/upstream/gitleaks.toml')
    parser.add_argument('--output',type=Path,default=root/'.build/profiles/gitleaks-deep.toml')
    args = parser.parse_args()
    output = deep_profile(args.source.read_text())
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(output)
    print(f'Generated {args.output}; 222 existing rules retained, only selected path exclusions changed.')

if __name__ == '__main__':
    main()
