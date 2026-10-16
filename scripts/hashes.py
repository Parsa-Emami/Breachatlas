#!/usr/bin/env python3
from pathlib import Path
import hashlib,sys
ROOT=Path(__file__).resolve().parents[1]
TARGET=ROOT/'SHA256SUMS.txt'
def selected():
    return sorted(p for p in ROOT.rglob('*') if p.is_file() and p!=TARGET and not any(x in p.relative_to(ROOT).parts for x in ['.git','node_modules','target','dist','.venv','__pycache__','test-results','playwright-report','vendor','build','.cache','.local-data']) and p.suffix!='.pyc')
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
if len(sys.argv)>1 and sys.argv[1]=='--write':
    TARGET.write_text(''.join(digest(p)+'  '+p.relative_to(ROOT).as_posix()+'\n' for p in selected()));print('Wrote SHA256SUMS.txt');sys.exit(0)
errors=[]; recorded=set()
for line in TARGET.read_text().splitlines():
    h,name=line.split('  ',1);p=ROOT/name
    if Path(name).is_absolute() or '..' in Path(name).parts: errors.append('Unsafe hash path');continue
    recorded.add(name)
    if not p.is_file() or digest(p)!=h:errors.append('Mismatch: '+name)
actual={p.relative_to(ROOT).as_posix() for p in selected()}
if recorded!=actual:errors.append('Manifest file set differs from actual file set')
print('Hash integrity passed' if not errors else '\n'.join(errors));sys.exit(1 if errors else 0)
