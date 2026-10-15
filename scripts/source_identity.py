#!/usr/bin/env python3
"""Reproduce the delivered source identity without evidence/checksum self-reference."""
from pathlib import Path
import subprocess, hashlib, json, sys
root=Path(__file__).resolve().parents[1]
excluded={'SHA256SUMS.txt','docs/evidence/web-foundation.json'}
paths=subprocess.check_output(['git','ls-files','-z','--cached','--others','--exclude-standard'],cwd=root).decode().split('\0')
h=hashlib.sha256()
for path in sorted(set(paths)-excluded-{''}):
    p=root/path
    if p.is_file(): h.update(path.encode()+b'\0'+hashlib.sha256(p.read_bytes()).digest())
value='sha256:'+h.hexdigest()
if '--check' in sys.argv:
    expected=json.loads((root/'docs/evidence/web-foundation.json').read_text())['source_identity']
    if value!=expected: print('Source identity mismatch');sys.exit(1)
    print('Source identity verified')
else: print(value)
