#!/usr/bin/env python3
"""Current source proof; historical evidence retains its original identity."""
from pathlib import Path
import subprocess,hashlib,json,sys
r=Path(__file__).resolve().parents[1]
paths=subprocess.check_output(['git','ls-files','-z','--cached','--others','--exclude-standard'],cwd=r).decode().split('\0')
h=hashlib.sha256()
for path in sorted(set(paths)-{''}):
    if path=='SHA256SUMS.txt' or path.startswith('docs/evidence/'):continue
    p=r/path
    if p.is_file():h.update(path.encode()+b'\0'+hashlib.sha256(p.read_bytes()).digest())
value='sha256:'+h.hexdigest()
if '--check' in sys.argv:
    index=sys.argv.index('--check');path=sys.argv[index+1] if len(sys.argv)>index+1 else 'docs/evidence/oss-roadmap.json'
    if value!=json.loads((r/path).read_text())['source_identity']:print('Source identity mismatch');sys.exit(1)
    print('Source identity verified')
else:print(value)
