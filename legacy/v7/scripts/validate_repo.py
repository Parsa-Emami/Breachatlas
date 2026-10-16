#!/usr/bin/env python3
from pathlib import Path
import json,re,sys
root=Path(__file__).resolve().parents[1]
errors=[]
def err(x): errors.append(x)
required=['README.md','LICENSE','SECURITY.md','CONTRIBUTING.md','.env.example','.github/workflows/contracts.yml','contracts/openapi.v1.json','contracts/openapi.v1.yaml','contracts/asyncapi.v1.json','contracts/asyncapi.v1.yaml','contracts/config.schema.json','contracts/event-types.v1.json']
for x in required:
    if not (root/x).exists(): err(f'missing: {x}')
for p in root.rglob('*.json'):
    try: json.loads(p.read_text(encoding='utf-8'))
    except Exception as e: err(f'invalid JSON {p.relative_to(root)}: {e}')
if (root/'contracts/openapi.v1.json').exists():
    o=json.loads((root/'contracts/openapi.v1.json').read_text())
    if o.get('openapi')!='3.2.0': err('OpenAPI must be 3.2.0')
    seen=set()
    for path,item in o.get('paths',{}).items():
        declared={p.get('name') for p in item.get('parameters',[]) if p.get('in')=='path'}
        wanted=set(re.findall(r'\{([^}]+)\}',path))
        if wanted-declared: err(f'{path}: missing path params {sorted(wanted-declared)}')
        for method,op in item.items():
            if method not in {'get','post','put','patch','delete'}: continue
            oid=op.get('operationId')
            if not oid or oid in seen: err(f'{method.upper()} {path}: missing/duplicate operationId')
            seen.add(oid)
            if method in {'post','put','patch'} and 'requestBody' not in op: err(f'{method.upper()} {path}: requestBody missing')
            good=False
            for code,res in op.get('responses',{}).items():
                if str(code).startswith('2'):
                    if str(code)=='204' or res.get('content'): good=True
            if not good: err(f'{method.upper()} {path}: no typed success response')
if (root/'contracts/asyncapi.v1.json').exists():
    a=json.loads((root/'contracts/asyncapi.v1.json').read_text())
    if a.get('asyncapi')!='3.1.0': err('AsyncAPI must be 3.1.0')
    if not a.get('channels') or not a.get('operations'): err('AsyncAPI channels/operations missing')
if (root/'contracts/config.schema.json').exists():
    c=json.loads((root/'contracts/config.schema.json').read_text())
    if 'example.invalid' in json.dumps(c): err('fake schema domain remains')
wf=(root/'.github/workflows/contracts.yml')
if wf.exists():
    s=wf.read_text()
    m=re.search(r'actions/checkout@([0-9a-f]{40})',s)
    if not m: err('checkout action must be pinned to full 40-char SHA')
if errors:
    print('VALIDATION FAILED')
    for x in errors: print(' -',x)
    sys.exit(1)
print('VALIDATION PASSED')
print(f'Checked {len(list(root.rglob("*.json")))} JSON files and repository contract invariants.')
