#!/usr/bin/env python3
"""Offline planning consistency tool. Does not build/test/deploy an application."""
from pathlib import Path
import json,sys,re
ROOT=Path(__file__).resolve().parents[1]
def read(p): return json.loads((ROOT/p).read_text(encoding='utf-8'))
def validate():
    errors=[]
    try:
        plan=read('plans/roadmap.json'); progress=read('plans/progress.json'); req=read('plans/requirements.json'); product=read('product/project.json')
        rows=plan['commits']; states=progress['commits']; requirements=req['requirements']
        ids=[r['id'] for r in rows]; states_by_id={s['id']:s for s in states}; req_ids={r['id'] for r in requirements}
        if len(ids)!=40 or len(set(ids))!=40: errors.append('Expected forty unique commit intents')
        if [s['id'] for s in states]!=ids: errors.append('Progress IDs/order differ from roadmap')
        if plan['project']!=product['name'] or progress['project']!=product['name']: errors.append('Project identity mismatch')
        if len(req_ids)!=len(requirements): errors.append('Duplicate requirement ID')
        covered=set(); seen=set()
        for r in rows:
            if not re.match(r'^(feat|fix|docs|chore|test|ci|perf|build|refactor|style|revert)(\([a-z0-9-]+\))?: \S',r['title']): errors.append(r['id']+': invalid Conventional Commit title')
            if not set(r['depends_on'])<=seen: errors.append(r['id']+': forward or missing dependency')
            if not r['deliverables'] or not r['acceptance'] or not r['verification'] or not r['rollback']: errors.append(r['id']+': missing implementation detail')
            for f in r['deliverables']:
                if Path(f).is_absolute() or '..' in Path(f).parts: errors.append(r['id']+': unsafe path')
            covered.update(r['requirements']);seen.add(r['id'])
        if covered!=req_ids: errors.append('Requirement coverage mismatch')
        for requirement in requirements:
            matches=[r for r in rows if requirement['id'] in r['requirements']]
            if not matches or matches[0]['id']!=requirement['planned_commit']: errors.append('Requirement target mismatch')
        allowed={'planned','in_progress','blocked','verified'}
        for s in states:
            if s['status'] not in allowed: errors.append(s['id']+': invalid progress state')
            if s['status']=='verified':
                row=next(r for r in rows if r['id']==s['id'])
                if any(states_by_id[d]['status']!='verified' for d in row['depends_on']): errors.append(s['id']+': unmet verified dependency')
                if not s.get('source_identity') or not s.get('evidence'): errors.append(s['id']+': verified without source/evidence')
                for path in s.get('evidence',[]):
                    if Path(path).is_absolute() or '..' in Path(path).parts: errors.append(s['id']+': unsafe evidence path');continue
                    try:
                        e=read(path)
                        if e.get('planning_template') or e.get('passed') is not True or not e.get('commands') or not e.get('results'): errors.append(s['id']+': incomplete evidence')
                        if e.get('commit_id')!=s['id'] or e.get('source_identity')!=s['source_identity']: errors.append(s['id']+': evidence identity mismatch')
                    except Exception as ex: errors.append(s['id']+': unreadable evidence '+str(ex))
        if (ROOT/'plans/web-roadmap.json').is_file():
            web=read('plans/web-roadmap.json'); web_seen={}; allowed_web={'planned','in_progress','blocked','verified'}
            if web.get('project')!=product['name']: errors.append('Web project identity mismatch')
            if [w['id'] for w in web['tasks']]!=['W%02d'%i for i in range(1,9)]: errors.append('Expected ordered W01-W08 web tasks')
            for w in web['tasks']:
                if w.get('status') not in allowed_web: errors.append(w['id']+': invalid web progress')
                if not set(w['depends_on'])<=set(web_seen): errors.append(w['id']+': invalid web dependency')
                if w['status']=='verified':
                    if any(web_seen.get(d)!='verified' for d in w['depends_on']): errors.append(w['id']+': unmet web dependency')
                    if not w.get('evidence'): errors.append(w['id']+': missing web evidence')
                    for path in w.get('evidence',[]):
                        if Path(path).is_absolute() or '..' in Path(path).parts: errors.append(w['id']+': unsafe web evidence path');continue
                        try:
                            e=read(path)
                            if e.get('passed') is not True or not e.get('source_identity') or not e.get('commands') or w['id'] not in e.get('web_tasks_verified',[]): errors.append(w['id']+': incomplete web evidence')
                        except Exception as ex: errors.append(w['id']+': unreadable web evidence '+str(ex))
                web_seen[w['id']]=w['status']
        for f in ['START_HERE.md','AGENTS.md','docs/architecture/ADR-0001-lean-v0.md','docs/engineering/CONTINUATION.md','docs/release/RELEASE_POLICY.md','ops/DEPLOYMENT_PREREQUISITES.md','product/PRODUCT_REVIEW_FA.md','contracts/input.schema.json','contracts/result.schema.json']:
            if not (ROOT/f).is_file():errors.append('Missing '+f)
        for path in ROOT.rglob('*.json'):
            if 'legacy' in path.parts or any(x in path.parts for x in ['node_modules','target','.venv','dist','.git','test-results','playwright-report']):continue
            try:json.loads(path.read_text(encoding='utf-8'))
            except Exception as ex:errors.append(str(path.relative_to(ROOT))+': '+str(ex))
    except Exception as ex: errors.append(str(ex))
    if errors:
        print('PLAN VALIDATION FAILED');print('\n'.join(errors));return False
    print('PLAN VALIDATION PASSED — 40 intents, coverage and progress checked; no application runtime tests performed')
    return True
def main():
    cmd=sys.argv[1] if len(sys.argv)>1 else 'status'
    if cmd=='validate':return 0 if validate() else 1
    if cmd not in {'next','status'}:print('Usage: python3 scripts/plan.py [validate|status|next]');return 2
    if not validate():return 1
    plan=read('plans/roadmap.json'); progress=read('plans/progress.json');s={x['id']:x for x in progress['commits']}
    if cmd=='status':
        print(json.dumps({'project':plan['project'],'readiness':progress['readiness'],'verified':sum(x['status']=='verified' for x in s.values()),'total':len(s),'market_validation':progress['market_validation']},ensure_ascii=False,indent=2));return 0
    candidates=[r for r in plan['commits'] if s[r['id']]['status']!='verified' and all(s[x]['status']=='verified' for x in r['depends_on'])]
    if not candidates: print('No dependency-ready task; inspect progress and release evidence.');return 0
    r=candidates[0];print(json.dumps({'next':r,'progress':s[r['id']],'instruction':'Inspect real repository and evidence first. Implement only unmet criteria; record actual results.'},ensure_ascii=False,indent=2));return 0
if __name__=='__main__':sys.exit(main())
