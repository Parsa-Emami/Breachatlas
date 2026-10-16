import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, isAbsolute } from 'node:path';
const root = fileURLToPath(new URL('../', import.meta.url));
const read = async path => JSON.parse(await readFile(resolve(root, path), 'utf8'));
const safe = path => typeof path === 'string' && path.length > 0 && !isAbsolute(path) && !path.split(/[\\/]/).includes('..');
export function validate(plan, progress, requirements, gates) {
  const errors = []; const seen = new Set(); const covered = new Set();
  const states = new Map(progress.commits.map(task => [task.id, task]));
  const ids = Array.from({ length: 40 }, (_, i) => 'C' + String(i + 1).padStart(2, '0'));
  if (JSON.stringify(plan.commits.map(t => t.id)) !== JSON.stringify(ids)) errors.push('Expected ordered C01-C40 tasks.');
  if (JSON.stringify(plan.commits.map(t => t.id)) !== JSON.stringify(progress.commits.map(t => t.id))) errors.push('Progress order mismatch.');
  for (const task of plan.commits) {
    for (const field of ['implementation_steps', 'acceptance', 'deliverables', 'negative_cases', 'read_before', 'verification_commands']) if (!Array.isArray(task[field]) || !task[field].length) errors.push(task.id + ': missing ' + field);
    if (!task.resources?.hardware || !task.resources?.fixture || !task.resources?.upstream?.length || !task.resources?.licenses) errors.push(task.id + ': incomplete resources');
    if (!task.before || !task.after || !task.rollback || !task.stop_conditions?.length) errors.push(task.id + ': incomplete execution boundary');
    if (!/^(feat|fix|docs|chore|test|ci|perf|build|refactor|style|revert)(\([a-z0-9-]+\))?: \S/.test(task.title)) errors.push(task.id + ': invalid commit title');
    if (task.depends_on.some(id => !seen.has(id))) errors.push(task.id + ': forward dependency');
    for (const path of [...task.deliverables, ...task.read_before, task.task_file, task.evidence_path, task.resources?.fixture?.path]) if (!safe(path)) errors.push(task.id + ': unsafe path');
    for (const command of task.verification_commands) if (!command.command || typeof command.available_now !== 'boolean' || !command.expected) errors.push(task.id + ': incomplete command');
    for (const command of task.verification_commands) {
      const introduced = command.introduced_by;
      if (!['web-foundation', 'oss-roadmap'].includes(introduced) && (!ids.includes(introduced) || ids.indexOf(introduced) > ids.indexOf(task.id))) errors.push(task.id + ': command requires a future task');
    }
    for (const id of task.requirements) covered.add(id);
    const state = states.get(task.id);
    if (!state || !['planned', 'in_progress', 'blocked', 'verified'].includes(state.status)) errors.push(task.id + ': invalid progress');
    if (state?.status === 'verified' && (!state.source_identity || !state.evidence?.length || task.depends_on.some(id => states.get(id)?.status !== 'verified'))) errors.push(task.id + ': unproved completion');
    seen.add(task.id);
  }
  const wanted = new Set(requirements.requirements.map(r => r.id));
  if (wanted.size !== requirements.requirements.length || [...wanted].some(id => !covered.has(id)) || [...covered].some(id => !wanted.has(id))) errors.push('Requirement coverage mismatch');
  for (const req of requirements.requirements) if (plan.commits.find(task => task.requirements.includes(req.id))?.id !== req.planned_commit) errors.push(req.id + ': wrong requirement owner');
  if (gates.usable_at !== 'C30' || gates.oss_v1_at !== 'C40' || typeof gates.core_ready !== 'boolean') errors.push('Missing explicit release gates');
  if (gates.core_ready && progress.commits.slice(0, 30).some(t => t.status !== 'verified')) errors.push('Core readiness requires C01-C30 proof');
  return errors;
}
export async function load() {
  const [plan, progress, requirements, gates, web] = await Promise.all(['plans/roadmap.json', 'plans/progress.json', 'plans/requirements.json', 'plans/release-gates.json', 'plans/web-roadmap.json'].map(read));
  const errors = validate(plan, progress, requirements, gates);
  for (const task of plan.commits) {
    for (const path of [...task.read_before, task.task_file]) try { await readFile(resolve(root, path)); } catch { errors.push(task.id + ': missing ' + path); }
    const state = progress.commits.find(t => t.id === task.id);
    if (state.status === 'verified') for (const path of state.evidence) {
      if (!safe(path)) { errors.push(task.id + ': unsafe evidence'); continue; }
      try { const proof = await read(path); if (!proof.passed || proof.planning_template || proof.commit_id !== task.id || proof.source_identity !== state.source_identity || !proof.commands?.length || proof.commands.some(c => c.exit_code !== 0)) errors.push(task.id + ': invalid evidence'); } catch { errors.push(task.id + ': missing evidence'); }
    }
  }
  if (web.tasks.length !== 8 || web.project !== plan.project) errors.push('Web task identity mismatch');
  for (const task of web.tasks) if (task.status === 'verified') for (const path of task.evidence ?? []) {
    if (!safe(path)) { errors.push('Unsafe web evidence'); continue; }
    try { const proof = await read(path); if (!proof.passed || !proof.web_tasks_verified?.includes(task.id)) errors.push(task.id + ': invalid historical web proof'); } catch { errors.push(task.id + ': missing web proof'); }
  }
  return { plan, progress, gates, errors };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) try {
  const { plan, progress, gates, errors } = await load(); if (errors.length) throw new Error(errors.join('\n'));
  const command = process.argv[2] ?? 'status';
  if (command === 'validate') console.log('Validated 40 detailed tasks, resources, references and progress; no runtime capability inferred.');
  else if (command === 'status') console.log(JSON.stringify({ project: plan.project, readiness: progress.readiness, verified: progress.commits.filter(t => t.status === 'verified').length, total: 40, core_ready: gates.core_ready, usable_at: 'C30', oss_v1_at: 'C40' }, null, 2));
  else if (command === 'show' || command === 'next') {
    const states = new Map(progress.commits.map(t => [t.id, t]));
    const task = command === 'show' ? plan.commits.find(t => t.id === process.argv[3]) : plan.commits.find(t => states.get(t.id).status !== 'verified' && t.depends_on.every(id => states.get(id).status === 'verified'));
    if (!task) throw new Error('No matching/dependency-ready task; inspect blockers.');
    console.log(JSON.stringify({ task, progress: states.get(task.id) }, null, 2));
  } else if (command === 'release-check') {
    const missing = progress.commits.slice(0, 38).filter(t => t.status !== 'verified').map(t => t.id);
    if (missing.length || !gates.core_ready) { console.error('NOT RELEASE READY: actual C01-C38 and complete clone-to-value evidence required. Missing: ' + missing.join(', ')); process.exitCode = 2; }
  } else throw new Error('Usage: npm run plan -- [validate|status|next|show C07|release-check]');
} catch (error) { console.error(error.message); process.exitCode = 1; }
