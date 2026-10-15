import { readFile, mkdir, writeFile } from 'node:fs/promises';
const read = async path => JSON.parse(await readFile(new URL('../' + path, import.meta.url), 'utf8'));
const product = await read('product/project.json');
const roadmap = await read('plans/roadmap.json');
const progress = await read('plans/progress.json');
const web = await read('plans/web-roadmap.json');
const brand = await read('ops/web/brand.json');
const output = {
  name: product.name,
  slug: brand.slug,
  title: brand.title,
  description: brand.description,
  accent: brand.accent,
  mode: product.web_application.deployment_profile,
  documentType: product.domain.primary,
  invariants: product.domain.invariants,
  fields: product.domain.fields,
  tasks: roadmap.commits.map(task => ({
    id: task.id, title: task.title, stage: task.stage,
    status: progress.commits.find(item => item.id === task.id)?.status ?? 'planned',
    acceptance: task.acceptance, dependsOn: task.depends_on,
  })),
  webTasks: web.tasks.map(({ id, title, status, acceptance }) => ({ id, title, status, acceptance })),
};
const directory = new URL('../apps/web/src/generated/', import.meta.url);
await mkdir(directory, { recursive: true });
await writeFile(new URL('project.json', directory), JSON.stringify(output, null, 2) + '\n');
