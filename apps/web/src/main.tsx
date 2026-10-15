import { StrictMode, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import project from './generated/project.json';
import { validateRuntimeConfig } from './lib/runtime-config.mjs';
import { inspectJson } from './lib/preview.mjs';
import './styles.css';

type Runtime = { projectId: string; apiBasePath: string; engineEnabled: false; maxPreviewBytes: number };
type Route = 'workspace' | 'roadmap';
function route(): Route { return location.hash === '#roadmap' ? 'roadmap' : 'workspace'; }

function App({ config }: { config: Runtime }) {
  const [page, setPage] = useState<Route>(route);
  const [query, setQuery] = useState('');
  const [stage, setStage] = useState('all');
  const [preview, setPreview] = useState<{ name: string; bytes: number; fields: string[] } | null>(null);
  const [error, setError] = useState('');
  const busy = useRef(false);
  const generation = useRef(0);
  useEffect(() => {
    const onRoute = () => { setPage(route()); document.getElementById('content')?.focus(); };
    addEventListener('hashchange', onRoute);
    return () => removeEventListener('hashchange', onRoute);
  }, []);
  async function importFile(file: File | undefined) {
    if (!file || busy.current) return;
    const current = ++generation.current;
    setError(''); setPreview(null);
    if (file.size > config.maxPreviewBytes) { setError('File exceeds the preview limit.'); return; }
    busy.current = true;
    try {
      const result = inspectJson(await file.text(), config.maxPreviewBytes);
      if (current === generation.current) setPreview({ name: file.name, fields: result.fields, bytes: result.bytes });
    } catch (reason) {
      if (current === generation.current) setError(reason instanceof Error ? reason.message : 'Unable to read this file.');
    } finally { busy.current = false; }
  }
  const tasks = project.tasks.filter(task => (stage === 'all' || task.stage === stage) && `${task.id} ${task.title}`.toLowerCase().includes(query.toLowerCase()));
  return <div className="app" style={{ '--accent': project.accent } as React.CSSProperties}>
    <a className="skip" href="#content">Skip to content</a>
    <header><a className="brand" href="#workspace"><span className="mark" aria-hidden="true">{project.name.slice(0, 1)}</span>{project.name}</a><nav aria-label="Main"><a href="#workspace" aria-current={page === 'workspace' ? 'page' : undefined}>Workspace</a><a href="#roadmap" aria-current={page === 'roadmap' ? 'page' : undefined}>Roadmap</a></nav><span className="badge">Foundation · 0.0.1</span></header>
    <main id="content" tabIndex={-1}>
      <div className="eyebrow">{project.mode.replaceAll('-', ' ')} · browser workspace</div>
      <h1>{page === 'workspace' ? project.title : 'A clear path to release.'}</h1>
      <p className="intro">{page === 'workspace' ? project.description : 'Track the product plan separately from the web foundation. Each task includes an acceptance target.'}</p>
      {page === 'workspace' ? <>
        <section className="notice" aria-label="Availability"><span className="dot"/>The workspace is available. The {project.name} engine is awaiting integration; this release does not produce security results.</section>
        <div className="grid"><section className="panel"><div className="eyebrow">Local file preview</div><h2>Inspect a document</h2><p>Choose a JSON file to inspect its top-level fields. The file stays in memory in this tab and is not uploaded or saved.</p><label className="file-button">Choose JSON file<input aria-label="Choose JSON file" type="file" accept=".json,application/json" onChange={event => { void importFile(event.target.files?.[0]); event.target.value = ''; }}/></label><p className="muted">Maximum {Math.round(config.maxPreviewBytes / 1024)} KiB · JSON structure only</p>
          {error && <p role="alert" className="error">{error}</p>}
          {preview && <div className="preview" role="status"><h3>{preview.name}</h3><p>{preview.bytes} bytes · {preview.fields.length} top-level fields</p><ul>{preview.fields.slice(0, 30).map(field => <li key={field}><code>{field}</code></li>)}</ul><p className="muted">JSON structure checked. Domain validation requires the engine.</p><button onClick={() => { generation.current++; setPreview(null); }}>Clear preview</button></div>}
        </section><section className="panel"><div className="eyebrow">Product contract</div><h2>{project.documentType.replaceAll('-', ' ')}</h2><p>The engine will enforce these domain guarantees.</p><ul className="invariants">{project.invariants.map(invariant => <li key={invariant}>{invariant}</li>)}</ul><a className="text-link" href="#roadmap">Explore the implementation plan <span aria-hidden="true">→</span></a></section></div>
        <section className="panel"><div className="eyebrow">Web foundation</div><h2>Release preparation</h2><div className="milestones">{project.webTasks.map(task => <article key={task.id}><span className="task-id">{task.id}</span><h3>{task.title}</h3><span className={'state ' + task.status}>{task.status.replaceAll('_', ' ')}</span></article>)}</div></section>
      </> : <section className="panel"><div className="filters"><label>Search tasks<input value={query} onChange={event => setQuery(event.target.value)} placeholder="ID or task title" type="search"/></label><label>Stage<select value={stage} onChange={event => setStage(event.target.value)}><option value="all">All stages</option>{[...new Set(project.tasks.map(task => task.stage))].map(value => <option key={value} value={value}>{value}</option>)}</select></label></div><p aria-live="polite" className="muted">{tasks.length} of {project.tasks.length} product tasks</p><ol className="tasks">{tasks.map(task => <li key={task.id}><div className="task-line"><span className="task-id">{task.id}</span><h2>{task.title}</h2><span className="state">{task.status.replaceAll('_', ' ')}</span></div><p>{task.acceptance.join(' ')}</p><p className="muted">Stage: {task.stage} · Prerequisites: {task.dependsOn.join(', ') || 'None'}</p></li>)}</ol>{tasks.length === 0 && <p>No matching tasks.</p>}</section>}
    </main><footer><span>{project.name}</span><span>No telemetry · No automatic file uploads</span></footer>
  </div>;
}

const root = createRoot(document.getElementById('root')!);
fetch('/runtime-config.json', { cache: 'no-store', credentials: 'omit' }).then(async response => {
  if (!response.ok) throw new Error('Workspace configuration is unavailable.');
  return validateRuntimeConfig(await response.json(), project.slug) as Runtime;
}).then(config => root.render(<StrictMode><App config={config}/></StrictMode>)).catch(() => {
  root.render(<main className="startup-error"><h1>Workspace unavailable</h1><p>The workspace configuration could not be loaded. Reload the page or contact the operator.</p></main>);
});
