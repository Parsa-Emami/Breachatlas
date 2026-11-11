import { useEffect, useRef, useState } from 'react';

type TimelineEventItem = {
  event_identity: string;
  record_kind: 'observed_fact';
  is_source_evidence: boolean;
  evidence_id: string;
  source_line: number;
  event_type: string;
  summary: string;
  raw_timestamp: string;
  normalized_timestamp: string;
  timezone_offset: string;
  zone_hint?: string;
  zone_name?: string;
  status: 'explicit_offset' | 'iana_zone' | 'unknown_zone' | 'dst_ambiguous' | 'dst_nonexistent';
  candidate_utcs?: string[];
  candidate_offsets?: string[];
  confidence: number;
  raw_confidence?: number;
};

type AnalystNoteItem = {
  hypothesis_id: string;
  record_kind: 'analyst_hypothesis';
  is_source_evidence: false;
  author: string;
  rationale: string;
  statement: string;
  status: string;
  confidence?: number;
  ui_label?: string;
  supporting_event_ids?: string[];
};

type TimelineInspectSuccess = {
  schema_version: '1';
  status: 'valid';
  case_id: string;
  provider: string;
  overall_status: 'resolved' | 'unresolved_timezones' | 'empty';
  total_events: number;
  resolved_count: number;
  unresolved_count: number;
  truncated: boolean;
  total_notes: number;
  events: TimelineEventItem[];
  notes: AnalystNoteItem[];
};

type TimelineInspectError = {
  schema_version?: string;
  status: 'error';
  error: { code: string; field?: string };
};

type ViewState =
  | { kind: 'idle' }
  | { kind: 'busy' }
  | { kind: 'interrupted'; message: string }
  | { kind: 'error'; errorType: 'invalid' | 'unavailable'; message: string }
  | { kind: 'loaded'; data: TimelineInspectSuccess };

const maxSnapshotBytes = 256 * 1024;

const errorMessages: Record<string, { kind: 'invalid' | 'unavailable'; text: string }> = {
  engine_unavailable: { kind: 'unavailable', text: 'Local engine is unavailable. Start the unified supervisor and retry.' },
  unavailable_provider: { kind: 'unavailable', text: 'Requested timeline provider is unavailable in the open-source local profile.' },
  invalid_json: { kind: 'invalid', text: 'Invalid snapshot: choose a single well-formed UTF-8 JSON object.' },
  invalid_field: { kind: 'invalid', text: 'Invalid field in timeline snapshot.' },
  missing_field: { kind: 'invalid', text: 'Timeline snapshot is missing a required field.' },
  unsupported_version: { kind: 'invalid', text: 'Unsupported timeline snapshot schema version; expected version 1.' },
  promotion_forbidden: { kind: 'invalid', text: 'Analyst notes cannot be promoted to observed source evidence.' },
  payload_too_large: { kind: 'invalid', text: 'Timeline snapshot exceeds the 256 KiB request limit.' },
};

function formatStatusLabel(status: TimelineEventItem['status']): string {
  switch (status) {
    case 'explicit_offset':
      return 'Explicit offset';
    case 'iana_zone':
      return 'IANA zone';
    case 'unknown_zone':
      return 'Unknown zone';
    case 'dst_ambiguous':
      return 'DST ambiguous';
    case 'dst_nonexistent':
      return 'DST nonexistent';
  }
}

export function TimelinePage() {
  const [view, setView] = useState<ViewState>({ kind: 'idle' });
  const [mode, setMode] = useState<'timeline' | 'table'>('timeline');
  const [filterText, setFilterText] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const pending = useRef<AbortController | null>(null);

  useEffect(() => () => pending.current?.abort(), []);

  async function inspectFile(file: File | undefined) {
    if (!file) return;
    pending.current?.abort();
    setSelectedId(null);

    if (file.size > maxSnapshotBytes) {
      setView({ kind: 'error', errorType: 'invalid', message: errorMessages.payload_too_large.text });
      return;
    }

    const controller = new AbortController();
    pending.current = controller;
    setView({ kind: 'busy' });

    try {
      const response = await fetch('/api/v1/timeline/inspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: file,
        credentials: 'omit',
        redirect: 'error',
        signal: AbortSignal.any([controller.signal, AbortSignal.timeout(5000)]),
      });

      if (controller.signal.aborted) return;

      const payload = (await response.json()) as TimelineInspectSuccess | TimelineInspectError;
      if (controller.signal.aborted) return;

      if (response.ok && payload.status === 'valid') {
        setSelectedId(payload.events[0]?.event_identity ?? null);
        setView({ kind: 'loaded', data: payload });
        return;
      }

      if (payload.status === 'error') {
        const code = payload.error?.code ?? 'invalid_json';
        if (code === 'request_timeout') {
          setView({ kind: 'interrupted', message: 'Timeline inspection interrupted after timeout.' });
          return;
        }
        const entry = Object.hasOwn(errorMessages, code)
          ? errorMessages[code]
          : { kind: response.status >= 500 ? ('unavailable' as const) : ('invalid' as const), text: 'Timeline inspection rejected the snapshot.' };
        const fieldSuffix = payload.error?.field ? ` Field: ${payload.error.field}.` : '';
        setView({ kind: 'error', errorType: entry.kind, message: `${entry.text}${fieldSuffix}` });
        return;
      }

      setView({ kind: 'error', errorType: 'unavailable', message: 'Unexpected response from local timeline engine.' });
    } catch (reason) {
      if (controller.signal.aborted) return;
      if (reason instanceof DOMException && reason.name === 'TimeoutError') {
        setView({ kind: 'interrupted', message: 'Timeline inspection interrupted after request timeout.' });
        return;
      }
      setView({ kind: 'error', errorType: 'unavailable', message: errorMessages.engine_unavailable.text });
    } finally {
      if (pending.current === controller) {
        pending.current = null;
      }
    }
  }

  function cancelInspection() {
    pending.current?.abort();
    pending.current = null;
    setView({ kind: 'interrupted', message: 'Inspection interrupted (cancelled by user).' });
  }

  const needle = filterText.trim().toLowerCase();
  const visibleEvents =
    view.kind === 'loaded'
      ? view.data.events.filter(ev =>
          needle === ''
            ? true
            : `${ev.event_type} ${ev.summary} ${ev.raw_timestamp} ${ev.normalized_timestamp} ${ev.evidence_id}`
                .toLowerCase()
                .includes(needle)
        )
      : [];

  const selectedEvent =
    view.kind === 'loaded' ? view.data.events.find(ev => ev.event_identity === selectedId) ?? null : null;

  return (
    <section className="panel" aria-labelledby="timeline-page-heading">
      <div className="eyebrow">Timezone-aware timeline &amp; analyst notes</div>
      <h2 id="timeline-page-heading">Inspect timeline normalization &amp; hypotheses</h2>
      <p>
        Compare preserved raw timestamps alongside normalized UTC values and confidence scores, with an accessible table
        alternative and separated non-evidence analyst hypotheses.
      </p>

      <div className="evidence-controls">
        <label className="file-button">
          Choose timeline snapshot JSON
          <input
            aria-label="Choose timeline snapshot JSON"
            type="file"
            accept=".json,application/json"
            onChange={event => {
              void inspectFile(event.target.files?.[0]);
              event.target.value = '';
            }}
          />
        </label>
        {view.kind === 'busy' && (
          <button type="button" className="secondary-btn" onClick={cancelInspection}>
            Cancel inspection
          </button>
        )}
        {view.kind !== 'idle' && view.kind !== 'busy' && (
          <button
            type="button"
            className="secondary-btn"
            onClick={() => {
              pending.current?.abort();
              setSelectedId(null);
              setFilterText('');
              setView({ kind: 'idle' });
            }}
          >
            Clear timeline
          </button>
        )}
      </div>

      {view.kind === 'busy' && (
        <p className="muted" role="status">
          Normalizing timeline events and checking analyst note boundaries…
        </p>
      )}

      {view.kind === 'idle' && (
        <div className="notice" role="status">
          <span className="dot" />
          <span>Empty: load a timeline and notes JSON snapshot to inspect raw timestamps, normalized UTC time, and confidence.</span>
        </div>
      )}

      {view.kind === 'interrupted' && (
        <div className="notice alert-warning" role="alert">
          <span className="dot" />
          <span>{view.message}</span>
        </div>
      )}

      {view.kind === 'error' && (
        <div className="notice alert-danger" role="alert">
          <span className="dot" />
          <span>
            <strong>{view.errorType === 'unavailable' ? 'Unavailable engine/provider: ' : 'Invalid input: '}</strong>
            {view.message}
          </span>
        </div>
      )}

      {view.kind === 'loaded' && view.data.events.length === 0 && view.data.notes.length === 0 && (
        <div className="notice" role="status">
          <span className="dot" />
          <span>
            Empty timeline snapshot for <code>{view.data.case_id}</code>: 0 observed events and 0 analyst notes.
          </span>
        </div>
      )}

      {view.kind === 'loaded' && (view.data.events.length > 0 || view.data.notes.length > 0) && (
        <div className="timeline-results">
          {view.data.unresolved_count > 0 && (
            <div className="notice alert-warning" role="status">
              <span className="dot" />
              <span>
                {view.data.unresolved_count} event(s) retain unresolved/ambiguous timezone status without fabricating UTC.
              </span>
            </div>
          )}

          <div className="kpi-row" aria-label="Timeline summary">
            <div className="kpi-card">
              <span className="muted">Case ID</span>
              <strong className="mono-break">{view.data.case_id}</strong>
            </div>
            <div className="kpi-card">
              <span className="muted">Resolved UTC</span>
              <strong>{view.data.resolved_count}</strong>
            </div>
            <div className="kpi-card">
              <span className="muted">Unresolved / Ambiguous</span>
              <strong>{view.data.unresolved_count}</strong>
            </div>
            <div className="kpi-card">
              <span className="muted">Analyst Notes</span>
              <strong>{view.data.total_notes}</strong>
            </div>
          </div>

          <div className="filters timeline-toolbar">
            <label>
              Filter timeline events
              <input
                type="search"
                value={filterText}
                onChange={event => setFilterText(event.target.value)}
                placeholder="Event type, summary, or timestamp"
              />
            </label>
            <div className="view-switch" role="group" aria-label="Timeline view mode">
              <button
                type="button"
                className={mode === 'timeline' ? 'active-tab' : 'secondary-btn'}
                aria-pressed={mode === 'timeline'}
                onClick={() => setMode('timeline')}
              >
                Timeline view
              </button>
              <button
                type="button"
                className={mode === 'table' ? 'active-tab' : 'secondary-btn'}
                aria-pressed={mode === 'table'}
                onClick={() => setMode('table')}
              >
                Table view
              </button>
            </div>
          </div>

          {mode === 'timeline' ? (
            <ol className="timeline-list" aria-label="Observed timeline events">
              {visibleEvents.map(ev => {
                const isSelected = selectedEvent?.event_identity === ev.event_identity;
                return (
                  <li key={ev.event_identity} className={isSelected ? 'timeline-card selected-row' : 'timeline-card'}>
                    <div className="timeline-card-head">
                      <span className="task-id">Line {ev.source_line} · {ev.event_type}</span>
                      <span className={`state ${ev.normalized_timestamp ? 'verified' : 'warning'}`}>
                        {formatStatusLabel(ev.status)}
                      </span>
                    </div>
                    <p className="mono-break">{ev.summary}</p>
                    <dl className="detail-grid">
                      <div>
                        <dt>Raw timestamp</dt>
                        <dd><code className="mono-break">{ev.raw_timestamp}</code></dd>
                      </div>
                      <div>
                        <dt>Normalized time</dt>
                        <dd>
                          <code className="mono-break">
                            {ev.normalized_timestamp || `Unresolved (${formatStatusLabel(ev.status)})`}
                          </code>
                        </dd>
                      </div>
                      <div>
                        <dt>Offset / Zone</dt>
                        <dd><code className="mono-break">{ev.timezone_offset}</code></dd>
                      </div>
                      <div>
                        <dt>Confidence</dt>
                        <dd>
                          <code>{ev.confidence.toFixed(2)}</code>
                          {ev.raw_confidence !== undefined && (
                            <span className="muted"> (raw: {ev.raw_confidence.toFixed(2)})</span>
                          )}
                        </dd>
                      </div>
                    </dl>
                    <button
                      type="button"
                      className="secondary-btn"
                      aria-expanded={isSelected}
                      aria-label={`Inspect event line ${ev.source_line}`}
                      onClick={() => setSelectedId(ev.event_identity)}
                    >
                      {isSelected ? 'Inspecting' : 'Inspect event'}
                    </button>
                  </li>
                );
              })}
            </ol>
          ) : (
            <div className="table-scroll">
              <table className="evidence-table timeline-table" aria-label="Observed timeline table">
                <thead>
                  <tr>
                    <th scope="col">Line</th>
                    <th scope="col">Event &amp; Summary</th>
                    <th scope="col">Raw Timestamp</th>
                    <th scope="col">Normalized Time</th>
                    <th scope="col">Zone / Confidence</th>
                    <th scope="col">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleEvents.map(ev => {
                    const isSelected = selectedEvent?.event_identity === ev.event_identity;
                    return (
                      <tr key={ev.event_identity} className={isSelected ? 'selected-row' : undefined}>
                        <td data-label="Line"><code>{ev.source_line}</code></td>
                        <td data-label="Event & Summary" className="mono-break">
                          <strong>{ev.event_type}</strong>
                          <div>{ev.summary}</div>
                        </td>
                        <td data-label="Raw Timestamp"><code className="mono-break">{ev.raw_timestamp}</code></td>
                        <td data-label="Normalized Time">
                          <code className="mono-break">
                            {ev.normalized_timestamp || `Unresolved (${formatStatusLabel(ev.status)})`}
                          </code>
                        </td>
                        <td data-label="Zone / Confidence">
                          <span className={`state ${ev.normalized_timestamp ? 'verified' : 'warning'}`}>
                            {formatStatusLabel(ev.status)} ({ev.timezone_offset})
                          </span>
                          <div className="muted">
                            Confidence: <code>{ev.confidence.toFixed(2)}</code>
                            {ev.raw_confidence !== undefined ? ` (raw ${ev.raw_confidence.toFixed(2)})` : ''}
                          </div>
                        </td>
                        <td data-label="Action">
                          <button
                            type="button"
                            className="secondary-btn"
                            aria-expanded={isSelected}
                            aria-label={`Inspect row ${ev.source_line}`}
                            onClick={() => setSelectedId(ev.event_identity)}
                          >
                            {isSelected ? 'Viewing' : 'Inspect'}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {visibleEvents.length === 0 && (
            <p className="muted" role="status">
              No timeline events match the current filter.
            </p>
          )}

          {selectedEvent && (
            <section className="preview evidence-detail" aria-label="Selected timeline event">
              <h3>
                Selected observed event (line <code>{selectedEvent.source_line}</code>)
              </h3>
              <dl className="detail-grid">
                <div>
                  <dt>Event Identity</dt>
                  <dd><code className="mono-break">{selectedEvent.event_identity}</code></dd>
                </div>
                <div>
                  <dt>Source Evidence ID</dt>
                  <dd><code className="mono-break">{selectedEvent.evidence_id}</code></dd>
                </div>
                <div>
                  <dt>Raw Timestamp</dt>
                  <dd><code className="mono-break">{selectedEvent.raw_timestamp}</code></dd>
                </div>
                <div>
                  <dt>Normalized Time (UTC)</dt>
                  <dd>
                    <code className="mono-break">
                      {selectedEvent.normalized_timestamp || `Unresolved (${formatStatusLabel(selectedEvent.status)})`}
                    </code>
                  </dd>
                </div>
                <div>
                  <dt>Timezone Offset / Zone</dt>
                  <dd>
                    <code className="mono-break">
                      {selectedEvent.timezone_offset}
                      {selectedEvent.zone_name ? ` (${selectedEvent.zone_name})` : ''}
                    </code>
                  </dd>
                </div>
                <div>
                  <dt>Confidence Score</dt>
                  <dd>
                    <code>{selectedEvent.confidence.toFixed(2)}</code>
                    {selectedEvent.raw_confidence !== undefined && (
                      <span> · Raw confidence: <code>{selectedEvent.raw_confidence.toFixed(2)}</code></span>
                    )}
                  </dd>
                </div>
                {selectedEvent.candidate_utcs && selectedEvent.candidate_utcs.length > 0 && (
                  <div>
                    <dt>Candidate DST UTC Instants</dt>
                    <dd><code className="mono-break">{selectedEvent.candidate_utcs.join(' , ')}</code></dd>
                  </div>
                )}
              </dl>
            </section>
          )}

          <section className="preview notes-section" aria-label="Analyst hypotheses and notes">
            <div className="eyebrow">Separated epistemic layer · non-evidence</div>
            <h3>Analyst hypotheses &amp; notes ({view.data.notes.length})</h3>
            {view.data.notes.length === 0 ? (
              <p className="muted">No analyst hypotheses recorded for this snapshot.</p>
            ) : (
              <ul className="custody-list notes-list">
                {view.data.notes.map(note => (
                  <li key={note.hypothesis_id}>
                    <div className="timeline-card-head">
                      <code className="task-id">{note.hypothesis_id}</code>
                      <span className="state warning">Analyst hypothesis (non-evidence)</span>
                      {note.ui_label && <span className="state mono-break">Label: {note.ui_label}</span>}
                    </div>
                    <p className="mono-break"><strong>Statement:</strong> {note.statement}</p>
                    <p className="muted mono-break"><strong>Author:</strong> {note.author}</p>
                    <p className="muted mono-break"><strong>Rationale:</strong> {note.rationale}</p>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      )}
    </section>
  );
}
