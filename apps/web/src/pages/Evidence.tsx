import { useEffect, useRef, useState } from 'react';

type CustodyEvent = {
  schema_version: string;
  event_id: string;
  case_id: string;
  evidence_id: string;
  sequence: number;
  event_type: string;
  actor: string;
  timestamp: string;
  reason: string;
  prev_hash: string;
  event_digest: string;
  custody_root: string;
};

type EvidenceInspectItem = {
  evidence_id: string;
  filename: string;
  media_type: string;
  size_bytes: number;
  seal_status: 'sealed' | 'incomplete_seal';
  verification_status: 'verified' | 'verification_failed' | 'pending_seal';
  custody_status: 'custody_verified' | 'custody_failed' | 'custody_missing';
  status_reason: string;
  expected_sha256: string;
  actual_sha256: string;
  custody_root: string;
  computed_root?: string;
  hold_active: boolean;
  hold_reason?: string;
  custody_events?: CustodyEvent[];
};

type EvidenceInspectSuccess = {
  schema_version: '1';
  status: 'valid';
  case_id: string;
  provider: string;
  overall_status: 'verified' | 'incomplete_seal' | 'verification_failed' | 'empty';
  total_items: number;
  verified_count: number;
  incomplete_count: number;
  failed_count: number;
  items: EvidenceInspectItem[];
};

type EvidenceInspectError = {
  schema_version?: string;
  status: 'error';
  error: { code: string; field?: string };
};

type ViewState =
  | { kind: 'idle' }
  | { kind: 'busy' }
  | { kind: 'interrupted'; message: string }
  | { kind: 'error'; errorType: 'invalid' | 'unavailable'; message: string }
  | { kind: 'loaded'; data: EvidenceInspectSuccess };

const maxSnapshotBytes = 256 * 1024;

const errorMessages: Record<string, { kind: 'invalid' | 'unavailable'; text: string }> = {
  engine_unavailable: { kind: 'unavailable', text: 'Local engine is unavailable. Start the unified supervisor and retry.' },
  unavailable_provider: { kind: 'unavailable', text: 'Requested evidence provider is unavailable in the open-source local profile.' },
  invalid_json: { kind: 'invalid', text: 'Invalid snapshot: choose a single well-formed UTF-8 JSON object.' },
  invalid_field: { kind: 'invalid', text: 'Invalid field in evidence snapshot.' },
  missing_field: { kind: 'invalid', text: 'Evidence snapshot is missing a required field.' },
  unsupported_version: { kind: 'invalid', text: 'Unsupported evidence snapshot schema version; expected version 1.' },
  payload_too_large: { kind: 'invalid', text: 'Evidence snapshot exceeds the 256 KiB request limit.' },
  request_timeout: { kind: 'interrupted', text: 'Evidence inspection timed out.' } as never,
};

function labelForSeal(status: EvidenceInspectItem['seal_status']): string {
  return status === 'sealed' ? 'Sealed' : 'Incomplete seal';
}

function labelForVerification(status: EvidenceInspectItem['verification_status']): string {
  if (status === 'verified') return 'Verified';
  if (status === 'verification_failed') return 'Failed verification';
  return 'Pending seal';
}

function labelForCustody(status: EvidenceInspectItem['custody_status']): string {
  if (status === 'custody_verified') return 'Custody verified';
  if (status === 'custody_failed') return 'Custody failed';
  return 'Custody missing';
}

export function EvidencePage() {
  const [view, setView] = useState<ViewState>({ kind: 'idle' });
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
      const response = await fetch('/api/v1/evidence-integrity/inspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: file,
        credentials: 'omit',
        redirect: 'error',
        signal: AbortSignal.any([controller.signal, AbortSignal.timeout(5000)]),
      });

      if (controller.signal.aborted) return;

      const payload = (await response.json()) as EvidenceInspectSuccess | EvidenceInspectError;
      if (controller.signal.aborted) return;

      if (response.ok && payload.status === 'valid') {
        setSelectedId(payload.items[0]?.evidence_id ?? null);
        setView({ kind: 'loaded', data: payload });
        return;
      }

      if (payload.status === 'error') {
        const code = payload.error?.code ?? 'invalid_json';
        if (code === 'request_timeout') {
          setView({ kind: 'interrupted', message: 'Evidence inspection interrupted after timeout.' });
          return;
        }
        const entry = Object.hasOwn(errorMessages, code)
          ? errorMessages[code]
          : { kind: response.status >= 500 ? ('unavailable' as const) : ('invalid' as const), text: 'Evidence inspection rejected the snapshot.' };
        const fieldSuffix = payload.error?.field ? ` Field: ${payload.error.field}.` : '';
        setView({ kind: 'error', errorType: entry.kind, message: `${entry.text}${fieldSuffix}` });
        return;
      }

      setView({ kind: 'error', errorType: 'unavailable', message: 'Unexpected response from local evidence engine.' });
    } catch (reason) {
      if (controller.signal.aborted) return;
      if (reason instanceof DOMException && reason.name === 'TimeoutError') {
        setView({ kind: 'interrupted', message: 'Evidence inspection interrupted after request timeout.' });
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

  const selectedItem =
    view.kind === 'loaded' ? view.data.items.find(item => item.evidence_id === selectedId) ?? null : null;

  return (
    <section className="panel" aria-labelledby="evidence-page-heading">
      <div className="eyebrow">Evidence integrity &amp; custody</div>
      <h2 id="evidence-page-heading">Inspect case evidence integrity</h2>
      <p>
        Verify sealed SHA-256 digests, seal completeness, hold locks, and custody hash chains through the local engine.
        Source bytes remain read-only.
      </p>

      <div className="evidence-controls">
        <label className="file-button">
          Choose evidence snapshot JSON
          <input
            aria-label="Choose evidence snapshot JSON"
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
              setView({ kind: 'idle' });
            }}
          >
            Clear results
          </button>
        )}
      </div>

      {view.kind === 'busy' && (
        <p className="muted" role="status">
          Verifying sealed evidence and custody chain with local engine…
        </p>
      )}

      {view.kind === 'idle' && (
        <div className="notice" role="status">
          <span className="dot" />
          <span>Empty: load a case evidence JSON snapshot to inspect seal completeness, digest verification, and custody records.</span>
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

      {view.kind === 'loaded' && view.data.items.length === 0 && (
        <div className="notice" role="status">
          <span className="dot" />
          <span>
            Empty case snapshot for <code>{view.data.case_id}</code>: 0 evidence items recorded.
          </span>
        </div>
      )}

      {view.kind === 'loaded' && view.data.items.length > 0 && (
        <div className="evidence-results">
          {view.data.failed_count > 0 && (
            <div className="notice alert-danger" role="alert">
              <span className="dot" />
              <span>
                Verification failed on {view.data.failed_count} item(s). Review digest and custody anomalies before trusting case artifacts.
              </span>
            </div>
          )}
          {view.data.incomplete_count > 0 && (
            <div className="notice alert-warning" role="status">
              <span className="dot" />
              <span>
                Incomplete seal on {view.data.incomplete_count} item(s). Finalize sealing and custody root before export or timeline binding.
              </span>
            </div>
          )}

          <div className="kpi-row" aria-label="Case evidence summary">
            <div className="kpi-card">
              <span className="muted">Case ID</span>
              <strong className="mono-break">{view.data.case_id}</strong>
            </div>
            <div className="kpi-card">
              <span className="muted">Verified</span>
              <strong>{view.data.verified_count}</strong>
            </div>
            <div className="kpi-card">
              <span className="muted">Incomplete seal</span>
              <strong>{view.data.incomplete_count}</strong>
            </div>
            <div className="kpi-card">
              <span className="muted">Failed verification</span>
              <strong>{view.data.failed_count}</strong>
            </div>
          </div>

          <div className="table-scroll">
            <table className="evidence-table" aria-label="Case evidence integrity and custody">
              <thead>
                <tr>
                  <th scope="col">Evidence ID</th>
                  <th scope="col">File / Source Label</th>
                  <th scope="col">Seal Status</th>
                  <th scope="col">Verification</th>
                  <th scope="col">Custody &amp; Hold</th>
                  <th scope="col">Details</th>
                </tr>
              </thead>
              <tbody>
                {view.data.items.map(item => {
                  const isSelected = selectedItem?.evidence_id === item.evidence_id;
                  return (
                    <tr key={item.evidence_id} className={isSelected ? 'selected-row' : undefined}>
                      <td data-label="Evidence ID">
                        <code className="mono-break">{item.evidence_id}</code>
                      </td>
                      <td data-label="File / Source Label" className="mono-break">
                        {item.filename || 'Unnamed artifact'}
                      </td>
                      <td data-label="Seal Status">
                        <span className={`state ${item.seal_status === 'sealed' ? 'verified' : 'warning'}`}>
                          {labelForSeal(item.seal_status)}
                        </span>
                      </td>
                      <td data-label="Verification">
                        <span
                          className={`state ${
                            item.verification_status === 'verified'
                              ? 'verified'
                              : item.verification_status === 'verification_failed'
                                ? 'failed'
                                : 'warning'
                          }`}
                        >
                          {labelForVerification(item.verification_status)}
                        </span>
                      </td>
                      <td data-label="Custody & Hold">
                        <div className="custody-cell">
                          <span className={`state ${item.custody_status === 'custody_verified' ? 'verified' : 'warning'}`}>
                            {labelForCustody(item.custody_status)}
                          </span>
                          {item.hold_active && <span className="state">Legal hold</span>}
                        </div>
                      </td>
                      <td data-label="Details">
                        <button
                          type="button"
                          className="secondary-btn"
                          aria-expanded={isSelected}
                          aria-label={`Inspect ${item.evidence_id}`}
                          onClick={() => setSelectedId(item.evidence_id)}
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

          {selectedItem && (
            <section className="preview evidence-detail" aria-label="Selected evidence details">
              <h3>
                Details for <code>{selectedItem.evidence_id}</code>
              </h3>
              <p className={selectedItem.verification_status === 'verification_failed' ? 'error' : 'muted'}>
                {selectedItem.status_reason}
              </p>
              <dl className="detail-grid">
                <div>
                  <dt>Filename</dt>
                  <dd className="mono-break">{selectedItem.filename}</dd>
                </div>
                <div>
                  <dt>Expected SHA-256</dt>
                  <dd>
                    <code className="mono-break">{selectedItem.expected_sha256 || 'Not recorded'}</code>
                  </dd>
                </div>
                <div>
                  <dt>Actual SHA-256</dt>
                  <dd>
                    <code className="mono-break">{selectedItem.actual_sha256 || 'Missing / not verified'}</code>
                  </dd>
                </div>
                <div>
                  <dt>Custody Root</dt>
                  <dd>
                    <code className="mono-break">{selectedItem.custody_root || 'None'}</code>
                  </dd>
                </div>
                {selectedItem.hold_active && (
                  <div>
                    <dt>Active Legal Hold</dt>
                    <dd className="mono-break">{selectedItem.hold_reason || 'Active'}</dd>
                  </div>
                )}
              </dl>

              {selectedItem.custody_events && selectedItem.custody_events.length > 0 && (
                <div className="custody-events">
                  <h4>Custody Chain ({selectedItem.custody_events.length})</h4>
                  <ul className="custody-list">
                    {selectedItem.custody_events.map(ev => (
                      <li key={`${ev.sequence}-${ev.event_id}`}>
                        <div>
                          <strong>#{ev.sequence} {ev.event_type}</strong> · <span className="mono-break">{ev.actor}</span> · <span>{ev.timestamp}</span>
                        </div>
                        <p className="muted mono-break">Reason: {ev.reason}</p>
                        <p className="muted mono-break">
                          Root: <code>{ev.custody_root}</code>
                        </p>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </section>
          )}
        </div>
      )}
    </section>
  );
}
