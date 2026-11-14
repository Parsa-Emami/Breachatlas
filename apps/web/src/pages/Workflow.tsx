import { useEffect, useState } from 'react';

type WorkflowStateItem = {
  case_id: string;
  evidence_id: string;
  sha256: string;
  size_bytes: number;
  media_type: string;
  acquired_at: string;
  custody_root: string;
  manifest_digest: string;
  verified: boolean;
  custody_chain_valid: boolean;
  custody_event_count: number;
  hold_status?: {
    active_hold_count: number;
    active_hold_ids?: string[];
    disposition: string;
  };
};

type WorkflowTimelineEntry = {
  event_identity: string;
  event_type: string;
  summary: string;
  time: {
    raw_timestamp: string;
    normalized_timestamp: string;
    timezone_status: string;
    timezone_offset: string;
    confidence: number;
  };
};

type WorkflowStateSnapshot = {
  schema_version: string;
  status: string;
  case_id: string;
  bundle_public_key: string;
  bundle_key_id: string;
  evidence: WorkflowStateItem[];
  timeline_count: number;
  timeline_entries: WorkflowTimelineEntry[];
};

const defaultPayload =
  '{"timestamp":"2026-11-14T07:45:12+03:30","event_type":"auth_login","summary":"Interactive SSH login on bastion-01","host":"bastion-01","account":"analyst-parisa"}\n' +
  '{"timestamp":"2026-11-14T08:05:30+03:30","event_type":"privilege_check","summary":"Read-only log collection initialized","host":"bastion-01","account":"analyst-parisa"}\n' +
  '{"timestamp":"2026-11-14 08:20:00","event_type":"export_prep","summary":"Zoneless log line normalized with source zone hint","host":"app-02","account":"svc-dfir"}\n';

export function WorkflowPage() {
  const [caseId, setCaseId] = useState('case-c30-acceptance-001');
  const [evidenceId, setEvidenceId] = useState('ev-c30-auth-01');
  const [artifactId, setArtifactId] = useState('art-c30-timeline-01');
  const [bundleId, setBundleId] = useState('bnd-c30-001');
  const [holdId, setHoldId] = useState('hold-c30-001');
  const [zoneHint, setZoneHint] = useState('Asia/Tehran');
  const [provider, setProvider] = useState('local');
  const [payload, setPayload] = useState(defaultPayload);

  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [snapshot, setSnapshot] = useState<WorkflowStateSnapshot | null>(null);
  const [lastExport, setLastExport] = useState<{ bundle_id: string; bundle_digest: string; public_key: string; signed: boolean } | null>(null);
  const [lastVerify, setLastVerify] = useState<string>('');
  const [lastRecover, setLastRecover] = useState<string>('');

  async function refreshState(targetCaseId = caseId) {
    try {
      const url = `/api/v1/workflow/state?case_id=${encodeURIComponent(targetCaseId)}&provider=${encodeURIComponent(provider)}`;
      const res = await fetch(url, { cache: 'no-store', credentials: 'omit' });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(`State load rejected: ${data?.error?.code || res.status}`);
        return;
      }
      setSnapshot(data);
    } catch {
      setErrorMsg('Local engine workflow state is unreachable.');
    }
  }

  useEffect(() => {
    void refreshState(caseId);
  }, []);

  async function postAction(endpoint: string, body: Record<string, unknown>, onSuccess: (data: Record<string, any>) => void) {
    if (busy) return;
    setBusy(true);
    setErrorMsg('');
    setNotice('');
    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
        cache: 'no-store',
        credentials: 'omit',
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        const code = data?.error?.code || (typeof data?.status === 'string' && data.status !== 'error' ? data.status : '') || `http_${res.status}`;
        const intact = data?.evidence_intact === true ? ' (sealed evidence intact)' : '';
        setErrorMsg(`Operation rejected (${code})${intact}`);
        await refreshState();
        return;
      }
      onSuccess(data);
      await refreshState();
    } catch {
      setErrorMsg('Local engine unavailable during workflow request.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="stack">
      <section className="panel">
        <div className="eyebrow">Clone-to-value end-to-end execution</div>
        <h2>Case Workflow Configuration</h2>
        <div className="filters">
          <label>
            Case ID
            <input value={caseId} onChange={e => setCaseId(e.target.value)} />
          </label>
          <label>
            Evidence ID
            <input value={evidenceId} onChange={e => setEvidenceId(e.target.value)} />
          </label>
          <label>
            Artifact ID
            <input value={artifactId} onChange={e => setArtifactId(e.target.value)} />
          </label>
          <label>
            Bundle ID
            <input value={bundleId} onChange={e => setBundleId(e.target.value)} />
          </label>
          <label>
            Hold ID
            <input value={holdId} onChange={e => setHoldId(e.target.value)} />
          </label>
          <label>
            Zone Hint
            <input value={zoneHint} onChange={e => setZoneHint(e.target.value)} />
          </label>
          <label>
            Provider
            <input value={provider} onChange={e => setProvider(e.target.value)} />
          </label>
        </div>
        <label style={{ display: 'block', marginTop: '1rem' }}>
          Synthetic Evidence Payload (JSONL)
          <textarea
            aria-label="Synthetic Evidence Payload"
            rows={4}
            style={{ width: '100%', boxSizing: 'border-box', fontFamily: 'monospace' }}
            value={payload}
            onChange={e => setPayload(e.target.value)}
          />
        </label>
        <div className="filters" style={{ marginTop: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              void postAction(
                '/api/v1/workflow/upload-seal',
                {
                  schema_version: '1',
                  case_id: caseId,
                  evidence_id: evidenceId,
                  filename: `${evidenceId}.jsonl`,
                  media_type: 'application/x-ndjson',
                  payload,
                  acquired_at: '2026-11-14T08:00:00+03:30',
                  actor: 'analyst-parisa',
                  provider,
                },
                data => setNotice(`Sealed ${data.evidence_id}: SHA-256 ${data.sha256} (${data.size_bytes} bytes)`)
              )
            }
          >
            1-2. Upload & Seal
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              void postAction(
                '/api/v1/workflow/custody',
                {
                  schema_version: '1',
                  case_id: caseId,
                  evidence_id: evidenceId,
                  event_id: `cust-${evidenceId}-02`,
                  event_type: 'custody_transfer',
                  actor: 'analyst-parisa',
                  timestamp: '2026-11-14T08:10:00+03:30',
                  reason: 'Transfer to forensic indexing',
                  from_custodian: 'collector-01',
                  to_custodian: 'analyst-parisa',
                  provider,
                },
                data => setNotice(`Custody chain updated: seq ${data.sequence}, root ${data.custody_root}`)
              )
            }
          >
            3. Add Custody
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              void postAction(
                '/api/v1/workflow/timeline',
                {
                  schema_version: '1',
                  case_id: caseId,
                  evidence_id: evidenceId,
                  artifact_id: artifactId,
                  zone_hint: zoneHint,
                  source_confidence: 0.96,
                  provider,
                },
                data => setNotice(`Indexed ${data.total_entries} timeline entries; raw_timestamps_preserved=${String(data.raw_timestamps_preserved)}`)
              )
            }
          >
            4. Parse Bounded Timeline
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              void postAction(
                '/api/v1/workflow/hold',
                {
                  schema_version: '1',
                  case_id: caseId,
                  evidence_id: evidenceId,
                  hold_id: holdId,
                  action: 'place',
                  actor: 'legal-counsel',
                  timestamp: '2026-11-14T08:15:00+03:30',
                  reason: 'Active incident litigation hold',
                  provider,
                },
                data => setNotice(`Legal hold active: ${data.hold_id}`)
              )
            }
          >
            5a. Place Legal Hold
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              void postAction(
                '/api/v1/workflow/hold',
                {
                  schema_version: '1',
                  case_id: caseId,
                  evidence_id: evidenceId,
                  action: 'attempt_delete',
                  actor: 'ops-cleanup',
                  timestamp: '2026-11-14T08:16:00+03:30',
                  reason: 'Negative UAT disposal test under hold',
                  provider,
                },
                () => setNotice('Disposal unexpectedly succeeded')
              )
            }
          >
            5b. Attempt Delete (Expect Reject)
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              void postAction(
                '/api/v1/workflow/hold',
                {
                  schema_version: '1',
                  case_id: caseId,
                  evidence_id: evidenceId,
                  action: 'attempt_expire',
                  actor: 'retention-worker',
                  timestamp: '2026-11-14T08:17:00+03:30',
                  reason: 'Negative UAT expiration test under hold',
                  provider,
                },
                () => setNotice('Expiration unexpectedly succeeded')
              )
            }
          >
            5c. Attempt Expire (Expect Reject)
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              void postAction(
                '/api/v1/workflow/export',
                {
                  schema_version: '1',
                  case_id: caseId,
                  bundle_id: bundleId,
                  evidence_ids: [evidenceId],
                  artifact_ids: [artifactId],
                  provider,
                },
                data => {
                  setLastExport({
                    bundle_id: data.bundle_id,
                    bundle_digest: data.bundle_digest,
                    public_key: data.public_key,
                    signed: Boolean(data.signed),
                  });
                  setNotice(`Exported signed bundle ${data.bundle_id} (digest ${data.bundle_digest})`);
                }
              )
            }
          >
            6. Export Signed Bundle
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              void postAction(
                '/api/v1/workflow/verify-bundle',
                {
                  schema_version: '1',
                  bundle_id: bundleId,
                  trusted_public_key: lastExport?.public_key || snapshot?.bundle_public_key || '',
                  require_signature: true,
                },
                data => {
                  const sig = data?.result?.signature_status || 'verified';
                  const evInt = data?.result?.evidence_integrity || 'MATCH';
                  setLastVerify(`verified:${evInt}:${sig}`);
                  setNotice(`Bundle ${bundleId} verified: ${evInt}, ${sig}`);
                }
              )
            }
          >
            7a. Verify Authentic Bundle
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              void postAction(
                '/api/v1/workflow/verify-bundle',
                {
                  schema_version: '1',
                  bundle_id: bundleId,
                  trusted_public_key: lastExport?.public_key || snapshot?.bundle_public_key || '',
                  require_signature: true,
                  simulate_tamper_copy: true,
                },
                () => setLastVerify('unexpected_pass')
              )
            }
          >
            7b. Simulate Tampered Byte Verification
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              void postAction(
                '/api/v1/workflow/recover',
                {
                  schema_version: '1',
                  case_id: caseId,
                  action: 'rebuild',
                  drop_index_first: true,
                  zone_hint: zoneHint,
                  provider,
                },
                data => {
                  setLastRecover(`rebuilt:${data.rebuilt_timeline_entries}:sealed_modified=${String(data.sealed_bytes_modified)}`);
                  setNotice(`Recovered consistency: rebuilt ${data.rebuilt_timeline_entries} entries, sealed_bytes_modified=${String(data.sealed_bytes_modified)}`);
                }
              )
            }
          >
            8a. Recover Consistency
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              void postAction(
                '/api/v1/workflow/recover',
                {
                  schema_version: '1',
                  case_id: caseId,
                  action: 'restore_bundle',
                  bundle_id: bundleId,
                  target_case_id: `${caseId}-restored`,
                  zone_hint: zoneHint,
                  provider,
                },
                data => {
                  setLastRecover(`restored:${data.restored_evidence_count}:entries=${data.rebuilt_timeline_entries}:sealed_modified=${String(data.sealed_bytes_modified)}`);
                  setNotice(`Restored bundle ${data.bundle_id}: evidence=${data.restored_evidence_count}, timeline=${data.rebuilt_timeline_entries}`);
                }
              )
            }
          >
            8b. Restore Bundle
          </button>
          <button type="button" disabled={busy} onClick={() => void refreshState(caseId)}>
            Refresh Persisted State
          </button>
        </div>

        {notice && (
          <p role="status" className="preview" style={{ marginTop: '1rem' }}>
            {notice}
          </p>
        )}
        {errorMsg && (
          <p role="alert" className="error" style={{ marginTop: '1rem' }}>
            {errorMsg}
          </p>
        )}
      </section>

      <section className="panel" aria-label="Persisted Workflow State">
        <div className="eyebrow">Authoritative Local Store State</div>
        <h2>Persisted Evidence & Timeline</h2>
        {lastExport && (
          <p className="muted" data-testid="export-summary">
            Bundle: <code>{lastExport.bundle_id}</code> · Digest: <code>{lastExport.bundle_digest}</code> · Key: <code>{lastExport.public_key}</code>
          </p>
        )}
        {lastVerify && (
          <p className="muted" data-testid="verify-summary">
            Verification: <code>{lastVerify}</code>
          </p>
        )}
        {lastRecover && (
          <p className="muted" data-testid="recover-summary">
            Recovery: <code>{lastRecover}</code>
          </p>
        )}

        {snapshot && (
          <div data-testid="persisted-state">
            <p className="muted">
              Case <code>{snapshot.case_id}</code> · Sealed items: {snapshot.evidence.length} · Indexed timeline events: {snapshot.timeline_count}
            </p>
            {snapshot.evidence.map(item => (
              <article key={item.evidence_id} className="preview" style={{ marginBottom: '0.75rem' }}>
                <h3>{item.evidence_id}</h3>
                <p>
                  SHA-256: <code>{item.sha256}</code> · {item.size_bytes} bytes · Verified: {String(item.verified)} · Custody valid: {String(item.custody_chain_valid)} ({item.custody_event_count} events)
                </p>
                <p>
                  Custody root: <code>{item.custody_root}</code> · Active holds: {item.hold_status?.active_hold_count ?? 0}
                </p>
              </article>
            ))}
            {snapshot.timeline_entries.length > 0 && (
              <ul>
                {snapshot.timeline_entries.map(entry => (
                  <li key={entry.event_identity}>
                    <code>{entry.time.raw_timestamp}</code> ({entry.time.timezone_offset}) → <code>{entry.time.normalized_timestamp}</code> · conf={entry.time.confidence} · {entry.event_type}: {entry.summary}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </section>
    </div>
  );
}
