import { useEffect, useRef, useState } from 'react';

type ManifestResponse =
  | { schema_version: '1'; status: 'valid'; result: { case_id: string; evidence_id: string } }
  | { schema_version: '1'; status: 'error'; error: { code: string; field?: string } };

const manifestLimit = 16 * 1024;
const messages: Record<string, string> = {
  engine_unavailable: 'Start the local engine with npm start, then try again.',
  invalid_json: 'Choose a manifest containing valid UTF-8 JSON.',
  invalid_manifest: 'The manifest must be one JSON object.',
  invalid_field: 'The manifest contains an invalid value.',
  missing_field: 'The manifest is missing a required field.',
  payload_too_large: 'The manifest exceeds 16 KiB.',
  request_timeout: 'Manifest validation timed out.',
  unexpected_or_duplicate_field: 'The manifest contains an unknown or duplicate field.',
  unsupported_version: 'Use evidence manifest schema version 1.',
};

export function ManifestValidation() {
  const [outcome, setOutcome] = useState<{ valid: boolean; message: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const pending = useRef<AbortController | null>(null);
  useEffect(() => () => pending.current?.abort(), []);

  async function validate(file: File | undefined) {
    if (!file) return;
    pending.current?.abort();
    setOutcome(null);
    if (file.size > manifestLimit) {
      setBusy(false);
      setOutcome({ valid: false, message: messages.payload_too_large });
      return;
    }

    const controller = new AbortController();
    pending.current = controller;
    setBusy(true);
    try {
      const response = await fetch('/api/v1/evidence-manifests/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: file,
        credentials: 'omit',
        redirect: 'error',
        signal: AbortSignal.any([controller.signal, AbortSignal.timeout(5000)]),
      });
      const data: ManifestResponse = await response.json();
      if (controller.signal.aborted) return;
      if (response.ok && data.schema_version === '1' && data.status === 'valid') {
        setOutcome({ valid: true, message: `Valid manifest for ${data.result.evidence_id} in ${data.result.case_id}.` });
      } else if (data.status === 'error') {
        const message = Object.hasOwn(messages, data.error.code) ? messages[data.error.code] : 'The engine rejected the manifest.';
        setOutcome({ valid: false, message: data.error.field ? `${message} Field: ${data.error.field}.` : message });
      } else {
        setOutcome({ valid: false, message: 'The engine returned an unexpected validation response.' });
      }
    } catch {
      if (!controller.signal.aborted) setOutcome({ valid: false, message: 'Unable to complete local manifest validation.' });
    } finally {
      if (pending.current === controller) {
        pending.current = null;
        setBusy(false);
      }
    }
  }

  function cancel() {
    pending.current?.abort();
    pending.current = null;
    setBusy(false);
    setOutcome({ valid: false, message: 'Validation cancelled.' });
  }

  return <section className="panel">
    <div className="eyebrow">Evidence contract</div>
    <h2>Validate an evidence manifest</h2>
    <p>Choose a version 1 JSON manifest to check its metadata with the local engine. Maximum 16 KiB.</p>
    <label className="file-button">Validate manifest<input aria-label="Validate manifest" type="file" accept=".json,application/json" onChange={event => { void validate(event.target.files?.[0]); event.target.value = ''; }}/></label>
    {busy && <p><button type="button" onClick={cancel}>Cancel validation</button></p>}
    {outcome && <p className={outcome.valid ? 'muted' : 'error'} role={outcome.valid ? 'status' : 'alert'}>{outcome.message}</p>}
  </section>;
}
