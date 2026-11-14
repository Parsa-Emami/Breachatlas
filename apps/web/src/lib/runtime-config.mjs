const allowed = new Set([
  'projectId',
  'apiBasePath',
  'engineEnabled',
  'maxPreviewBytes',
  'readinessPath',
  'diagnosticsPath',
  'maxDiagnosticLogBytes',
  'maxDiagnosticEntries',
  'requiredProviders',
]);

export function validateRuntimeConfig(value, expectedProjectId) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Configuration must be an object.');
  if (Object.keys(value).some(key => !allowed.has(key))) throw new Error('Unknown public configuration field.');
  if (!/^[a-z][a-z0-9-]{1,63}$/.test(value.projectId) || value.projectId !== expectedProjectId) throw new Error('Project configuration mismatch.');
  if (value.apiBasePath !== '/api') throw new Error('Only the same-origin /api path is supported.');
  if (value.engineEnabled !== false) throw new Error('Engine integration has not been enabled in this release.');
  if (!Number.isSafeInteger(value.maxPreviewBytes) || value.maxPreviewBytes < 1 || value.maxPreviewBytes > 1048576) throw new Error('Preview limit must be 1 to 1048576 bytes.');

  if (value.readinessPath !== undefined && value.readinessPath !== '/readyz') {
    throw new Error('Only the same-origin /readyz readiness path is supported.');
  }
  if (value.diagnosticsPath !== undefined && value.diagnosticsPath !== '/api/v1/diagnostics') {
    throw new Error('Only the same-origin /api/v1/diagnostics path is supported.');
  }
  if (value.maxDiagnosticLogBytes !== undefined && (!Number.isSafeInteger(value.maxDiagnosticLogBytes) || value.maxDiagnosticLogBytes < 1024 || value.maxDiagnosticLogBytes > 65536)) {
    throw new Error('Diagnostic log byte limit must be 1024 to 65536 bytes.');
  }
  if (value.maxDiagnosticEntries !== undefined && (!Number.isSafeInteger(value.maxDiagnosticEntries) || value.maxDiagnosticEntries < 1 || value.maxDiagnosticEntries > 256)) {
    throw new Error('Diagnostic log entry limit must be 1 to 256.');
  }
  if (value.requiredProviders !== undefined) {
    if (!Array.isArray(value.requiredProviders) || value.requiredProviders.length === 0 || value.requiredProviders.some(p => typeof p !== 'string' || !/^[a-z0-9-]{1,32}$/.test(p))) {
      throw new Error('Required providers must be a non-empty array of valid identifiers.');
    }
  }

  return Object.freeze({ ...value });
}
