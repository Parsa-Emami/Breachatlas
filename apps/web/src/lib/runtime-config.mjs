const allowed = new Set(['projectId', 'apiBasePath', 'engineEnabled', 'maxPreviewBytes']);

export function validateRuntimeConfig(value, expectedProjectId) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Configuration must be an object.');
  if (Object.keys(value).some(key => !allowed.has(key))) throw new Error('Unknown public configuration field.');
  if (!/^[a-z][a-z0-9-]{1,63}$/.test(value.projectId) || value.projectId !== expectedProjectId) throw new Error('Project configuration mismatch.');
  if (value.apiBasePath !== '/api') throw new Error('Only the same-origin /api path is supported.');
  if (value.engineEnabled !== false) throw new Error('Engine integration has not been enabled in this release.');
  if (!Number.isSafeInteger(value.maxPreviewBytes) || value.maxPreviewBytes < 1 || value.maxPreviewBytes > 1048576) throw new Error('Preview limit must be 1 to 1048576 bytes.');
  return Object.freeze({ ...value });
}
