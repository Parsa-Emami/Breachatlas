import http from 'node:http';
import { readFile, realpath, stat } from 'node:fs/promises';
import { resolve, relative, extname, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { validateRuntimeConfig } from '../apps/web/src/lib/runtime-config.mjs';

const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.webmanifest': 'application/manifest+json' };
const manifestPath = '/api/v1/evidence-manifests/validate';
const integrityPath = '/api/v1/evidence-integrity/inspect';
const timelinePath = '/api/v1/timeline/inspect';
const diagnosticsPath = '/api/v1/diagnostics';

const forgedApiHeaders = new Set([
  'x-identity-override',
  'x-forwarded-user',
  'x-forwarded-host',
  'x-forwarded-role',
  'x-role',
  'x-case-scope',
  'x-provider',
  'x-auth-user',
  'x-user-override',
]);

export function redactDiagnosticText(raw) {
  const original = String(raw ?? '');
  let redacted = original
    .replace(/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g, '[REDACTED_PEM]')
    .replace(/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[^\r\n]*/g, '[REDACTED_PEM]')
    .replace(/\b(?:SECRET|CREDENTIAL|TOKEN|PRIVATE_KEY|API_KEY|AUTH)_SENTINEL(?:_[A-Z0-9_-]+)?\b/gi, '[REDACTED]')
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, '$1 [REDACTED]')
    .replace(/(https?:\/\/)[^/@\s]+:[^/@\s]+@/gi, '$1[REDACTED]@')
    .replace(/\b(password|passwd|secret|token|api_key|apikey|access_key|private_key|client_secret|authorization|cookie)\s*([=:])\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)/gi, '$1$2[REDACTED]');
  return {
    text: redacted,
    redacted: redacted !== original,
  };
}

function truncateUtf8(str, maxBytes) {
  const buf = Buffer.from(str, 'utf8');
  if (buf.length <= maxBytes) return str;
  if (maxBytes <= 3) return buf.subarray(0, maxBytes).toString('utf8');
  let end = maxBytes - 3;
  while (end > 0 && (buf[end] & 0xc0) === 0x80) end--;
  return buf.subarray(0, end).toString('utf8') + '...';
}

export function createDiagnosticLogBuffer({ maxEntries = 64, maxBytes = 16384 } = {}) {
  const safeMaxEntries = Number.isInteger(maxEntries) && maxEntries > 0 ? maxEntries : 64;
  const safeMaxBytes = Number.isInteger(maxBytes) && maxBytes >= 1024 ? maxBytes : 16384;
  const stored = [];
  let totalBytes = 0;
  let evictedCount = 0;
  let redactedCount = 0;

  return {
    record(level, component, code, message) {
      const cClean = redactDiagnosticText(String(component ?? '').trim());
      const codeClean = redactDiagnosticText(String(code ?? '').trim());
      const msgClean = redactDiagnosticText(String(message ?? '').trim());
      const wasRedacted = cClean.redacted || codeClean.redacted || msgClean.redacted;

      const entry = {
        timestamp: new Date().toISOString(),
        level: String(level || 'info').toLowerCase().trim(),
        component: truncateUtf8(cClean.text, 64),
        code: truncateUtf8(codeClean.text, 64),
        message: truncateUtf8(msgClean.text, 256),
        redacted: wasRedacted,
      };
      if (wasRedacted) redactedCount++;

      let bytes = Buffer.byteLength(JSON.stringify(entry), 'utf8');
      if (bytes > safeMaxBytes) {
        entry.message = '[TRUNCATED]';
        bytes = Buffer.byteLength(JSON.stringify(entry), 'utf8');
      }

      while (stored.length > 0 && (stored.length >= safeMaxEntries || totalBytes + bytes > safeMaxBytes)) {
        const oldest = stored.shift();
        totalBytes -= oldest.bytes;
        evictedCount++;
      }

      stored.push({ entry, bytes });
      totalBytes += bytes;
      return entry;
    },
    snapshot() {
      return {
        max_entries: safeMaxEntries,
        max_bytes: safeMaxBytes,
        total_bytes: totalBytes,
        evicted_count: evictedCount,
        redacted_count: redactedCount,
        entries: stored.map(item => item.entry),
      };
    },
  };
}

function hasDisallowedOriginOrSite(req) {
  const secFetchRaw = Array.isArray(req.headers['sec-fetch-site'])
    ? req.headers['sec-fetch-site'].join(',')
    : String(req.headers['sec-fetch-site'] ?? '');
  for (const part of secFetchRaw.split(',')) {
    if (part.trim().toLowerCase() === 'cross-site') return true;
  }
  const host = String(req.headers.host ?? '').toLowerCase();
  const originRaw = req.headers.origin;
  if (originRaw !== undefined) {
    const origins = Array.isArray(originRaw) ? originRaw : [String(originRaw)];
    for (const entry of origins) {
      for (const part of entry.split(',')) {
        const origin = part.trim().toLowerCase();
        if (origin !== '' && origin !== `http://${host}` && origin !== `https://${host}`) return true;
      }
    }
  }
  return false;
}

function hasForgedApiHeader(headers) {
  return Object.keys(headers).some(name => forgedApiHeaders.has(name.trim().toLowerCase()));
}

function probeEngineJson(engine, targetPath, timeoutMs = 1500) {
  return new Promise(resolvePromise => {
    const hostname = engine.hostname ?? '127.0.0.1';
    const port = Number(engine.port);
    const hostHeader = hostname.includes(':') ? `[${hostname}]:${port}` : `${hostname}:${port}`;
    const signal = AbortSignal.timeout(timeoutMs);
    const req = http.request({
      hostname,
      port,
      path: targetPath,
      method: 'GET',
      headers: { Host: hostHeader, Accept: 'application/json' },
      signal,
    }, response => {
      const chunks = [];
      let total = 0;
      let tooBig = false;
      response.on('data', chunk => {
        total += chunk.length;
        if (total > 65536) {
          tooBig = true;
          response.destroy();
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => {
        if (tooBig) {
          resolvePromise({ ok: false, status: 502, code: 'engine_response_too_large', message: 'Upstream engine diagnostic payload exceeded bounded size limit.' });
          return;
        }
        try {
          const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          resolvePromise({ ok: response.statusCode === 200, status: response.statusCode ?? 502, data: parsed });
        } catch {
          resolvePromise({ ok: false, status: 502, code: 'engine_malformed_response', message: 'Upstream engine returned invalid JSON readiness payload.' });
        }
      });
      response.on('error', () => {
        resolvePromise({ ok: false, status: 503, code: 'engine_unavailable', message: 'Failed while reading upstream engine readiness response.' });
      });
    });
    req.on('error', err => {
      if (signal.aborted) {
        resolvePromise({ ok: false, status: 504, code: 'engine_timeout', message: 'Engine readiness probe timed out.' });
      } else {
        resolvePromise({ ok: false, status: 503, code: 'engine_unavailable', message: redactDiagnosticText(err.message).text });
      }
    });
    req.end();
  });
}

function relayEngineRequest(req, res, engine, targetPath, send, logBuffer) {
  const fail = (status, code) => send(status, JSON.stringify({ schema_version: '1', status: 'error', error: { code } }));
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    fail(405, 'method_not_allowed');
    return;
  }
  if (hasDisallowedOriginOrSite(req)) {
    fail(403, 'origin_not_allowed');
    return;
  }
  if (hasForgedApiHeader(req.headers)) {
    fail(403, 'forged_header');
    return;
  }
  if (!engine) {
    fail(503, 'engine_unavailable');
    return;
  }

  const headers = { 'content-type': req.headers['content-type'] ?? '' };
  for (const name of ['content-length', 'content-encoding']) {
    if (req.headers[name] !== undefined) headers[name] = req.headers[name];
  }
  const signal = AbortSignal.timeout(3500);
  const upstream = http.request({ ...engine, path: targetPath, method: 'POST', headers, signal }, response => {
    res.writeHead(response.statusCode ?? 502, { 'Content-Type': 'application/json; charset=utf-8' });
    response.on('error', () => res.destroy());
    response.pipe(res);
  });
  upstream.on('error', err => {
    logBuffer?.record('error', 'relay', 'engine_relay_failed', err?.message || 'Engine relay error');
    if (res.destroyed) return;
    if (res.headersSent) res.destroy();
    else if (signal.aborted) fail(408, 'request_timeout');
    else fail(503, 'engine_unavailable');
  });
  res.on('close', () => {
    if (!res.writableFinished || !req.complete) upstream.destroy();
  });
  req.pipe(upstream);
}

const csp = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'";
export function createWebServer({ root, config, projectId, manifestEngine, diagnosticLog }) {
  const valid = validateRuntimeConfig(config, projectId);
  const publicRoot = resolve(root);
  const logBuffer = diagnosticLog ?? createDiagnosticLogBuffer({
    maxEntries: valid.maxDiagnosticEntries ?? 64,
    maxBytes: valid.maxDiagnosticLogBytes ?? 16384,
  });
  logBuffer.record('info', 'web-relay', 'startup', `Initialized web relay for ${valid.projectId}`);

  const within = targetPath => { const diff = relative(publicRoot, targetPath); return diff !== '..' && !diff.startsWith('../') && !isAbsolute(diff); };
  const server = http.createServer({ requestTimeout: 15000, headersTimeout: 10000, keepAliveTimeout: 5000, maxHeaderSize: 16384 }, async (req, res) => {
    res.setHeader('Content-Security-Policy', csp);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Cache-Control', 'no-store');
    const send = (status, body, type = 'application/json; charset=utf-8') => {
      res.writeHead(status, { 'Content-Type': type, 'Content-Length': Buffer.byteLength(body) });
      res.end(req.method === 'HEAD' ? undefined : body);
    };
    const localAuthority = /^(?:localhost|127\.0\.0\.1|\[::1\])(?::([0-9]{1,5}))?$/i.exec(req.headers.host ?? '');
    if (!localAuthority || (localAuthority[1] && (Number(localAuthority[1]) < 1 || Number(localAuthority[1]) > 65535))) { send(403, '{"error":"invalid_host"}'); return; }
    let path;
    try {
      path = decodeURIComponent((req.url ?? '/').split('?')[0]);
      if (!path.startsWith('/') || path.includes('\\') || path.includes('\0') || path.split('/').some(part => part.startsWith('.'))) throw new Error();
    } catch { send(400, '{"error":"invalid_path"}'); return; }
    if (path === '/api' || path.startsWith('/api/')) {
      const failApi = (status, code) => send(status, JSON.stringify({ schema_version: '1', status: 'error', error: { code } }));
      if (hasDisallowedOriginOrSite(req)) { failApi(403, 'origin_not_allowed'); return; }
      if (hasForgedApiHeader(req.headers)) { failApi(403, 'forged_header'); return; }
      if (path === diagnosticsPath) {
        if (!['GET', 'HEAD'].includes(req.method ?? '')) { res.setHeader('Allow', 'GET, HEAD'); failApi(405, 'method_not_allowed'); return; }
        let webAssetsReady = true;
        try { await stat(resolve(publicRoot, 'index.html')); } catch { webAssetsReady = false; }

        if (!manifestEngine) {
          const failures = [];
          if (!webAssetsReady) {
            failures.push({ component: 'web', code: 'web_assets_missing', message: 'Built web assets missing.' });
            logBuffer.record('error', 'web', 'web_assets_missing', 'Built web assets missing during diagnostics probe.');
          }
          failures.push({ component: 'engine', code: 'engine_not_integrated', message: 'Go engine is not configured for standalone web shell.' });
          send(webAssetsReady ? 200 : 503, JSON.stringify({
            schema_version: '1',
            status: webAssetsReady ? 'web_only' : 'not_ready',
            web_health: { status: 'ok', scope: 'web-shell', webHealthy: true, webReady: webAssetsReady },
            readiness: {
              status: webAssetsReady ? 'ready' : 'not_ready',
              scope: 'web-shell',
              webReady: webAssetsReady,
              engineReady: false,
              storageReady: false,
              providersReady: false,
              failures,
            },
            diagnostics: {
              web_relay: logBuffer.snapshot(),
              engine: null,
            },
          }));
          return;
        }

        const upstream = await probeEngineJson(manifestEngine, diagnosticsPath);
        if (!upstream.data) {
          logBuffer.record('error', 'engine', upstream.code || 'engine_unavailable', upstream.message || 'Engine diagnostics unreachable.');
          const failures = [];
          if (!webAssetsReady) failures.push({ component: 'web', code: 'web_assets_missing', message: 'Built web assets missing.' });
          failures.push({ component: 'engine', code: upstream.code || 'engine_unavailable', message: upstream.message || 'Engine diagnostics unreachable.' });
          send(503, JSON.stringify({
            schema_version: '1',
            status: 'not_ready',
            web_health: { status: 'ok', scope: 'web-shell', webHealthy: true, webReady: webAssetsReady },
            readiness: {
              status: 'not_ready',
              scope: 'unified-local-runtime',
              webReady: webAssetsReady,
              engineReady: false,
              storageReady: false,
              providersReady: false,
              failures,
            },
            diagnostics: {
              web_relay: logBuffer.snapshot(),
              engine: null,
            },
          }));
          return;
        }

        const engReadiness = upstream.data.readiness ?? {};
        const overallReady = webAssetsReady && upstream.ok && engReadiness.status === 'ready';
        const combinedFailures = [];
        if (!webAssetsReady) combinedFailures.push({ component: 'web', code: 'web_assets_missing', message: 'Built web assets missing.' });
        if (Array.isArray(engReadiness.failures)) combinedFailures.push(...engReadiness.failures);
        send(overallReady ? 200 : 503, JSON.stringify({
          schema_version: '1',
          status: overallReady ? 'ready' : 'not_ready',
          web_health: { status: 'ok', scope: 'web-shell', webHealthy: true, webReady: webAssetsReady },
          readiness: {
            ...engReadiness,
            status: overallReady ? 'ready' : 'not_ready',
            scope: 'unified-local-runtime',
            webReady: webAssetsReady,
            failures: combinedFailures,
          },
          diagnostics: {
            web_relay: logBuffer.snapshot(),
            engine: upstream.data.diagnostics ?? null,
          },
        }));
        return;
      }
      if (path === manifestPath || path === integrityPath || path === timelinePath) { relayEngineRequest(req, res, manifestEngine, path, send, logBuffer); return; }
      if (!['GET', 'HEAD'].includes(req.method ?? '')) { res.setHeader('Allow', 'GET, HEAD'); failApi(405, 'method_not_allowed'); return; }
      send(503, '{"error":"engine_not_integrated"}');
      return;
    }
    if (!['GET', 'HEAD'].includes(req.method ?? '')) { res.setHeader('Allow', 'GET, HEAD'); send(405, '{"error":"method_not_allowed"}'); return; }
    if (path === '/healthz') { send(200, '{"status":"ok","scope":"web-shell","webHealthy":true}'); return; }
    if (path === '/readyz') {
      let webReady = true;
      try { await stat(resolve(publicRoot, 'index.html')); } catch { webReady = false; }
      if (!webReady) {
        logBuffer.record('error', 'web', 'web_assets_missing', 'Built web assets missing during /readyz probe.');
        send(503, JSON.stringify({
          status: 'not_ready',
          scope: manifestEngine ? 'unified-local-runtime' : 'web-shell',
          webReady: false,
          engineReady: false,
          storageReady: false,
          providersReady: false,
          failures: [{ component: 'web', code: 'web_assets_missing', message: 'Built web assets missing.' }],
        }));
        return;
      }
      if (!manifestEngine) {
        send(200, JSON.stringify({
          status: 'ready',
          scope: 'web-shell',
          webReady: true,
          engineReady: false,
          storageReady: false,
          providersReady: false,
        }));
        return;
      }
      const upstream = await probeEngineJson(manifestEngine, '/readyz');
      if (!upstream.data) {
        logBuffer.record('error', 'engine', upstream.code || 'engine_unavailable', upstream.message || 'Engine readiness endpoint unreachable.');
        send(503, JSON.stringify({
          status: 'not_ready',
          scope: 'unified-local-runtime',
          webReady: true,
          engineReady: false,
          storageReady: false,
          providersReady: false,
          failures: [{ component: 'engine', code: upstream.code || 'engine_unavailable', message: upstream.message || 'Engine readiness endpoint unreachable.' }],
        }));
        return;
      }
      const ready = upstream.ok && upstream.data.status === 'ready' && upstream.data.storageReady === true && upstream.data.providersReady === true;
      if (!ready) {
        logBuffer.record('warn', 'readiness', 'degraded_dependencies', 'Engine reported unready storage or provider prerequisites.');
      }
      send(ready ? 200 : 503, JSON.stringify({
        status: ready ? 'ready' : 'not_ready',
        scope: 'unified-local-runtime',
        webReady: true,
        engineReady: Boolean(upstream.data.engineReady),
        storageReady: Boolean(upstream.data.storageReady),
        providersReady: Boolean(upstream.data.providersReady),
        storage: upstream.data.storage,
        providers: upstream.data.providers,
        failures: Array.isArray(upstream.data.failures) ? upstream.data.failures : [],
      }));
      return;
    }
    if (path === '/runtime-config.json') {
      if (hasDisallowedOriginOrSite(req)) { send(403, '{"error":"origin_not_allowed"}'); return; }
      send(200, JSON.stringify(valid));
      return;
    }
    const asset = path.startsWith('/assets/');
    if (!(asset || ['/', '/index.html', '/icon.svg', '/manifest.webmanifest', '/robots.txt'].includes(path))) { send(404, '{"error":"not_found"}'); return; }
    try {
      const filename = await realpath(resolve(publicRoot, '.' + (path === '/' ? '/index.html' : path)));
      if (!within(filename) || !(await stat(filename)).isFile()) { send(404, '{"error":"not_found"}'); return; }
      const bytes = await readFile(filename);
      res.writeHead(200, { 'Content-Type': types[extname(filename)] ?? 'application/octet-stream', 'Content-Length': bytes.length, 'Cache-Control': asset ? 'public, max-age=31536000, immutable' : 'no-store' });
      res.end(req.method === 'HEAD' ? undefined : bytes);
    } catch { send(404, '{"error":"not_found"}'); }
  });
  server.diagnosticLog = logBuffer;
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const args = process.argv.slice(2);
  const options = { host: '127.0.0.1', port: '4173', root: 'dist/web', config: 'ops/web/runtime-config.json' };
  for (let i = 0; i < args.length; i += 2) {
    const key = args[i].slice(2);
    if (!args[i].startsWith('--') || !Object.hasOwn(options, key) || !args[i + 1]) throw new Error('Usage: node scripts/serve-web.mjs [--host 127.0.0.1] [--port 4173] [--root dist/web] [--config path]');
    options[key] = args[i + 1];
  }
  if (!['127.0.0.1', '::1'].includes(options.host)) throw new Error('Bind to loopback and use the documented TLS proxy.');
  if (!/^\d+$/.test(options.port) || +options.port < 1 || +options.port > 65535) throw new Error('Invalid port.');
  const product = JSON.parse(await readFile(new URL('../ops/web/brand.json', import.meta.url), 'utf8'));
  const config = JSON.parse(await readFile(resolve(options.config), 'utf8'));
  await stat(resolve(options.root, 'index.html'));
  const server = createWebServer({ root: options.root, config, projectId: product.slug });
  server.maxRequestsPerSocket = 1000;
  server.on('error', error => { console.error(error.message); process.exitCode = 1; });
  server.listen(+options.port, options.host, () => console.log(JSON.stringify({ service: product.slug + '-web', host: options.host, port: +options.port, engineReady: false })));
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => {
    server.close(() => process.exit(0));
    setTimeout(() => { server.closeAllConnections(); process.exit(1); }, 10000).unref();
  });
}
