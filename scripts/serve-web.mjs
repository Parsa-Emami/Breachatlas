import http from 'node:http';
import { readFile, realpath, stat } from 'node:fs/promises';
import { resolve, relative, extname, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { validateRuntimeConfig } from '../apps/web/src/lib/runtime-config.mjs';

const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.webmanifest': 'application/manifest+json' };
const csp = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'";
export function createWebServer({ root, config, projectId }) {
  const valid = validateRuntimeConfig(config, projectId);
  const publicRoot = resolve(root);
  const within = path => { const diff = relative(publicRoot, path); return diff !== '..' && !diff.startsWith('../') && !isAbsolute(diff); };
  return http.createServer({ requestTimeout: 15000, headersTimeout: 10000, keepAliveTimeout: 5000, maxHeaderSize: 16384 }, async (req, res) => {
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
    if (!['GET', 'HEAD'].includes(req.method ?? '')) { res.setHeader('Allow', 'GET, HEAD'); send(405, '{"error":"method_not_allowed"}'); return; }
    let path;
    try {
      path = decodeURIComponent((req.url ?? '/').split('?')[0]);
      if (!path.startsWith('/') || path.includes('\\') || path.includes('\0') || path.split('/').some(part => part.startsWith('.'))) throw new Error();
    } catch { send(400, '{"error":"invalid_path"}'); return; }
    if (path === '/healthz') { send(200, '{"status":"ok","scope":"web-shell"}'); return; }
    if (path === '/readyz') {
      try { await stat(resolve(publicRoot, 'index.html')); send(200, '{"status":"ready","scope":"web-shell","engineReady":false}'); }
      catch { send(503, '{"status":"not_ready","scope":"web-shell"}'); }
      return;
    }
    if (path === '/api' || path.startsWith('/api/')) { send(503, '{"error":"engine_not_integrated"}'); return; }
    if (path === '/runtime-config.json') { send(200, JSON.stringify(valid)); return; }
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
