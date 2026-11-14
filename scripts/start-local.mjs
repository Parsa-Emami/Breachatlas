#!/usr/bin/env node
import { createInterface } from 'node:readline';
import { spawn } from 'node:child_process';
import { readFile, access, stat } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { constants } from 'node:fs';
import { createWebServer } from './serve-web.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..');

export async function checkEngineHealth(host, port, timeoutMs = 5000) {
  const hostname = host.includes(':') ? `[${host}]` : host;
  try {
    const response = await fetch(`http://${hostname}:${port}/healthz`, {
      redirect: 'error', signal: AbortSignal.timeout(timeoutMs)
    });
    if (!response.ok) {
      await response.body?.cancel();
      return false;
    }
    const health = await response.json();
    return health.status === 'ok' && health.service === 'breachatlas-engine';
  } catch {
    return false;
  }
}

export async function ensureEngineBinary(binaryPath) {
  try {
    await access(binaryPath, constants.X_OK);
    return true;
  } catch {
    const build = spawn('go', ['build', '-o', binaryPath, './cmd/breachatlas'], { cwd: root, stdio: 'ignore' });
    return new Promise(resolvePromise => {
      build.once('error', () => resolvePromise(false));
      build.once('close', code => resolvePromise(code === 0));
    });
  }
}

export async function startSupervisor(options = {}) {
  const host = options.host ?? '127.0.0.1';
  const webPort = Number(options.port ?? '4173');
  const enginePort = Number(options.enginePort ?? '8080');
  const webRoot = resolve(root, options.root || 'dist/web');
  const configPath = resolve(root, options.config || 'ops/web/runtime-config.json');
  const engineBinary = resolve(root, options.engineBin || 'dist/bin/breachatlas');

  if (!['127.0.0.1', '::1', 'localhost'].includes(host)) {
    throw new Error(`Supervisor strictly forbids non-loopback host "${host}".`);
  }
  if (![webPort, enginePort].every(port => Number.isInteger(port) && port > 0 && port <= 65535)) {
    throw new Error('Web and engine ports must be integers from 1 to 65535.');
  }

  options.signal?.throwIfAborted();
  const product = JSON.parse(await readFile(resolve(root, 'ops/web/brand.json'), 'utf8'));
  const config = JSON.parse(await readFile(configPath, 'utf8'));
  await stat(resolve(webRoot, 'index.html'));
  const webServer = createWebServer({ root: webRoot, config, projectId: product.slug, manifestEngine: { hostname: host, port: enginePort } });
  webServer.maxRequestsPerSocket = 1000;

  if (!await ensureEngineBinary(engineBinary)) {
    throw new Error(`Failed to locate or build Go engine binary at ${engineBinary}.`);
  }
  options.signal?.throwIfAborted();

  const storageDir = String(options.storageDir ?? process.env.BREACHATLAS_STORAGE_DIR ?? '').trim();
  const requiredProviders = String(options.requiredProviders ?? process.env.BREACHATLAS_REQUIRED_PROVIDERS ?? '').trim();
  const engineArgs = ['--host', host, '--port', String(enginePort)];
  if (storageDir) engineArgs.push('--storage-dir', storageDir);
  if (requiredProviders) engineArgs.push('--required-providers', requiredProviders);

  const engineProcess = spawn(engineBinary, engineArgs, {
    cwd: root, stdio: ['ignore', 'pipe', options.engineStdio || 'inherit']
  });
  if (options.engineStdio !== 'ignore') engineProcess.stdout.pipe(process.stdout, { end: false });
  let exited = false;
  const engineExit = new Promise(resolvePromise => {
    engineProcess.once('error', error => { exited = true; resolvePromise(error.message); });
    engineProcess.once('exit', (code, signal) => { exited = true; resolvePromise(signal ?? code); });
  });

  let closing;
  const shutdown = () => closing ??= (async () => {
    const webClosed = new Promise(resolvePromise => webServer.close(resolvePromise));
    webServer.closeAllConnections();
    if (!exited) {
      engineProcess.kill('SIGTERM');
      const timer = setTimeout(() => engineProcess.kill('SIGKILL'), 3000);
      await engineExit;
      clearTimeout(timer);
    }
    await webClosed;
  })();

  const lines = createInterface({ input: engineProcess.stdout });
  const signal = AbortSignal.any([AbortSignal.timeout(options.healthTimeoutMs ?? 5000), ...(options.signal ? [options.signal] : [])]);
  let abort;
  const cancelled = new Promise((_, reject) => {
    abort = () => reject(new Error('Go engine startup cancelled or timed out.', { cause: signal.reason }));
    if (signal.aborted) abort();
    else signal.addEventListener('abort', abort, { once: true });
  });
  const ready = new Promise(resolvePromise => {
    lines.on('line', line => {
      try {
        const status = JSON.parse(line);
        if (status.service === 'breachatlas-engine' && status.status === 'listening' && status.port === enginePort) resolvePromise();
      } catch {}
    });
  });
  const prematureExit = engineExit.then(status => { throw new Error(`Go engine exited during startup (${status}).`); });

  try {
    await Promise.race([ready, cancelled, prematureExit]);
    await Promise.race([new Promise((resolvePromise, reject) => {
      webServer.once('error', reject);
      webServer.listen(webPort, host, resolvePromise);
    }), cancelled, prematureExit]);
  } catch (error) {
    await shutdown();
    throw error;
  } finally {
    signal.removeEventListener('abort', abort);
    lines.close();
    engineProcess.stdout.resume();
  }

  const state = {
    service: `${product.slug}-unified-supervisor`,
    host,
    webPort,
    enginePort,
    status: 'ready',
    engineReady: true
  };
  void engineExit.then(shutdown);
  return { state, webServer, engineProcess, engineExit, shutdown };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const args = process.argv.slice(2);
  const options = {
    host: '127.0.0.1',
    port: '4173',
    enginePort: '8080',
    root: 'dist/web',
    config: 'ops/web/runtime-config.json',
    engineBin: 'dist/bin/breachatlas',
    storageDir: '',
    requiredProviders: ''
  };

  for (let i = 0; i < args.length; i += 2) {
    const key = args[i].slice(2);
    if (!args[i].startsWith('--') || !Object.hasOwn(options, key) || !args[i + 1]) {
      console.error('Usage: node scripts/start-local.mjs [--host 127.0.0.1] [--port 4173] [--enginePort 8080] [--root dist/web] [--config path]');
      process.exit(1);
    }
    options[key] = args[i + 1];
  }

  const startup = new AbortController();
  options.signal = startup.signal;
  const signals = ['SIGINT', 'SIGTERM'];
  const cancelStartup = () => startup.abort();
  for (const signal of signals) process.once(signal, cancelStartup);
  try {
    const supervisor = await startSupervisor(options);
    for (const signal of signals) process.removeListener(signal, cancelStartup);
    console.log(JSON.stringify(supervisor.state));

    let stopping = false;
    const onSignal = async signal => {
      if (stopping) return;
      stopping = true;
      console.log(JSON.stringify({ service: supervisor.state.service, action: 'shutting_down', signal }));
      await supervisor.shutdown();
      process.exit(0);
    };

    for (const sig of signals) process.once(sig, () => onSignal(sig));
    void supervisor.engineExit.then(async status => {
      if (stopping) return;
      console.error(`Go engine exited unexpectedly (${status}).`);
      await supervisor.shutdown();
      process.exit(1);
    });
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}
