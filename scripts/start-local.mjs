#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { readFile, access, stat } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import http from 'node:http';
import { createWebServer } from './serve-web.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..');

export async function checkEngineHealth(host, port, timeoutMs = 5000) {
  const start = Date.now();
  const url = `http://${host}:${port}/healthz`;

  while (Date.now() - start < timeoutMs) {
    try {
      const ok = await new Promise(resolvePromise => {
        const req = http.get(url, { timeout: 1000 }, res => {
          let data = '';
          res.on('data', chunk => { data += chunk; });
          res.on('end', () => {
            if (res.statusCode === 200) {
              try {
                const parsed = JSON.parse(data);
                resolvePromise(parsed.status === 'ok');
              } catch {
                resolvePromise(false);
              }
            } else {
              resolvePromise(false);
            }
          });
        });
        req.on('error', () => resolvePromise(false));
      });
      if (ok) return true;
    } catch {}
    await new Promise(r => setTimeout(r, 100));
  }
  return false;
}

export async function ensureEngineBinary(binaryPath) {
  try {
    await access(binaryPath);
    return true;
  } catch {
    // Attempt build with go
    const build = spawn('go', ['build', '-o', binaryPath, './cmd/breachatlas'], { cwd: root, stdio: 'pipe' });
    const code = await new Promise(resolvePromise => build.on('close', resolvePromise));
    return code === 0;
  }
}

export async function startSupervisor(options = {}) {
  const host = options.host || '127.0.0.1';
  const webPort = parseInt(options.port || '4173', 10);
  const enginePort = parseInt(options.enginePort || '8080', 10);
  const webRoot = resolve(root, options.root || 'dist/web');
  const configPath = resolve(root, options.config || 'ops/web/runtime-config.json');
  const engineBinary = resolve(root, options.engineBin || 'dist/bin/breachatlas');

  if (!['127.0.0.1', '::1', 'localhost'].includes(host)) {
    throw new Error(`Supervisor strictly forbids non-loopback host "${host}".`);
  }

  // 1. Ensure engine binary is available
  const built = await ensureEngineBinary(engineBinary);
  if (!built) {
    throw new Error(`Failed to locate or build Go engine binary at ${engineBinary}.`);
  }

  // 2. Spawn Go engine
  const engineProcess = spawn(engineBinary, ['--host', host, '--port', String(enginePort)], {
    cwd: root,
    stdio: options.engineStdio || 'inherit'
  });

  let engineExited = false;
  let exitCode = null;
  engineProcess.on('exit', code => {
    engineExited = true;
    exitCode = code;
  });

  // 3. Wait for engine health
  const healthy = await checkEngineHealth(host, enginePort, options.healthTimeoutMs || 5000);
  if (!healthy) {
    try { engineProcess.kill('SIGKILL'); } catch {}
    throw new Error(`Go engine failed to report healthy on ${host}:${enginePort} within timeout.`);
  }

  // 4. Start web server
  const product = JSON.parse(await readFile(resolve(root, 'ops/web/brand.json'), 'utf8'));
  const config = JSON.parse(await readFile(configPath, 'utf8'));
  await stat(resolve(webRoot, 'index.html'));

  const webServer = createWebServer({ root: webRoot, config, projectId: product.slug });
  webServer.maxRequestsPerSocket = 1000;

  await new Promise((resolvePromise, rejectPromise) => {
    webServer.once('error', rejectPromise);
    webServer.listen(webPort, host, resolvePromise);
  });

  const state = {
    service: `${product.slug}-unified-supervisor`,
    host,
    webPort,
    enginePort,
    status: 'ready',
    engineReady: true
  };

  const shutdown = async () => {
    // Close web server
    await new Promise(r => webServer.close(r));
    // Terminate engine child process
    if (!engineExited) {
      engineProcess.kill('SIGTERM');
      await new Promise(r => {
        const timer = setTimeout(() => {
          if (!engineExited) engineProcess.kill('SIGKILL');
          r();
        }, 3000);
        engineProcess.once('exit', () => {
          clearTimeout(timer);
          r();
        });
      });
    }
  };

  return { state, webServer, engineProcess, shutdown };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const args = process.argv.slice(2);
  const options = {
    host: '127.0.0.1',
    port: '4173',
    enginePort: '8080',
    root: 'dist/web',
    config: 'ops/web/runtime-config.json',
    engineBin: 'dist/bin/breachatlas'
  };

  for (let i = 0; i < args.length; i += 2) {
    const key = args[i].slice(2);
    if (!args[i].startsWith('--') || !Object.hasOwn(options, key) || !args[i + 1]) {
      console.error('Usage: node scripts/start-local.mjs [--host 127.0.0.1] [--port 4173] [--enginePort 8080] [--root dist/web] [--config path]');
      process.exit(1);
    }
    options[key] = args[i + 1];
  }

  try {
    const supervisor = await startSupervisor(options);
    console.log(JSON.stringify(supervisor.state));

    let stopping = false;
    const onSignal = async signal => {
      if (stopping) return;
      stopping = true;
      console.log(JSON.stringify({ service: supervisor.state.service, action: 'shutting_down', signal }));
      await supervisor.shutdown();
      process.exit(0);
    };

    for (const sig of ['SIGINT', 'SIGTERM']) {
      process.once(sig, () => onSignal(sig));
    }
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}
