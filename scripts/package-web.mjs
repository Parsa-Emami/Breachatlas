#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { chmod, cp, mkdir, readdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { packageSourceArtifacts } from './package-source.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const defaultRoot = resolve(__dirname, '..');

async function fileSha256(filePath) {
  const data = await readFile(filePath);
  return createHash('sha256').update(data).digest('hex');
}

async function ensureBinary(rootDir, outRelPath, pkgTarget) {
  const absOut = join(rootDir, outRelPath);
  let needsBuild = false;
  try {
    const info = await stat(absOut);
    if (!info.isFile() || info.size === 0) needsBuild = true;
  } catch {
    needsBuild = true;
  }
  if (needsBuild) {
    await mkdir(dirname(absOut), { recursive: true });
    execFileSync('go', ['build', '-trimpath', '-buildvcs=false', '-o', absOut, pkgTarget], {
      cwd: rootDir,
      stdio: 'inherit',
    });
  }
  return absOut;
}

async function collectChecksums(rootDir) {
  const lines = [];
  async function walk(dir, prefix = '') {
    const entries = await readdir(dir, { withFileTypes: true });
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      const rel = prefix + entry.name;
      const abs = join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(abs, rel + '/');
      } else if (entry.isFile() && rel !== 'SHA256SUMS.txt') {
        lines.push(`${await fileSha256(abs)}  ${rel}`);
      }
    }
  }
  await walk(rootDir);
  return lines;
}

export async function packageCompleteRelease(options = {}) {
  const rootDir = resolve(options.rootDir || defaultRoot);
  const outputDir = resolve(options.outputDir || join(rootDir, 'dist', 'release'));
  const outputParent = dirname(outputDir);
  await mkdir(outputParent, { recursive: true });

  // Validate web assets exist before staging.
  const webIndex = join(rootDir, 'dist', 'web', 'index.html');
  try {
    const info = await stat(webIndex);
    if (!info.isFile()) throw new Error('not a file');
  } catch {
    throw new Error('dist/web/index.html missing; run npm run build before packaging release.');
  }

  // Ensure both Go engine and standalone offline verifier binaries exist.
  const engineBinSrc = await ensureBinary(rootDir, 'dist/bin/breachatlas', './cmd/breachatlas');
  const verifierBinSrc = await ensureBinary(rootDir, 'dist/bin/verify', './cmd/verify');

  const stagingDir = join(outputParent, `.release-staging-${process.pid}-${Date.now()}`);
  const backupDir = join(outputParent, `.release-backup-${process.pid}-${Date.now()}`);
  await rm(stagingDir, { recursive: true, force: true });
  await mkdir(stagingDir, { recursive: true });

  try {
    // 1. Web UI & scripts & config validator
    await cp(join(rootDir, 'dist', 'web'), join(stagingDir, 'web'), { recursive: true });
    await cp(join(rootDir, 'scripts', 'serve-web.mjs'), join(stagingDir, 'scripts', 'serve-web.mjs'));
    await cp(join(rootDir, 'scripts', 'start-local.mjs'), join(stagingDir, 'scripts', 'start-local.mjs'));
    await cp(
      join(rootDir, 'apps', 'web', 'src', 'lib', 'runtime-config.mjs'),
      join(stagingDir, 'apps', 'web', 'src', 'lib', 'runtime-config.mjs')
    );

    // 2. Compiled Go engine + offline verifier binaries
    await mkdir(join(stagingDir, 'bin'), { recursive: true });
    await cp(engineBinSrc, join(stagingDir, 'bin', 'breachatlas'));
    await chmod(join(stagingDir, 'bin', 'breachatlas'), 0o755);
    await cp(verifierBinSrc, join(stagingDir, 'bin', 'verify'));
    await chmod(join(stagingDir, 'bin', 'verify'), 0o755);

    // 3. Ops templates, runtime requirements, contracts/offline rules, and notices
    await cp(join(rootDir, 'ops', 'web'), join(stagingDir, 'ops', 'web'), { recursive: true });
    await cp(join(rootDir, 'ops', 'runtime-requirements.json'), join(stagingDir, 'ops', 'runtime-requirements.json'));
    await cp(join(rootDir, 'ops', 'deployment-profiles.json'), join(stagingDir, 'ops', 'deployment-profiles.json'));
    await cp(join(rootDir, 'docs', 'engineering', 'toolchain-lock.json'), join(stagingDir, 'docs', 'engineering', 'toolchain-lock.json'));
    await cp(join(rootDir, 'docs', 'engineering', 'WEB_RUNBOOK.md'), join(stagingDir, 'docs', 'engineering', 'WEB_RUNBOOK.md'));
    await cp(join(rootDir, 'docs', 'release', 'ARTIFACTS.md'), join(stagingDir, 'docs', 'release', 'ARTIFACTS.md'));
    await cp(join(rootDir, 'contracts'), join(stagingDir, 'contracts'), { recursive: true });
    await cp(join(rootDir, 'LICENSE'), join(stagingDir, 'LICENSE'));
    await cp(join(rootDir, 'NOTICE'), join(stagingDir, 'NOTICE'));
    await cp(join(rootDir, 'THIRD_PARTY_NOTICES.md'), join(stagingDir, 'THIRD_PARTY_NOTICES.md'));
    await cp(join(rootDir, 'docs', 'engineering', 'WEB_RUNBOOK.md'), join(stagingDir, 'README.md'));

    // 4. Deterministic source archive, BUILD_RECIPE.json, source-manifest.json, and SPDX SBOM
    const sourceMeta = await packageSourceArtifacts({ rootDir, outputDir: stagingDir });

    // 5. Complete-product provenance manifest (release.json)
    const releaseManifest = {
      schemaVersion: '1',
      project: 'BreachAtlas',
      scope: 'complete-open-source',
      engineReady: true,
      offlineVerifierReady: true,
      reproducible: true,
      sourceCommit: sourceMeta.sourceCommit,
      dirty: sourceMeta.dirty,
      components: {
        engineBinary: {
          path: 'bin/breachatlas',
          sha256: await fileSha256(join(stagingDir, 'bin', 'breachatlas')),
        },
        offlineVerifier: {
          path: 'bin/verify',
          sha256: await fileSha256(join(stagingDir, 'bin', 'verify')),
        },
        webUi: {
          path: 'web/index.html',
          sha256: await fileSha256(join(stagingDir, 'web', 'index.html')),
        },
        sourceArchive: {
          path: 'source/breachatlas-source.tar.gz',
          sha256: sourceMeta.archiveSha256,
        },
        buildRecipe: {
          path: 'source/BUILD_RECIPE.json',
          sha256: sourceMeta.buildRecipeSha256,
        },
        sbom: {
          path: 'sbom.spdx.json',
          sha256: sourceMeta.sbomSha256,
          packageCount: sourceMeta.sbomPackageCount,
        },
        thirdPartyNotices: {
          path: 'THIRD_PARTY_NOTICES.md',
          sha256: await fileSha256(join(stagingDir, 'THIRD_PARTY_NOTICES.md')),
        },
        nginxTemplate: {
          path: 'ops/web/nginx.conf.template',
          sha256: await fileSha256(join(stagingDir, 'ops', 'web', 'nginx.conf.template')),
        },
        systemdUnit: {
          path: 'ops/web/service.systemd',
          sha256: await fileSha256(join(stagingDir, 'ops', 'web', 'service.systemd')),
        },
      },
    };
    await writeFile(join(stagingDir, 'release.json'), JSON.stringify(releaseManifest, null, 2) + '\n', 'utf8');

    // 6. Sorted SHA256SUMS.txt over staged release tree
    const checksumLines = await collectChecksums(stagingDir);
    await writeFile(join(stagingDir, 'SHA256SUMS.txt'), checksumLines.join('\n') + '\n', 'utf8');

    // 7. Atomic swap into final outputDir
    let hadExisting = false;
    try {
      await stat(outputDir);
      hadExisting = true;
    } catch {
      hadExisting = false;
    }

    if (hadExisting) {
      await rename(outputDir, backupDir);
    }
    try {
      await rename(stagingDir, outputDir);
      if (hadExisting) {
        await rm(backupDir, { recursive: true, force: true });
      }
    } catch (swapErr) {
      if (hadExisting) {
        await rename(backupDir, outputDir).catch(() => {});
      }
      throw swapErr;
    }

    return {
      outputDir,
      fileCount: checksumLines.length,
      releaseManifest,
    };
  } catch (err) {
    await rm(stagingDir, { recursive: true, force: true }).catch(() => {});
    throw err;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const result = await packageCompleteRelease();
  console.log(
    `Packaged complete open-source release (${result.fileCount} files); ` +
      `source dirty=${result.releaseManifest.dirty}; engineReady=${result.releaseManifest.engineReady}; ` +
      `offlineVerifierReady=${result.releaseManifest.offlineVerifierReady}`
  );
}
