#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { gzipSync } from 'node:zlib';

const __dirname = dirname(fileURLToPath(import.meta.url));
const defaultRoot = resolve(__dirname, '..');

export const ALLOWED_LICENSES = new Set([
  'Apache-2.0',
  'MIT',
  'BSD-3-Clause',
  'BSD-2-Clause',
  'ISC',
  'MPL-2.0',
  'Artistic-2.0',
]);

function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

function splitTarPath(relPath) {
  const clean = relPath.replace(/\\/g, '/').replace(/^\/+/, '');
  if (Buffer.byteLength(clean, 'utf8') <= 100) {
    return { name: clean, prefix: '' };
  }
  const parts = clean.split('/');
  for (let i = parts.length - 1; i > 0; i--) {
    const prefix = parts.slice(0, i).join('/');
    const name = parts.slice(i).join('/');
    if (Buffer.byteLength(name, 'utf8') <= 100 && Buffer.byteLength(prefix, 'utf8') <= 155) {
      return { name, prefix };
    }
  }
  throw new Error(`Path exceeds POSIX ustar limits: ${relPath}`);
}

function writeOctalField(buf, offset, length, value) {
  const oct = value.toString(8).padStart(length - 1, '0') + '\0';
  if (oct.length > length) {
    throw new Error(`Value ${value} overflows tar octal field of length ${length}`);
  }
  buf.write(oct, offset, length, 'ascii');
}

function createUstarHeader(relPath, size, isExecutable) {
  const { name, prefix } = splitTarPath(relPath);
  const header = Buffer.alloc(512, 0);
  header.write(name, 0, Math.min(Buffer.byteLength(name, 'utf8'), 100), 'utf8');
  writeOctalField(header, 100, 8, isExecutable ? 0o755 : 0o644);
  writeOctalField(header, 108, 8, 0);
  writeOctalField(header, 116, 8, 0);
  writeOctalField(header, 124, 12, size);
  writeOctalField(header, 136, 12, 0); // Deterministic epoch mtime
  header.fill(0x20, 148, 156); // Checksum placeholder spaces
  header.write('0', 156, 1, 'ascii'); // Regular file
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  if (prefix) {
    header.write(prefix, 345, Math.min(Buffer.byteLength(prefix, 'utf8'), 155), 'utf8');
  }
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += header[i];
  header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
  return header;
}

export async function createDeterministicTarGz(rootDir) {
  const rawList = execFileSync('git', ['ls-files', '-z'], { cwd: rootDir });
  const paths = rawList
    .toString('utf8')
    .split('\0')
    .filter(Boolean)
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

  const chunks = [];
  const manifestFiles = [];

  for (const relPath of paths) {
    const absPath = join(rootDir, relPath);
    const info = await stat(absPath);
    if (!info.isFile()) continue;
    const data = await readFile(absPath);
    const isExec = (info.mode & 0o111) !== 0;
    const header = createUstarHeader(relPath, data.length, isExec);
    chunks.push(header, data);
    const rem = data.length % 512;
    if (rem !== 0) {
      chunks.push(Buffer.alloc(512 - rem, 0));
    }
    manifestFiles.push({
      path: relPath,
      sizeBytes: data.length,
      mode: isExec ? '0755' : '0644',
      sha256: sha256Hex(data),
    });
  }

  // Two 512-byte zero blocks terminate the tar archive.
  chunks.push(Buffer.alloc(1024, 0));
  const tarBuffer = Buffer.concat(chunks);
  // Deterministic zlib compression; OS byte patched to Unix (3) for cross-host stability.
  const gzBuffer = gzipSync(tarBuffer, { level: 9 });
  if (gzBuffer.length >= 10) {
    gzBuffer[9] = 3;
  }
  return { gzBuffer, manifestFiles, fileCount: manifestFiles.length };
}

export async function generateSpdxSbom(rootDir, sourceCommit, dirty) {
  const pkgLock = JSON.parse(await readFile(join(rootDir, 'package-lock.json'), 'utf8'));
  const toolchainLock = JSON.parse(await readFile(join(rootDir, 'docs/engineering/toolchain-lock.json'), 'utf8'));
  const goMod = await readFile(join(rootDir, 'go.mod'), 'utf8');
  const goVerMatch = goMod.match(/^go\s+([0-9.]+)/m);
  const goMinVersion = goVerMatch ? goVerMatch[1] : toolchainLock.runtimes.go.version;

  const packages = [
    {
      name: 'github.com/Parsa-Emami/Breachatlas',
      SPDXID: 'SPDXRef-Package-BreachAtlas',
      versionInfo: `${pkgLock.version || '0.0.1'}+git.${sourceCommit.slice(0, 12)}`,
      downloadLocation: 'https://github.com/Parsa-Emami/Breachatlas',
      filesAnalyzed: false,
      licenseConcluded: 'Apache-2.0',
      licenseDeclared: 'Apache-2.0',
      supplier: 'Organization: BreachAtlas Contributors',
      comment: `Engine language Go ${goMinVersion}; working tree dirty=${dirty}`,
    },
  ];

  // Validate and include runtime dependencies from toolchain-lock.json
  for (const [runtimeName, meta] of Object.entries(toolchainLock.runtimes || {})) {
    if (!meta.license || !ALLOWED_LICENSES.has(meta.license)) {
      throw new Error(`Disallowed or missing license for runtime ${runtimeName}: ${meta.license}`);
    }
    packages.push({
      name: `runtime/${runtimeName}`,
      SPDXID: `SPDXRef-Runtime-${runtimeName}`,
      versionInfo: String(meta.version),
      downloadLocation: meta.official_source || 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: meta.license,
      licenseDeclared: meta.license,
      checksums: meta.digest && meta.digest.startsWith('sha256:')
        ? [{ algorithm: 'SHA256', checksumValue: meta.digest.slice(7) }]
        : undefined,
    });
  }

  // Validate and include Go stdlib engine libraries recorded in toolchain-lock.json
  for (const [libName, meta] of Object.entries(toolchainLock.engine_libraries || {})) {
    if (!meta.license || !ALLOWED_LICENSES.has(meta.license)) {
      throw new Error(`Disallowed or missing license for engine library ${libName}: ${meta.license}`);
    }
    packages.push({
      name: `go-stdlib/${libName}`,
      SPDXID: `SPDXRef-GoStdlib-${libName.replace(/[^A-Za-z0-9.-]/g, '-')}`,
      versionInfo: `go-${goMinVersion}`,
      downloadLocation: meta.official_source || 'https://pkg.go.dev/std',
      filesAnalyzed: false,
      licenseConcluded: meta.license,
      licenseDeclared: meta.license,
    });
  }

  // Validate and include every locked npm package from package-lock.json
  const lockPackages = pkgLock.packages || {};
  const sortedEntries = Object.entries(lockPackages)
    .filter(([pkgPath]) => pkgPath !== '')
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

  const seenSpdxIds = new Set(packages.map(p => p.SPDXID));
  for (const [pkgPath, meta] of sortedEntries) {
    const pkgName = meta.name || pkgPath.replace(/^.*node_modules\//, '');
    const license = meta.license;
    if (!license || !ALLOWED_LICENSES.has(license)) {
      throw new Error(`Restricted or unknown license in package-lock.json for ${pkgName}: ${license ?? 'missing'}`);
    }
    let spdxId = `SPDXRef-npm-${pkgName.replace(/[^A-Za-z0-9.-]/g, '-')}-${meta.version || '0'}`;
    while (seenSpdxIds.has(spdxId)) spdxId += '-dup';
    seenSpdxIds.add(spdxId);

    packages.push({
      name: pkgName,
      SPDXID: spdxId,
      versionInfo: String(meta.version || '0.0.0'),
      downloadLocation: meta.resolved || 'https://registry.npmjs.org/',
      filesAnalyzed: false,
      licenseConcluded: license,
      licenseDeclared: license,
      comment: meta.dev ? 'npm dev/build dependency' : 'npm runtime dependency',
    });
  }

  // Offline contracts and rules authored under Apache-2.0
  packages.push({
    name: 'breachatlas-offline-contracts-and-rules',
    SPDXID: 'SPDXRef-Offline-Rules',
    versionInfo: '1.0.0',
    downloadLocation: 'NOASSERTION',
    filesAnalyzed: false,
    licenseConcluded: 'Apache-2.0',
    licenseDeclared: 'Apache-2.0',
    comment: 'Includes contracts/*.json, contracts/*.yaml, internal/analyzers offline rules, and ops/runtime-requirements.json',
  });

  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `BreachAtlas-${sourceCommit.slice(0, 12)}`,
    documentNamespace: `https://breachatlas.local/spdx/${sourceCommit}`,
    creationInfo: {
      created: '1970-01-01T00:00:00Z',
      creators: ['Tool: breachatlas-package-source-1.0.0'],
      licenseListVersion: '3.25',
    },
    documentDescribes: ['SPDXRef-Package-BreachAtlas'],
    packages,
    relationships: packages.slice(1).map(p => ({
      spdxElementId: 'SPDXRef-Package-BreachAtlas',
      relationshipType: 'DEPENDS_ON',
      relatedSpdxElement: p.SPDXID,
    })),
  };
}

export async function packageSourceArtifacts(options = {}) {
  const rootDir = resolve(options.rootDir || defaultRoot);
  const outputDir = resolve(options.outputDir || join(rootDir, 'dist', 'release'));
  const sourceDir = join(outputDir, 'source');
  await mkdir(sourceDir, { recursive: true });

  let sourceCommit;
  try {
    sourceCommit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: rootDir, encoding: 'utf8' }).trim();
  } catch {
    throw new Error('Package source from a git checkout so provenance is explicit.');
  }
  const dirty = execFileSync('git', ['status', '--porcelain', '--untracked-files=normal'], { cwd: rootDir, encoding: 'utf8' }).trim() !== '';

  const { gzBuffer, manifestFiles, fileCount } = await createDeterministicTarGz(rootDir);
  const archiveName = 'breachatlas-source.tar.gz';
  const archivePath = join(sourceDir, archiveName);
  await writeFile(archivePath, gzBuffer);
  const archiveSha256 = sha256Hex(gzBuffer);

  const toolchainLock = JSON.parse(await readFile(join(rootDir, 'docs/engineering/toolchain-lock.json'), 'utf8'));
  const buildRecipe = {
    schemaVersion: '1',
    project: 'BreachAtlas',
    sourceCommit,
    dirty,
    archive: `source/${archiveName}`,
    archiveSha256,
    reproducible: true,
    requiredTools: {
      node: toolchainLock.runtimes.node.version,
      npm: toolchainLock.runtimes.npm.version,
      go: toolchainLock.runtimes.go.version,
    },
    buildCommands: [
      'npm ci --ignore-scripts --no-fund',
      'npm run build',
      'go build -trimpath -buildvcs=false -o dist/bin/breachatlas ./cmd/breachatlas',
      'go build -trimpath -buildvcs=false -o dist/bin/verify ./cmd/verify',
      'npm run package:web',
    ],
    verifyCommands: [
      'sha256sum -c SHA256SUMS.txt',
      './bin/breachatlas --version',
      './bin/verify --version',
    ],
  };
  const recipeText = JSON.stringify(buildRecipe, null, 2) + '\n';
  await writeFile(join(sourceDir, 'BUILD_RECIPE.json'), recipeText, 'utf8');

  const sourceManifest = {
    schemaVersion: '1',
    project: 'BreachAtlas',
    sourceCommit,
    dirty,
    fileCount,
    totalBytes: manifestFiles.reduce((acc, f) => acc + f.sizeBytes, 0),
    archiveSha256,
    files: manifestFiles,
  };
  const manifestText = JSON.stringify(sourceManifest, null, 2) + '\n';
  await writeFile(join(sourceDir, 'source-manifest.json'), manifestText, 'utf8');

  const sbom = await generateSpdxSbom(rootDir, sourceCommit, dirty);
  const sbomText = JSON.stringify(sbom, null, 2) + '\n';
  await writeFile(join(outputDir, 'sbom.spdx.json'), sbomText, 'utf8');

  return {
    sourceCommit,
    dirty,
    fileCount,
    archivePath,
    archiveSha256,
    buildRecipePath: join(sourceDir, 'BUILD_RECIPE.json'),
    buildRecipeSha256: sha256Hex(Buffer.from(recipeText, 'utf8')),
    sourceManifestPath: join(sourceDir, 'source-manifest.json'),
    sbomPath: join(outputDir, 'sbom.spdx.json'),
    sbomSha256: sha256Hex(Buffer.from(sbomText, 'utf8')),
    sbomPackageCount: sbom.packages.length,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const args = process.argv.slice(2);
  let outputDir;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--output' && args[i + 1]) {
      outputDir = args[++i];
    } else {
      console.error('Usage: node scripts/package-source.mjs [--output <dir>]');
      process.exit(1);
    }
  }
  const result = await packageSourceArtifacts({ outputDir });
  console.log(JSON.stringify({ packaged: 'source-and-sbom', ...result }));
}
