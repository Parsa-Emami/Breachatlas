#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { lstat, readdir, readFile, writeFile } from 'node:fs/promises';
import { basename, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';

const SIGNATURE_DOMAIN_PREFIX = 'breachatlas:release-provenance:v1:';
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const ALLOWED_LICENSES = new Set([
  'Apache-2.0',
  'MIT',
  'BSD-3-Clause',
  'BSD-2-Clause',
  'ISC',
  'MPL-2.0',
  'Artistic-2.0',
]);
const REQUIRED_REL_PATHS = [
  'bin/breachatlas',
  'bin/verify',
  'web/index.html',
  'source/breachatlas-source.tar.gz',
  'source/BUILD_RECIPE.json',
  'sbom.spdx.json',
  'THIRD_PARTY_NOTICES.md',
  'ops/web/nginx.conf.template',
  'ops/web/service.systemd',
  'ops/runtime-requirements.json',
  'docs/engineering/toolchain-lock.json',
  'docs/release/ARTIFACTS.md',
  'LICENSE',
  'NOTICE',
];

export class ReleaseVerificationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ReleaseVerificationError';
    this.code = code;
  }
}

function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

function serializeComponentDigest(comp) {
  if (!comp || typeof comp !== 'object') {
    throw new ReleaseVerificationError('incomplete_release_artifact', 'Missing component entry in release.json');
  }
  const out = {
    path: String(comp.path || ''),
    sha256: String(comp.sha256 || ''),
  };
  if (typeof comp.packageCount === 'number' && comp.packageCount !== 0) {
    out.packageCount = comp.packageCount;
  }
  return out;
}

export function canonicalManifestPayload(manifest) {
  const c = manifest.components || {};
  const ordered = {
    schemaVersion: String(manifest.schemaVersion || ''),
    project: String(manifest.project || ''),
    scope: String(manifest.scope || ''),
  };
  if (manifest.releaseVersion) {
    ordered.releaseVersion = String(manifest.releaseVersion);
  }
  ordered.engineReady = Boolean(manifest.engineReady);
  ordered.offlineVerifierReady = Boolean(manifest.offlineVerifierReady);
  ordered.reproducible = Boolean(manifest.reproducible);
  ordered.sourceCommit = String(manifest.sourceCommit || '');
  ordered.dirty = Boolean(manifest.dirty);
  ordered.components = {
    engineBinary: serializeComponentDigest(c.engineBinary),
    offlineVerifier: serializeComponentDigest(c.offlineVerifier),
    webUi: serializeComponentDigest(c.webUi),
    sourceArchive: serializeComponentDigest(c.sourceArchive),
    buildRecipe: serializeComponentDigest(c.buildRecipe),
    sbom: serializeComponentDigest(c.sbom),
    thirdPartyNotices: serializeComponentDigest(c.thirdPartyNotices),
    nginxTemplate: serializeComponentDigest(c.nginxTemplate),
    systemdUnit: serializeComponentDigest(c.systemdUnit),
  };
  if (manifest.provenanceKeyId) {
    ordered.provenanceKeyId = String(manifest.provenanceKeyId);
  }
  if (manifest.provenancePublicKey) {
    ordered.provenancePublicKey = String(manifest.provenancePublicKey);
  }
  if (typeof manifest.provenanceRevision === 'number' && manifest.provenanceRevision !== 0) {
    ordered.provenanceRevision = manifest.provenanceRevision;
  }
  if (manifest.provenanceIssuedAt) {
    ordered.provenanceIssuedAt = String(manifest.provenanceIssuedAt);
  }
  if (manifest.provenanceExpiresAt) {
    ordered.provenanceExpiresAt = String(manifest.provenanceExpiresAt);
  }
  return Buffer.from(SIGNATURE_DOMAIN_PREFIX + JSON.stringify(ordered), 'utf8');
}

function publicKeyFromHex(hexStr) {
  const raw = Buffer.from(String(hexStr || ''), 'hex');
  if (raw.length !== 32) {
    throw new ReleaseVerificationError('signature_invalid', 'Invalid Ed25519 public key length');
  }
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });
}

function privateKeyAndPubHex(privHexStr) {
  const raw = Buffer.from(String(privHexStr || ''), 'hex');
  if (raw.length !== 32 && raw.length !== 64) {
    throw new ReleaseVerificationError('signature_invalid', 'Invalid Ed25519 private key length');
  }
  const seed = raw.subarray(0, 32);
  const privKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const pubSpki = createPublicKey(privKey).export({ format: 'der', type: 'spki' });
  const pubHex = pubSpki.subarray(ED25519_SPKI_PREFIX.length).toString('hex');
  return { privKey, pubHex };
}

async function ensureSafeRegularFile(baseDir, relPath) {
  if (!relPath || isAbsolute(relPath) || relPath.split(/[\\/]/).includes('..')) {
    throw new ReleaseVerificationError('invalid_release_path', `Unsafe relative path rejected: ${relPath}`);
  }
  let cur = baseDir;
  for (const part of relPath.split('/').filter(Boolean)) {
    cur = join(cur, part);
    let st;
    try {
      st = await lstat(cur);
    } catch (err) {
      throw new ReleaseVerificationError('incomplete_release_artifact', `Missing required deliverable ${relPath}: ${err.message}`);
    }
    if (st.isSymbolicLink()) {
      throw new ReleaseVerificationError('invalid_release_path', `Symlink rejected in release tree: ${relPath}`);
    }
  }
  const finalStat = await lstat(cur);
  if (!finalStat.isFile()) {
    throw new ReleaseVerificationError('incomplete_release_artifact', `${relPath} is not a regular file`);
  }
  return { absPath: cur, stat: finalStat };
}

async function collectActualFiles(dir) {
  const files = new Map();
  async function walk(curDir, prefix = '') {
    const entries = await readdir(curDir, { withFileTypes: true });
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      const rel = prefix + entry.name;
      const abs = join(curDir, entry.name);
      const st = await lstat(abs);
      if (st.isSymbolicLink()) {
        throw new ReleaseVerificationError('invalid_release_path', `Symlink rejected in release tree: ${rel}`);
      }
      if (st.isDirectory()) {
        await walk(abs, rel + '/');
      } else if (st.isFile() && rel !== 'SHA256SUMS.txt') {
        files.set(rel, sha256Hex(await readFile(abs)));
      }
    }
  }
  await walk(dir);
  return files;
}

export async function verifyChecksumsFile(dir) {
  const sumsFile = await ensureSafeRegularFile(dir, 'SHA256SUMS.txt').catch(err => {
    if (err.code === 'incomplete_release_artifact') {
      throw new ReleaseVerificationError('checksum_mismatch', err.message);
    }
    throw err;
  });
  const raw = await readFile(sumsFile.absPath, 'utf8');
  const recorded = new Map();
  for (const line of raw.replace(/\r\n/g, '\n').split('\n')) {
    if (!line.trim()) continue;
    const idx = line.indexOf('  ');
    if (idx !== 64) {
      throw new ReleaseVerificationError('checksum_mismatch', `Malformed SHA256SUMS line: ${line}`);
    }
    const digest = line.slice(0, 64);
    const rel = line.slice(66).replace(/\\/g, '/');
    if (!/^[a-f0-9]{64}$/.test(digest)) {
      throw new ReleaseVerificationError('checksum_mismatch', `Invalid digest in SHA256SUMS: ${line}`);
    }
    if (!rel || isAbsolute(rel) || rel.split('/').includes('..')) {
      throw new ReleaseVerificationError('invalid_release_path', `Unsafe checksum path: ${rel}`);
    }
    recorded.set(rel, digest);
  }

  const actual = await collectActualFiles(dir);
  if (recorded.size !== actual.size) {
    throw new ReleaseVerificationError(
      'checksum_mismatch',
      `Checksum count (${recorded.size}) does not match actual files (${actual.size})`
    );
  }
  for (const [rel, expected] of recorded.entries()) {
    const got = actual.get(rel);
    if (!got) {
      throw new ReleaseVerificationError('checksum_mismatch', `Missing file listed in SHA256SUMS.txt: ${rel}`);
    }
    if (got !== expected) {
      throw new ReleaseVerificationError('checksum_mismatch', `SHA-256 mismatch for ${rel}`);
    }
  }
  return actual.size;
}

function verifyTarGzContainsBuildFiles(gzBuf) {
  const tar = gunzipSync(gzBuf);
  let offset = 0;
  let files = 0;
  let hasGoMod = false;
  let hasPkgJson = false;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every(b => b === 0)) break;
    const rawName = header.subarray(0, 100).toString('utf8').replace(/\0.*$/, '');
    const rawPrefix = header.subarray(345, 500).toString('utf8').replace(/\0.*$/, '');
    const fullName = rawPrefix ? `${rawPrefix}/${rawName}` : rawName;
    if (isAbsolute(fullName) || fullName.split(/[\\/]/).includes('..')) {
      throw new ReleaseVerificationError('invalid_release_path', `Unsafe tar entry: ${fullName}`);
    }
    const sizeOct = header.subarray(124, 136).toString('ascii').replace(/\0.*$/, '').trim();
    const size = sizeOct ? Number.parseInt(sizeOct, 8) : 0;
    if (fullName === 'go.mod') hasGoMod = true;
    if (fullName === 'package.json') hasPkgJson = true;
    files++;
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  if (files === 0 || !hasGoMod || !hasPkgJson) {
    throw new ReleaseVerificationError('incomplete_release_artifact', 'Source archive missing go.mod or package.json');
  }
  return files;
}

export async function signReleaseDirectory(dir, options) {
  const absDir = resolve(dir);
  const {
    privateKeyHex,
    keyId,
    releaseVersion,
    revision,
    issuedAt = new Date().toISOString(),
    expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
  } = options;
  if (!keyId) {
    throw new ReleaseVerificationError('signature_invalid', 'keyId is required to sign release');
  }
  if (!Number.isInteger(revision) || revision < 1) {
    throw new ReleaseVerificationError('stale_or_expired_revision', 'revision must be an integer >= 1');
  }
  const { privKey, pubHex } = privateKeyAndPubHex(privateKeyHex);
  const manifestPath = join(absDir, 'release.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  const annotated = {
    ...manifest,
    releaseVersion: String(releaseVersion || manifest.releaseVersion || '0.1.0'),
    provenanceKeyId: String(keyId),
    provenancePublicKey: pubHex,
    provenanceRevision: revision,
    provenanceIssuedAt: new Date(issuedAt).toISOString().replace('.000Z', 'Z'),
    provenanceExpiresAt: new Date(expiresAt).toISOString().replace('.000Z', 'Z'),
  };
  delete annotated.provenanceSignature;
  const payload = canonicalManifestPayload(annotated);
  const sigHex = cryptoSign(null, payload, privKey).toString('hex');
  annotated.provenanceSignature = sigHex;
  await writeFile(manifestPath, JSON.stringify(annotated, null, 2) + '\n', 'utf8');

  const files = await collectActualFiles(absDir);
  const lines = [...files.entries()]
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .map(([rel, sum]) => `${sum}  ${rel}`);
  await writeFile(join(absDir, 'SHA256SUMS.txt'), lines.join('\n') + '\n', 'utf8');
  return annotated;
}

export async function verifyReleaseArtifact(dir, options = {}) {
  const absDir = resolve(dir);
  const {
    trustedKeys = {},
    requireSignature = true,
    minRevision = 1,
    now = new Date().toISOString(),
  } = options;

  const rootStat = await lstat(absDir).catch(err => {
    throw new ReleaseVerificationError('incomplete_release_artifact', `Missing release directory: ${err.message}`);
  });
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
    throw new ReleaseVerificationError('invalid_release_path', 'Release path must be a real directory');
  }

  const manifestFile = await ensureSafeRegularFile(absDir, 'release.json');
  let manifest;
  try {
    manifest = JSON.parse(await readFile(manifestFile.absPath, 'utf8'));
  } catch (err) {
    throw new ReleaseVerificationError('incomplete_release_artifact', `Malformed release.json: ${err.message}`);
  }
  if (
    manifest.project !== 'BreachAtlas' ||
    manifest.scope !== 'complete-open-source' ||
    manifest.engineReady !== true ||
    manifest.offlineVerifierReady !== true
  ) {
    throw new ReleaseVerificationError('incomplete_release_artifact', 'Release manifest is incomplete or web-only');
  }

  // Verify independent trusted Ed25519 signer and signature.
  let signatureVerified = false;
  if (requireSignature || manifest.provenanceSignature) {
    if (!manifest.provenanceSignature) {
      throw new ReleaseVerificationError('signature_invalid', 'Missing Ed25519 provenance signature');
    }
    const keyHex = trustedKeys[manifest.provenanceKeyId];
    if (!keyHex) {
      throw new ReleaseVerificationError(
        'signature_invalid',
        `Untrusted or unknown provenanceKeyId: ${manifest.provenanceKeyId || '<empty>'}`
      );
    }
    if (manifest.provenancePublicKey && manifest.provenancePublicKey !== keyHex) {
      throw new ReleaseVerificationError('signature_invalid', 'Manifest public key does not match trusted key');
    }
    const pubKey = publicKeyFromHex(keyHex);
    const sigBuf = Buffer.from(String(manifest.provenanceSignature), 'hex');
    if (sigBuf.length !== 64) {
      throw new ReleaseVerificationError('signature_invalid', 'Malformed Ed25519 signature hex');
    }
    const payload = canonicalManifestPayload(manifest);
    if (!cryptoVerify(null, payload, pubKey, sigBuf)) {
      throw new ReleaseVerificationError('signature_invalid', 'Ed25519 signature verification failed');
    }
    signatureVerified = true;

    const revision = Number(manifest.provenanceRevision || 0);
    if (!Number.isInteger(revision) || revision < minRevision) {
      throw new ReleaseVerificationError(
        'stale_or_expired_revision',
        `Release revision ${revision} is below minimum accepted authority ${minRevision}`
      );
    }
    const expiresMs = Date.parse(manifest.provenanceExpiresAt || '');
    const nowMs = Date.parse(now);
    if (!Number.isFinite(expiresMs) || !Number.isFinite(nowMs) || expiresMs <= nowMs) {
      throw new ReleaseVerificationError(
        'stale_or_expired_revision',
        `Release expired or has invalid expiration (${manifest.provenanceExpiresAt})`
      );
    }
    if (manifest.provenanceIssuedAt) {
      const issuedMs = Date.parse(manifest.provenanceIssuedAt);
      if (!Number.isFinite(issuedMs) || expiresMs <= issuedMs) {
        throw new ReleaseVerificationError('stale_or_expired_revision', 'Invalid provenance issuance/expiry window');
      }
    }
  }

  for (const rel of REQUIRED_REL_PATHS) {
    const info = await ensureSafeRegularFile(absDir, rel);
    if ((rel === 'bin/breachatlas' || rel === 'bin/verify') && (info.stat.mode & 0o111) === 0) {
      throw new ReleaseVerificationError('incomplete_release_artifact', `Packaged binary ${rel} is not executable`);
    }
  }

  for (const comp of Object.values(manifest.components || {})) {
    const compFile = await ensureSafeRegularFile(absDir, comp.path);
    const actualHash = sha256Hex(await readFile(compFile.absPath));
    if (comp.sha256 && actualHash !== comp.sha256) {
      throw new ReleaseVerificationError('checksum_mismatch', `Component ${comp.path} digest mismatch`);
    }
  }

  const sbomDoc = JSON.parse(await readFile(join(absDir, 'sbom.spdx.json'), 'utf8'));
  if (sbomDoc.spdxVersion !== 'SPDX-2.3' || !Array.isArray(sbomDoc.packages) || sbomDoc.packages.length === 0) {
    throw new ReleaseVerificationError('incomplete_release_artifact', 'Invalid SPDX-2.3 SBOM');
  }
  for (const pkg of sbomDoc.packages) {
    const lic = String(pkg.licenseConcluded || pkg.licenseDeclared || '').trim();
    if (!ALLOWED_LICENSES.has(lic)) {
      throw new ReleaseVerificationError('restricted_license', `Disallowed license ${lic} on ${pkg.name}`);
    }
  }

  const archiveBuf = await readFile(join(absDir, 'source', 'breachatlas-source.tar.gz'));
  const sourceArchiveFiles = verifyTarGzContainsBuildFiles(archiveBuf);
  const recipe = JSON.parse(await readFile(join(absDir, 'source', 'BUILD_RECIPE.json'), 'utf8'));
  if (!recipe.reproducible || !Array.isArray(recipe.buildCommands) || recipe.buildCommands.length === 0) {
    throw new ReleaseVerificationError('incomplete_release_artifact', 'Incomplete source/BUILD_RECIPE.json');
  }
  if (recipe.archiveSha256 && recipe.archiveSha256 !== sha256Hex(archiveBuf)) {
    throw new ReleaseVerificationError('checksum_mismatch', 'BUILD_RECIPE archiveSha256 mismatch');
  }

  const verifiedFiles = await verifyChecksumsFile(absDir);

  return {
    valid: true,
    scope: manifest.scope,
    releaseVersion: manifest.releaseVersion || '',
    provenanceKeyId: manifest.provenanceKeyId || '',
    provenanceRevision: manifest.provenanceRevision || 0,
    signatureVerified,
    verifiedFiles,
    sbomPackages: sbomDoc.packages.length,
    sourceArchiveFiles,
    sourceBuildRecipeReady: true,
    sourceCommit: manifest.sourceCommit,
  };
}

function parseCliArgs(argv) {
  const opts = { trustedKeys: {}, minRevision: 1, requireSignature: true };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--dir' && argv[i + 1]) opts.dir = argv[++i];
    else if (arg === '--trusted-key' && argv[i + 1]) opts.trustedKeyHex = argv[++i];
    else if (arg === '--key-id' && argv[i + 1]) opts.keyId = argv[++i];
    else if (arg === '--min-revision' && argv[i + 1]) opts.minRevision = Number(argv[++i]);
    else if (arg === '--now' && argv[i + 1]) opts.now = argv[++i];
    else if (arg === '--allow-unsigned') opts.requireSignature = false;
    else {
      throw new Error(`Usage: node ${basename(argv[1] || 'verify-release.mjs')} --dir <releaseDir> [--trusted-key <hex> --key-id <id>] [--min-revision <n>] [--now <iso>] [--allow-unsigned]`);
    }
  }
  if (opts.trustedKeyHex && opts.keyId) {
    opts.trustedKeys[opts.keyId] = opts.trustedKeyHex;
  }
  return opts;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const cli = parseCliArgs(process.argv.slice(2));
    if (!cli.dir) throw new Error('--dir <releaseDir> is required');
    if (cli.trustedKeyHex && !cli.keyId) {
      const m = JSON.parse(await readFile(join(resolve(cli.dir), 'release.json'), 'utf8'));
      if (m.provenanceKeyId) cli.trustedKeys[m.provenanceKeyId] = cli.trustedKeyHex;
    }
    const res = await verifyReleaseArtifact(cli.dir, cli);
    console.log(JSON.stringify(res, null, 2));
  } catch (err) {
    console.error(JSON.stringify({ valid: false, code: err.code || 'verification_failed', error: err.message }));
    process.exitCode = 1;
  }
}
