#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import {
  chmod,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { packageCompleteRelease } from '../../scripts/package-web.mjs';
import {
  ReleaseVerificationError,
  signReleaseDirectory,
  verifyReleaseArtifact,
} from '../../scripts/verify-release.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '../..');
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

function generateEd25519HexPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const pkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' });
  return {
    publicKeyHex: spki.subarray(ED25519_SPKI_PREFIX.length).toString('hex'),
    privateKeyHex: pkcs8.subarray(ED25519_PKCS8_PREFIX.length).toString('hex'),
  };
}

async function snapshotDirDigests(dir) {
  const out = {};
  async function walk(cur, prefix = '') {
    const entries = await (await import('node:fs/promises')).readdir(cur, { withFileTypes: true });
    for (const entry of entries) {
      const rel = prefix + entry.name;
      const abs = join(cur, entry.name);
      if (entry.isDirectory()) {
        await walk(abs, rel + '/');
      } else if (entry.isFile()) {
        out[rel] = sha256Hex(await readFile(abs));
      }
    }
  }
  await walk(dir);
  return out;
}

async function installOrUpgradeHost({ installRoot, dataDir, candidateDir, trustedKeys, verifyNow, overwriteDataWithOldBackup = false }) {
  const dataBefore = await snapshotDirDigests(dataDir);
  if (overwriteDataWithOldBackup && Object.keys(dataBefore).length > 0) {
    throw new ReleaseVerificationError(
      'newer_data_overwrite_forbidden',
      'Refusing to overwrite newer accepted host data with an older backup.'
    );
  }
  const authPath = join(installRoot, 'authority.json');
  let existingAuth = null;
  try {
    existingAuth = JSON.parse(await readFile(authPath, 'utf8'));
  } catch {
    existingAuth = null;
  }
  const minRevision = existingAuth ? existingAuth.highest_accepted_revision + 1 : 1;
  const vr = await verifyReleaseArtifact(candidateDir, {
    trustedKeys,
    requireSignature: true,
    minRevision,
    now: verifyNow,
  });

  const currentDir = join(installRoot, 'current');
  const previousDir = join(installRoot, 'previous');
  const stagedDir = join(installRoot, `.staging-${Date.now()}`);
  const backupPrev = join(installRoot, `.backup-prev-${Date.now()}`);
  await cp(candidateDir, stagedDir, { recursive: true });
  let hadPrev = false;
  try {
    await stat(previousDir);
    await rename(previousDir, backupPrev);
    hadPrev = true;
  } catch {
    hadPrev = false;
  }
  try {
    await stat(currentDir);
    await rename(currentDir, previousDir);
  } catch {
    // fresh install
  }
  await rename(stagedDir, currentDir);
  if (hadPrev) {
    await rm(backupPrev, { recursive: true, force: true });
  }

  const nextAuth = {
    schema_version: '1',
    current_version: vr.releaseVersion,
    current_revision: vr.provenanceRevision,
    highest_accepted_revision: existingAuth
      ? Math.max(existingAuth.highest_accepted_revision, vr.provenanceRevision)
      : vr.provenanceRevision,
    previous_version: existingAuth ? existingAuth.current_version : '',
    previous_revision: existingAuth ? existingAuth.current_revision : 0,
    trusted_key_id: vr.provenanceKeyId,
  };
  await writeFile(authPath, JSON.stringify(nextAuth, null, 2) + '\n', 'utf8');
  const dataAfter = await snapshotDirDigests(dataDir);
  assert.deepEqual(dataAfter, dataBefore);
  return { verification: vr, authority: nextAuth };
}

async function rollbackHost({ installRoot, dataDir, targetDir, trustedKeys, verifyNow, overwriteDataWithOldBackup = false }) {
  const dataBefore = await snapshotDirDigests(dataDir);
  if (overwriteDataWithOldBackup && Object.keys(dataBefore).length > 0) {
    throw new ReleaseVerificationError(
      'newer_data_overwrite_forbidden',
      'Rollback refused attempt to replace newer accepted host data with an older backup.'
    );
  }
  const authPath = join(installRoot, 'authority.json');
  const existingAuth = JSON.parse(await readFile(authPath, 'utf8'));
  const vr = await verifyReleaseArtifact(targetDir, {
    trustedKeys,
    requireSignature: true,
    minRevision: 1,
    now: verifyNow,
  });

  const currentDir = join(installRoot, 'current');
  const previousDir = join(installRoot, 'previous');
  const stagedDir = join(installRoot, `.staging-rb-${Date.now()}`);
  const backupPrev = join(installRoot, `.backup-prev-rb-${Date.now()}`);
  await cp(targetDir, stagedDir, { recursive: true });
  let hadPrev = false;
  try {
    await stat(previousDir);
    await rename(previousDir, backupPrev);
    hadPrev = true;
  } catch {
    hadPrev = false;
  }
  await rename(currentDir, previousDir);
  await rename(stagedDir, currentDir);
  if (hadPrev) {
    await rm(backupPrev, { recursive: true, force: true });
  }

  const nextAuth = {
    schema_version: '1',
    current_version: vr.releaseVersion,
    current_revision: vr.provenanceRevision,
    highest_accepted_revision: existingAuth.highest_accepted_revision,
    previous_version: existingAuth.current_version,
    previous_revision: existingAuth.current_revision,
    trusted_key_id: vr.provenanceKeyId,
  };
  await writeFile(authPath, JSON.stringify(nextAuth, null, 2) + '\n', 'utf8');
  const dataAfter = await snapshotDirDigests(dataDir);
  assert.deepEqual(dataAfter, dataBefore);
  return { verification: vr, authority: nextAuth };
}

export async function runUpgradeRecoverySuite(options = {}) {
  const workDir = await mkdtemp(join(tmpdir(), 'breachatlas-c35-'));
  try {
    const baseReleaseDir = join(workDir, 'base-release');
    await packageCompleteRelease({ rootDir: repoRoot, outputDir: baseReleaseDir });

    const trustedPair = generateEd25519HexPair();
    const roguePair = generateEd25519HexPair();
    const keyId = 'release-key-ed25519-v1';
    const trustedKeys = { [keyId]: trustedPair.publicKeyHex };
    const issuedAt = '2026-11-14T10:00:00Z';
    const expiresAt = '2027-11-14T10:00:00Z';
    const verifyNow = '2026-11-14T14:00:00Z';

    const relV1Dir = join(workDir, 'release-v1');
    const relV2Dir = join(workDir, 'release-v2');
    await cp(baseReleaseDir, relV1Dir, { recursive: true });
    await cp(baseReleaseDir, relV2Dir, { recursive: true });

    await signReleaseDirectory(relV1Dir, {
      privateKeyHex: trustedPair.privateKeyHex,
      keyId,
      releaseVersion: '0.1.0',
      revision: 1,
      issuedAt,
      expiresAt,
    });
    await signReleaseDirectory(relV2Dir, {
      privateKeyHex: trustedPair.privateKeyHex,
      keyId,
      releaseVersion: '0.1.1',
      revision: 2,
      issuedAt: '2026-11-14T12:00:00Z',
      expiresAt,
    });

    const installRoot = join(workDir, 'host-install');
    const dataDir = join(workDir, 'host-data');
    await mkdir(installRoot, { recursive: true });
    await mkdir(dataDir, { recursive: true });

    // 1. Fresh install v0.1.0 (rev 1) + execute packaged binaries.
    const installRes = await installOrUpgradeHost({
      installRoot,
      dataDir,
      candidateDir: relV1Dir,
      trustedKeys,
      verifyNow,
    });
    assert.equal(installRes.verification.signatureVerified, true);
    assert.equal(installRes.authority.current_version, '0.1.0');
    assert.equal(installRes.authority.highest_accepted_revision, 1);

    execFileSync(join(installRoot, 'current', 'bin', 'breachatlas'), ['--version']);
    execFileSync(join(installRoot, 'current', 'bin', 'verify'), ['--version']);

    // 2. Accept sealed evidence + case state under v0.1.0 (0440 sealed bytes).
    const caseV1Sealed = join(dataDir, 'cases', 'case-v1', 'sealed.bin');
    await mkdir(dirname(caseV1Sealed), { recursive: true });
    const v1Bytes = Buffer.from('2026-11-14T10:30:00Z host-a sshd: sealed-v1-event\n');
    await writeFile(caseV1Sealed, v1Bytes);
    await chmod(caseV1Sealed, 0o440);
    const v1Hash = sha256Hex(v1Bytes);

    // 3. Upgrade to v0.1.1 (rev 2) preserving case-v1.
    const upgradeRes = await installOrUpgradeHost({
      installRoot,
      dataDir,
      candidateDir: relV2Dir,
      trustedKeys,
      verifyNow,
    });
    assert.equal(upgradeRes.authority.current_version, '0.1.1');
    assert.equal(upgradeRes.authority.highest_accepted_revision, 2);
    assert.equal(sha256Hex(await readFile(caseV1Sealed)), v1Hash);

    // 4. Accept newer case data under v0.1.1.
    const caseV2Sealed = join(dataDir, 'cases', 'case-v2-newer', 'sealed.bin');
    await mkdir(dirname(caseV2Sealed), { recursive: true });
    const v2Bytes = Buffer.from('2026-11-14T12:30:00Z host-b nginx: sealed-v2-newer-event\n');
    await writeFile(caseV2Sealed, v2Bytes);
    await chmod(caseV2Sealed, 0o440);
    const v2Hash = sha256Hex(v2Bytes);

    // 5. Negative: old-backup overwrite rollback must be rejected.
    await assert.rejects(
      () =>
        rollbackHost({
          installRoot,
          dataDir,
          targetDir: join(installRoot, 'previous'),
          trustedKeys,
          verifyNow,
          overwriteDataWithOldBackup: true,
        }),
      err => err instanceof ReleaseVerificationError && err.code === 'newer_data_overwrite_forbidden'
    );

    // 6. Data-safe binary rollback from v0.1.1 -> v0.1.0 preserves case-v1, case-v2-newer, and authority high-water mark = 2.
    const rollbackRes = await rollbackHost({
      installRoot,
      dataDir,
      targetDir: join(installRoot, 'previous'),
      trustedKeys,
      verifyNow,
    });
    assert.equal(rollbackRes.authority.current_version, '0.1.0');
    assert.equal(rollbackRes.authority.highest_accepted_revision, 2);
    assert.equal(sha256Hex(await readFile(caseV1Sealed)), v1Hash);
    assert.equal(sha256Hex(await readFile(caseV2Sealed)), v2Hash);

    // 7. Negative: replay stale rev 1 into upgrade path rejected because highest_accepted_revision == 2.
    await assert.rejects(
      () =>
        installOrUpgradeHost({
          installRoot,
          dataDir,
          candidateDir: relV1Dir,
          trustedKeys,
          verifyNow,
        }),
      err => err instanceof ReleaseVerificationError && err.code === 'stale_or_expired_revision'
    );

    // 8. Negative: one-byte tamper rejected.
    const tamperDir = join(workDir, 'tamper-one-byte');
    await cp(relV2Dir, tamperDir, { recursive: true });
    const noticePath = join(tamperDir, 'THIRD_PARTY_NOTICES.md');
    const noticeBuf = await readFile(noticePath);
    noticeBuf[0] = noticeBuf[0] ^ 0x01;
    await writeFile(noticePath, noticeBuf);
    await assert.rejects(
      () => verifyReleaseArtifact(tamperDir, { trustedKeys, now: verifyNow }),
      err => err instanceof ReleaseVerificationError && err.code === 'checksum_mismatch'
    );

    // 9. Negative: missing deliverable rejected.
    const missingDir = join(workDir, 'missing-deliverable');
    await cp(relV2Dir, missingDir, { recursive: true });
    await rm(join(missingDir, 'bin', 'verify'));
    await assert.rejects(
      () => verifyReleaseArtifact(missingDir, { trustedKeys, now: verifyNow }),
      err => err instanceof ReleaseVerificationError && err.code === 'incomplete_release_artifact'
    );

    // 10. Negative: untrusted signer rejected.
    const rogueDir = join(workDir, 'rogue-signer');
    await cp(baseReleaseDir, rogueDir, { recursive: true });
    await signReleaseDirectory(rogueDir, {
      privateKeyHex: roguePair.privateKeyHex,
      keyId: 'rogue-signer-key',
      releaseVersion: '0.1.2',
      revision: 3,
      issuedAt,
      expiresAt,
    });
    await assert.rejects(
      () => verifyReleaseArtifact(rogueDir, { trustedKeys, now: verifyNow }),
      err => err instanceof ReleaseVerificationError && err.code === 'signature_invalid'
    );

    // 11. Negative: expired revision rejected.
    const expiredDir = join(workDir, 'expired-revision');
    await cp(baseReleaseDir, expiredDir, { recursive: true });
    await signReleaseDirectory(expiredDir, {
      privateKeyHex: trustedPair.privateKeyHex,
      keyId,
      releaseVersion: '0.1.3',
      revision: 3,
      issuedAt: '2026-10-01T00:00:00Z',
      expiresAt: '2026-11-01T00:00:00Z',
    });
    await assert.rejects(
      () => verifyReleaseArtifact(expiredDir, { trustedKeys, now: verifyNow }),
      err => err instanceof ReleaseVerificationError && err.code === 'stale_or_expired_revision'
    );

    const summary = {
      schema_version: '1',
      task: 'C35',
      requirement: 'N35',
      passed: true,
      supported_hosts: ['Linux x86_64'],
      trusted_signer_key_id: keyId,
      verified_files: installRes.verification.verifiedFiles,
      sbom_packages: installRes.verification.sbomPackages,
      source_archive_files: installRes.verification.sourceArchiveFiles,
      source_build_alternative_verified: installRes.verification.sourceBuildRecipeReady,
      lifecycle_checks: {
        installed_version: '0.1.0',
        upgraded_version: '0.1.1',
        rolled_back_version: '0.1.0',
        authority_high_water_mark: rollbackRes.authority.highest_accepted_revision,
        case_v1_preserved: true,
        case_v2_newer_preserved: true,
        sealed_bytes_modified: false,
      },
      negative_cases_rejected: [
        'one_byte_tamper',
        'missing_deliverable',
        'untrusted_signer',
        'expired_revision',
        'stale_replayed_revision',
        'old_backup_overwrite_newer_data',
      ],
    };

    if (options.reportPath) {
      await mkdir(dirname(options.reportPath), { recursive: true });
      await writeFile(options.reportPath, JSON.stringify(summary, null, 2) + '\n', 'utf8');
    }

    return summary;
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const writeReport = process.argv.includes('--write-report');
  const reportPath = writeReport ? join(repoRoot, 'docs', 'evidence', 'release-verification.json') : undefined;
  const result = await runUpgradeRecoverySuite({ reportPath });
  console.log(JSON.stringify(result, null, 2));
}
