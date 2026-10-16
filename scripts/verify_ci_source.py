#!/usr/bin/env python3
"""Verify immutable recorded snapshots and the exact checkout being tested."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

MANIFEST = 'SHA256SUMS.txt'
EVIDENCE = 'docs/evidence/oss-roadmap.json'


class IntegrityError(ValueError):
    pass


def git(root, *args, input_bytes=None):
    result = subprocess.run(['git', *args], cwd=root, input=input_bytes,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if result.returncode:
        raise IntegrityError('Git history/read failed: ' + result.stderr.decode(errors='replace').strip())
    return result.stdout


def safe_path(name):
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and '..' not in path.parts and '\n' not in name and '\r' not in name


def tree_files(root, revision):
    entries = {}
    for entry in git(root, 'ls-tree', '-r', '-z', '--full-tree', revision).split(b'\0'):
        if not entry:
            continue
        header, name_bytes = entry.split(b'\t', 1)
        mode, kind, oid = header.decode().split()
        name = name_bytes.decode('utf-8')
        if kind != 'blob' or mode not in {'100644', '100755', '120000'} or not safe_path(name):
            raise IntegrityError('Unsupported source entry: ' + name)
        entries[name] = {'mode': mode, 'oid': oid}
    objects = list(dict.fromkeys(item['oid'] for item in entries.values()))
    output = git(root, 'cat-file', '--batch', input_bytes=('\n'.join(objects) + '\n').encode())
    blobs = {}
    cursor = 0
    for oid in objects:
        end = output.index(b'\n', cursor)
        actual, kind, size = output[cursor:end].decode().split()
        if actual != oid or kind != 'blob':
            raise IntegrityError('Unexpected Git object: ' + oid)
        cursor = end + 1
        size = int(size)
        blobs[oid] = output[cursor:cursor + size]
        if len(blobs[oid]) != size or output[cursor + size:cursor + size + 1] != b'\n':
            raise IntegrityError('Incomplete Git blob: ' + oid)
        cursor += size + 1
    for item in entries.values():
        item['bytes'] = blobs[item['oid']]
        item['sha256'] = hashlib.sha256(item['bytes']).hexdigest()
    return entries


def source_identity(files):
    digest = hashlib.sha256()
    for name in sorted(files):
        if name == MANIFEST or name.startswith('docs/evidence/'):
            continue
        digest.update(name.encode() + b'\0' + bytes.fromhex(files[name]['sha256']))
    return 'sha256:' + digest.hexdigest()


def origin(root, path):
    commit = git(root, 'log', '-1', '--format=%H', 'HEAD', '--', path).decode().strip()
    if not re.fullmatch(r'[0-9a-f]{40,64}', commit):
        raise IntegrityError('No recorded source history for ' + path)
    return commit


def verify_manifest(files):
    if MANIFEST not in files:
        raise IntegrityError('Missing committed source manifest')
    recorded = {}
    for line in files[MANIFEST]['bytes'].decode('utf-8').splitlines():
        if '  ' not in line:
            raise IntegrityError('Malformed source manifest entry')
        digest, name = line.split('  ', 1)
        if not safe_path(name) or name in recorded or not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise IntegrityError('Unsafe/duplicate/invalid source manifest entry: ' + name)
        recorded[name] = digest
    actual = {name: item['sha256'] for name, item in files.items() if name != MANIFEST}
    if recorded.keys() != actual.keys():
        raise IntegrityError('Recorded manifest file set differs from its historical Git tree')
    different = [name for name in recorded if recorded[name] != actual[name]]
    if different:
        raise IntegrityError('Historical manifest mismatch: ' + ', '.join(different[:8]))
    return len(actual)


def verify(root):
    root = root.resolve()
    if git(root, 'rev-parse', '--is-shallow-repository').strip() == b'true':
        raise IntegrityError('Full history required; use actions/checkout fetch-depth: 0 or git fetch --unshallow')
    head = git(root, 'rev-parse', 'HEAD').decode().strip()
    current = tree_files(root, head)
    for name, item in current.items():
        path = root / name
        if item['mode'] == '120000':
            actual = os.fsencode(os.readlink(path)) if path.is_symlink() else None
        else:
            actual = path.read_bytes() if path.is_file() and not path.is_symlink() else None
            if actual is not None and os.name != 'nt':
                executable = bool(path.stat().st_mode & 0o111)
                if executable != (item['mode'] == '100755'):
                    raise IntegrityError('Checkout mode differs from Git: ' + name)
        if actual != item['bytes']:
            raise IntegrityError('Checkout differs from Git: ' + name)
    untracked = git(root, 'ls-files', '--others', '--exclude-standard', '-z').decode().split('\0')
    if any(untracked):
        raise IntegrityError('Untracked source is not part of the tested commit: ' + ', '.join(filter(None, untracked)))
    manifest_commit = origin(root, MANIFEST)
    evidence_commit = origin(root, EVIDENCE)
    cache = {head: current}
    for revision in [manifest_commit, evidence_commit]:
        if revision not in cache:
            cache[revision] = tree_files(root, revision)
    count = verify_manifest(cache[manifest_commit])
    files = cache[evidence_commit]
    if EVIDENCE not in files:
        raise IntegrityError('Missing recorded evidence')
    evidence = json.loads(files[EVIDENCE]['bytes'])
    if evidence.get('source_identity') != source_identity(files):
        raise IntegrityError('Recorded evidence does not match its historical Git source identity')
    return {
        'schema_version': 1,
        'passed': True,
        'scope': 'Source integrity only; runtime results belong to this commit\'s CI jobs',
        'commit': head,
        'git_tree': git(root, 'rev-parse', 'HEAD^{tree}').decode().strip(),
        'current_source_identity': source_identity(current),
        'current_files': {name: {'mode': item['mode'], 'sha256': item['sha256']} for name, item in sorted(current.items())},
        'historical_manifest': {'commit': manifest_commit, 'verified_files': count},
        'historical_evidence': {'commit': evidence_commit, 'source_identity': evidence['source_identity']},
        'runtime_tests_certified': False,
        'core_tasks_certified': [],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='dist/ci/source.json', help='Ignored artifact path inside this checkout')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        result = verify(root)
        output = (root / args.output).resolve()
        relative = output.relative_to(root).as_posix()
        if not safe_path(relative) or subprocess.run(['git', 'check-ignore', '--quiet', '--', relative], cwd=root).returncode:
            raise IntegrityError('Output must be an ignored artifact path inside this checkout')
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({key: value for key, value in result.items() if key != 'current_files'}))
        return 0
    except (IntegrityError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print('SOURCE INTEGRITY FAILED: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
