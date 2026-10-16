"""Regression: action updates retain historical proofs and verify new bytes."""
from pathlib import Path
import hashlib
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/verify_ci_source.py'
SPEC = importlib.util.spec_from_file_location('ci_source', SCRIPT)
ci_source = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci_source)


class CiSourceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ci-source-regression-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'source'
        self.root.mkdir()
        self.git('init', '--quiet')
        self.write('.gitignore', 'dist/\n__pycache__/\n')
        self.write('.github/workflows/verify.yml', 'uses: actions/example@' + '1' * 40 + '\n')
        self.write('README.md', 'Synthetic licensed source fixture.\n')
        self.git('add', '--all')
        # The synthetic fixture deliberately certifies no product/runtime work.
        files = self.index_files()
        self.write(ci_source.EVIDENCE, json.dumps({'source_identity': ci_source.source_identity(files), 'scope': 'Synthetic unit fixture only'}))
        self.git('add', '--all')
        self.write(ci_source.MANIFEST, ''.join(item['sha256'] + '  ' + name + '\n' for name, item in sorted(self.index_files().items())))
        self.commit('Synthetic baseline')
        self.baseline = self.git('rev-parse', 'HEAD').strip()

    def git(self, *args):
        result = subprocess.run(['git', *args], cwd=self.root, text=True, capture_output=True)
        if result.returncode:
            self.fail(result.stderr)
        return result.stdout

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def index_files(self):
        return ci_source.tree_files(self.root, self.git('write-tree').strip())

    def commit(self, message):
        self.git('add', '--all')
        self.git('-c', 'user.name=CI fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', message)

    def test_action_and_source_updates_keep_old_proofs_bound_to_their_real_tree(self):
        new_workflow = 'uses: actions/example@' + '2' * 40 + '\n'
        self.write('.github/workflows/verify.yml', new_workflow)
        self.write('README.md', 'Intentional changed source, requiring fresh CI execution.\n')
        self.commit('Synthetic dependency and source update')
        proof = ci_source.verify(self.root)
        self.assertEqual(self.baseline, proof['historical_manifest']['commit'])
        self.assertEqual(self.baseline, proof['historical_evidence']['commit'])
        self.assertEqual(hashlib.sha256(new_workflow.encode()).hexdigest(), proof['current_files']['.github/workflows/verify.yml']['sha256'])
        self.assertNotEqual(proof['historical_evidence']['source_identity'], proof['current_source_identity'])
        self.assertFalse(proof['runtime_tests_certified'])
        self.assertEqual([], proof['core_tasks_certified'])

    def test_dirty_workflow_is_rejected_even_if_old_evidence_is_valid(self):
        self.write('.github/workflows/verify.yml', 'uncommitted altered workflow\n')
        with self.assertRaisesRegex(ci_source.IntegrityError, 'Checkout differs'):
            ci_source.verify(self.root)

    def test_corrupted_recorded_manifest_cannot_be_relabelled_as_history(self):
        manifest = (self.root / ci_source.MANIFEST).read_text()
        first = manifest[0]
        self.write(ci_source.MANIFEST, ('0' if first != '0' else '1') + manifest[1:])
        self.commit('Synthetic corrupt manifest')
        with self.assertRaisesRegex(ci_source.IntegrityError, 'Historical manifest mismatch'):
            ci_source.verify(self.root)

    def test_forged_evidence_identity_is_rejected(self):
        self.write(ci_source.EVIDENCE, json.dumps({'source_identity': 'sha256:' + '0' * 64}))
        self.commit('Synthetic forged evidence')
        with self.assertRaisesRegex(ci_source.IntegrityError, 'historical Git source identity'):
            ci_source.verify(self.root)

    def test_shallow_history_fails_with_an_actionable_message(self):
        self.write('README.md', 'Another committed fixture revision.\n')
        self.commit('Synthetic second commit')
        shallow = Path(self.temp.name) / 'shallow'
        subprocess.run(['git', 'clone', '--quiet', '--depth=1', '--no-local', str(self.root), str(shallow)], check=True)
        with self.assertRaisesRegex(ci_source.IntegrityError, 'fetch-depth: 0'):
            ci_source.verify(shallow)

    def test_untracked_source_is_not_silently_omitted(self):
        self.write('unexpected-source.txt', 'Unexpected untracked source.\n')
        with self.assertRaisesRegex(ci_source.IntegrityError, 'Untracked source'):
            ci_source.verify(self.root)


if __name__ == '__main__':
    unittest.main()
