"""Bulk and resume behavior on independent synthetic files; no NAS access."""
import contextlib
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

SKILL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL/'scripts'))
import c3r_local
from recovery_batch import run_batch


def fixture(root, count=3):
    out = root/'candidates'; out.mkdir()
    known = root/'known'; known.mkdir()
    records = []
    for index in range(count):
        data = ('complete original '+str(index)).encode(); name = 'file-%d.bin' % index
        (out/name).write_bytes(data); (known/name).write_bytes(data)
        records.append({'path': '/volume/'+name+'.L0CK3D', 'member': name, 'variant': 'exact',
                        'status': 'exact', 'orig': len(data), 'bytes': len(data),
                        'sha256': hashlib.sha256(data).hexdigest()})
    (out/'_c3r_manifest.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in records), encoding='utf-8')
    return out, known, records


def validate(out, known=None, resume=False):
    with contextlib.redirect_stdout(io.StringIO()), patch('c3r_local.ProcessPoolExecutor', ThreadPoolExecutor):
        return c3r_local.cmd_validate(types.SimpleNamespace(out=str(out), known=[str(known)] if known else None,
                                       workers=2, resume=resume, progress=None))


def export_fixture(root):
    out, known, records = fixture(root)
    source = root/'export.tar'
    with tarfile.open(source, 'w') as archive:
        for path in out.iterdir():
            archive.add(path, arcname=path.name, recursive=False)
    return source, known, out


class BatchRecoveryTests(unittest.TestCase):
    def test_resume_reuses_successful_decode_but_rereads_current_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); out, _, _ = fixture(root)
            with patch('c3r_local.decode', return_value='decoded') as decoder:
                first = validate(out)
                self.assertEqual(decoder.call_count, 3)
            with patch('c3r_local.decode', side_effect=AssertionError('Unexpected full decode')):
                second = validate(out, resume=True)
            self.assertEqual(first['exceptions'], 0); self.assertEqual(second['decode_reused'], 3)
            self.assertEqual(second['sources'], 3)

    def test_changed_bytes_with_preserved_mtime_are_not_reused_or_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); out, _, records = fixture(root, 1)
            with patch('c3r_local.decode', return_value='decoded'): validate(out)
            path = out/records[0]['member']; info = path.stat()
            path.write_bytes(b'x'*info.st_size); os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
            summary = validate(out, resume=True)
            self.assertEqual(summary['decode_reused'], 0); self.assertEqual(summary['exceptions'], 1)
            row = json.loads((out/'_validation.jsonl').read_text())
            self.assertFalse(row['sha_ok']); self.assertEqual(row['verdict'], 'bad')

    def test_unreadable_item_does_not_stop_other_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); out, known, _ = fixture(root)
            original = c3r_local.sha256
            def fail_one(path):
                if Path(path) == out/'file-1.bin': raise OSError('Synthetic unreadable file')
                return original(path)
            with patch('c3r_local.sha256', side_effect=fail_one): summary = validate(out, known)
            self.assertEqual(summary['sources'], 3); self.assertEqual(summary['exceptions'], 1)
            rows = [json.loads(line) for line in (out/'_validation.jsonl').read_text().splitlines()]
            self.assertEqual(sum(row['verdict']=='ok' for row in rows), 2)
            self.assertEqual(len((out/'_validation_journal.jsonl').read_text().splitlines()), 3)

    def test_truncated_final_checkpoint_record_is_repaired_on_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); out, known, _ = fixture(root)
            validate(out, known)
            journal = out/'_validation_journal.jsonl'
            with journal.open('ab') as stream: stream.write(b'{"unfinished":')
            summary = validate(out, known, resume=True)
            self.assertEqual(summary['sources'], 3)
            self.assertTrue(all(json.loads(line) for line in journal.read_text().splitlines()))

    def test_bad_alternative_does_not_raise_an_exception_for_verified_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); out, known, records = fixture(root, 1)
            row = dict(records[0], member='bad-prev.bin', variant='prev', status='needs_inference')
            (out/row['member']).write_bytes(b'bad bytes')
            with (out/'_c3r_manifest.jsonl').open('a') as stream: stream.write(json.dumps(row)+'\n')
            summary = validate(out, known)
            self.assertEqual(summary['sources'], 1); self.assertEqual(summary['exceptions'], 0)
            self.assertEqual((out/'_exceptions.jsonl').read_text(), '')

    def test_new_known_original_is_checked_even_when_decoder_is_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); out, known, _ = fixture(root, 1)
            with patch('c3r_local.decode', return_value='decoded'): validate(out, known)
            (known/'file-0.bin').write_bytes(b'x'*len((known/'file-0.bin').read_bytes()))
            with patch('c3r_local.decode', side_effect=AssertionError('Unexpected decode')):
                summary = validate(out, known, resume=True)
            self.assertEqual(summary['decode_reused'], 1); self.assertEqual(summary['exceptions'], 1)
            row = json.loads((out/'_validation.jsonl').read_text())
            self.assertFalse(row['known_original_match']); self.assertEqual(row['verdict'], 'bad')

    def test_pipeline_finishes_whole_export_and_completed_resume_runs_no_new_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source, known, originals = export_fixture(root)
            result = run_batch(source, root/'batch', workers=2, known=[str(known)])
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(result['summary']['sources'], 3)
            for path in originals.iterdir():
                self.assertEqual((root/'batch/candidates'/path.name).read_bytes(), path.read_bytes())
            with patch('recovery_batch.cmd_validate', side_effect=AssertionError('Repeated completed batch')):
                resumed = run_batch(source, root/'batch', resume=True)
            self.assertEqual(resumed['status'], 'already_completed'); self.assertFalse(resumed['new_checks_run'])

    def test_validation_interruption_preserves_export_and_resumes_at_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source, known, _ = export_fixture(root)
            with patch('recovery_batch.cmd_validate', side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt): run_batch(source, root/'batch', known=[str(known)])
            state = json.loads((root/'batch/batch-state.json').read_text())
            self.assertTrue(state['extracted']); self.assertFalse(state['validated'])
            with patch('recovery_batch.cmd_extract', side_effect=AssertionError('Repeated extraction')):
                result = run_batch(source, root/'batch', resume=True)
            self.assertEqual(result['status'], 'completed'); self.assertEqual(result['summary']['exceptions'], 0)

    def test_changed_export_cannot_mix_with_old_batch_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source, known, _ = export_fixture(root)
            run_batch(source, root/'batch', known=[str(known)])
            with source.open('ab') as stream: stream.write(b'new bytes')
            with self.assertRaises(ValueError): run_batch(source, root/'batch', resume=True)

    def test_cli_real_process_pool_and_summary_are_separate_from_progress(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source, known, _ = export_fixture(root)
            result = subprocess.run([sys.executable, '-X', 'utf8', str(SKILL/'scripts/recovery_batch.py'),
                      '--export', str(source), '--output', str(root/'batch'), '--known', str(known), '--workers', '2'],
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['summary']['sources'], 3)
            self.assertTrue(result.stderr)


if __name__ == '__main__': unittest.main()
