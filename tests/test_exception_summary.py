"""Compact post-batch hand-offs from private synthetic exception receipts."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SKILL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL/'scripts'))
from summarize_exceptions import build_report, write_report
from recovery_batch import run_batch
from test_batch_recovery import export_fixture


def receipt(index=0, **changes):
    row = {'path': '/private/file-%d.jpg.L0CK3D' % index, 'member': 'file-%d.jpg' % index,
           'reason': 'decode_error: damaged later frame', 'outcome': 'failed',
           'source_complete': True, 'validation_run_id': 'synthetic-run'}
    return dict(row, **changes)


def save(root, rows):
    path = root/'_exceptions.jsonl'
    path.write_text(''.join(json.dumps(row)+'\n' for row in rows), encoding='utf-8')
    return path


class ExceptionSummaryTests(unittest.TestCase):
    def test_thousand_similar_errors_become_one_bounded_group_with_offsets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = save(root, [receipt(i) for i in range(1000)])
            report = build_report(source)
            self.assertEqual(report['exception_records'], 1000)
            self.assertEqual(report['groups_total'], 1)
            samples = report['groups'][0]['representatives']
            self.assertEqual(len(samples), 3); self.assertLess(len(json.dumps(report)), 4000)
            with source.open('rb') as stream:
                stream.seek(samples[2]['byte_offset'])
                self.assertEqual(json.loads(stream.readline())['path'], receipt(2)['path'])

    def test_different_issues_and_formats_are_counted_separately(self):
        with tempfile.TemporaryDirectory() as directory:
            source = save(Path(directory), [receipt(0), receipt(1),
                receipt(2, member='partial.bin', reason='inferred_or_partial', outcome='partial_unverified'),
                receipt(3, member='changed.jpg', reason='file_changed')])
            report = build_report(source)
            self.assertEqual(report['groups_total'], 3)
            counts = {group['issue']: group['exception_records'] for group in report['groups']}
            self.assertEqual(counts, {'decode_error': 2, 'inferred_or_partial': 1, 'file_changed': 1})

    def test_group_cap_preserves_omitted_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            source = save(Path(directory), [receipt(0), receipt(1), receipt(2, reason='file_changed')])
            report = build_report(source, max_groups=1)
            self.assertEqual(report['groups_omitted'], 1)
            self.assertEqual(report['records_in_omitted_groups'], 1)
            self.assertEqual(report['records_in_shown_groups'], 2)
            self.assertEqual(report['exception_records'], 3)

    def test_partial_or_unfinished_source_receipts_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = save(root, [receipt(source_complete=False)])
            with self.assertRaises(ValueError): build_report(source)
            source.write_text(json.dumps(receipt()), encoding='utf-8')
            with self.assertRaises(ValueError): build_report(source)
            self.assertFalse((root/'review.json').exists())

    def test_mixed_runs_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = save(Path(directory), [receipt(0), receipt(1, validation_run_id='another-run')])
            with self.assertRaises(ValueError): build_report(source)

    def test_existing_output_and_source_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = save(root, [receipt()]); output = root/'review.json'
            output.write_text('previous review'); before = source.read_bytes()
            with self.assertRaises(FileExistsError): write_report(source, output)
            with self.assertRaises(FileExistsError): write_report(source, source)
            self.assertEqual(output.read_text(), 'previous review'); self.assertEqual(source.read_bytes(), before)

    def test_cli_returns_counts_without_printing_private_failure_details(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = save(root, [receipt(detail='synthetic-private-detail')])
            process = subprocess.run([sys.executable, '-X', 'utf8', str(SKILL/'scripts/summarize_exceptions.py'),
                '--input', str(source), '--output', str(root/'review.json')], capture_output=True,
                text=True, encoding='utf-8', timeout=15)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(json.loads(process.stdout)['exception_records'], 1)
            self.assertNotIn('synthetic-private-detail', process.stdout+process.stderr)
            self.assertNotIn('/private/file-', process.stdout+process.stderr)

    def test_batch_generates_review_once_and_completed_resume_preserves_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source, _, _ = export_fixture(root)
            result = run_batch(source, root/'batch')
            self.assertTrue(result['ai_review_needed'])
            output = Path(result['ai_review']); before = output.read_bytes()
            report = json.loads(before)
            self.assertEqual(report['review_mode'], 'after_batch')
            self.assertEqual(report['exception_records'], 3); self.assertEqual(report['groups_total'], 1)
            resumed = run_batch(source, root/'batch', resume=True)
            self.assertFalse(resumed['new_checks_run']); self.assertEqual(resumed['ai_review'], str(output))
            self.assertEqual(output.read_bytes(), before)

    def test_empty_exceptions_need_no_ai_review(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = save(root, [])
            self.assertFalse(build_report(source)['ai_review_needed'])
            root2 = root/'pipeline'; root2.mkdir()
            export, known, _ = export_fixture(root2)
            result = run_batch(export, root2/'batch', known=[str(known)])
            self.assertFalse(result['ai_review_needed'])
            self.assertEqual(json.loads(Path(result['ai_review']).read_text())['groups'], [])


if __name__ == '__main__': unittest.main()
