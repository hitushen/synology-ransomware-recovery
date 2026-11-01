"""Observable validation failures on synthetic files and actual OS locks."""
import contextlib
from concurrent.futures import ThreadPoolExecutor
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

SKILL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL/'scripts'))
import c3r_local
from recovery_batch import run_batch
from test_batch_recovery import export_fixture, fixture, validate

try:
    from PIL import Image
except ImportError:
    Image = None


def media_fixture(root):
    media = root/'two-streams.mkv'
    subprocess.run([shutil.which('ffmpeg'), '-v', 'error', '-f', 'lavfi', '-i',
        'color=red:size=64x64:rate=1', '-f', 'lavfi', '-i', 'color=blue:size=32x32:rate=1',
        '-map', '0:v', '-map', '1:v', '-c:v:0', 'ffv1', '-c:v:1', 'png',
        '-threads', '1', '-t', '120', str(media)], check=True, capture_output=True,
        text=False, encoding=None, timeout=30)
    return media


class ValidationIntegrityTests(unittest.TestCase):
    @unittest.skipUnless(Image, 'Optional Pillow unavailable')
    def test_valid_multiframe_images_decode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for suffix in ('.gif', '.tiff'):
                path = root/('two-frames'+suffix)
                Image.new('RGB', (32, 32), 'red').save(path, save_all=True,
                    append_images=[Image.new('RGB', (32, 32), 'blue')])
                self.assertEqual(c3r_local.decode(path), 'decoded')

    @unittest.skipUnless(Image, 'Optional Pillow unavailable')
    def test_bad_later_tiff_page_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'two-pages.tiff'
            Image.new('RGB', (32, 32), 'red').save(path, save_all=True,
                append_images=[Image.new('RGB', (32, 32), 'blue')], compression='raw')
            path.write_bytes(path.read_bytes()[:-100])
            with Image.open(path) as image:
                image.load()  # The first page is still usable.
            self.assertTrue(c3r_local.decode(path).startswith('decode_error:'))

    @unittest.skipUnless(shutil.which('ffmpeg'), 'Optional ffmpeg unavailable')
    def test_valid_multiple_media_streams_decode(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(c3r_local.decode(media_fixture(Path(directory))), 'decoded')

    @unittest.skipUnless(shutil.which('ffmpeg'), 'Optional ffmpeg unavailable')
    def test_corrupt_late_frame_in_second_track_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = media_fixture(Path(directory))
            data = bytearray(path.read_bytes()); data[data.rindex(b'IDAT')+4] ^= 255
            path.write_bytes(data)
            # The conventional default-stream check misses this corruption.
            default = subprocess.run([shutil.which('ffmpeg'), '-v', 'error', '-xerror', '-i',
                str(path), '-f', 'null', '-'], capture_output=True, text=False, encoding=None, timeout=30)
            self.assertEqual(default.returncode, 0, default.stderr)
            self.assertTrue(c3r_local.decode(path).startswith('decode_error:'))

    def test_candidate_changed_during_decode_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            out, _, records = fixture(Path(directory), 1)
            path = out/records[0]['member']; info = path.stat()
            def mutate(candidate):
                candidate.write_bytes(b'x'*info.st_size)
                os.utime(candidate, ns=(info.st_atime_ns, info.st_mtime_ns))
                return 'decoded'
            with patch('c3r_local.decode', side_effect=mutate):
                row = c3r_local.check((records[0], path, None, None))
            self.assertTrue(row['changed_during_check']); self.assertFalse(row['sha_ok'])
            self.assertEqual(row['verdict'], 'bad')

    def test_candidate_replaced_during_decode_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); out, _, records = fixture(root, 1)
            path = out/records[0]['member']; info = path.stat()
            def replace(candidate):
                replacement = root/'replacement'; replacement.write_bytes(candidate.read_bytes())
                os.utime(replacement, ns=(info.st_atime_ns, info.st_mtime_ns))
                os.replace(replacement, candidate)
                return 'decoded'
            with patch('c3r_local.decode', side_effect=replace):
                row = c3r_local.check((records[0], path, None, None))
            self.assertTrue(row['changed_during_check']); self.assertEqual(row['verdict'], 'bad')

    def test_original_changed_during_hash_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); out, known, _ = fixture(root, 1)
            original_sha = c3r_local.sha256
            def mutate_original(path):
                result = original_sha(path)
                if path.parent == known:
                    info = path.stat()
                    path.write_bytes(b'x'*path.stat().st_size)
                    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
                return result
            with patch('c3r_local.sha256', side_effect=mutate_original):
                summary = validate(out, known)
            self.assertEqual(summary['exceptions'], 1)
            self.assertEqual(json.loads((out/'_validation.jsonl').read_text())['verdict'], 'bad')

    def test_corrupt_candidate_archive_does_not_stop_other_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source, known, out = export_fixture(root)
            corrupt = gzip.compress(b'candidate contents')[:-4]
            (out/'damaged.gz').write_bytes(corrupt)
            record = {'path': '/volume/damaged.gz.L0CK3D', 'member': 'damaged.gz', 'variant': 'exact',
                'status': 'exact', 'orig': len(corrupt), 'bytes': len(corrupt),
                'sha256': hashlib.sha256(corrupt).hexdigest()}
            with (out/'_c3r_manifest.jsonl').open('a') as stream: stream.write(json.dumps(record)+'\n')
            with tarfile.open(source, 'w') as archive:
                for path in out.iterdir(): archive.add(path, arcname=path.name, recursive=False)
            result = run_batch(source, root/'batch', known=[str(known)])
            self.assertEqual(result['status'], 'completed_with_exceptions')
            self.assertEqual(result['summary']['sources'], 4)
            self.assertEqual(result['summary']['exceptions'], 1)
            exception = json.loads((root/'batch/candidates/_exceptions.jsonl').read_text())
            self.assertEqual(exception['member'], 'damaged.gz')
            self.assertTrue(exception['reason'].startswith('decode_error:'))

    def test_valid_tar_gzip_candidate_gets_format_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'backup.tar.gz'
            with tarfile.open(path, 'w:gz') as archive:
                record = tarfile.TarInfo('payload'); record.size = 7
                archive.addfile(record, io.BytesIO(b'payload'))
            self.assertEqual(c3r_local.decode(path), 'decoded')
            path.write_bytes(path.read_bytes()[:-4])
            self.assertTrue(c3r_local.decode(path).startswith('decode_error:'))

    def test_archive_decoder_does_not_emit_auditor_logs_to_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'backup.tar'
            with tarfile.open(path, 'w') as archive:
                entry = tarfile.TarInfo('payload'); entry.size = 7
                archive.addfile(entry, io.BytesIO(b'payload'))
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream), patch('verify_backup.time.time', side_effect=[0, 30, 30]):
                self.assertEqual(c3r_local.decode(path), 'decoded')
            self.assertEqual(stream.getvalue(), '')

    def test_truncated_outer_export_is_still_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source, known, _ = export_fixture(root)
            source.write_bytes(source.read_bytes()[:700])
            with self.assertRaises((ValueError, tarfile.TarError)):
                run_batch(source, root/'batch', known=[str(known)])
            self.assertFalse((root/'batch/candidates').exists())

    def test_competing_batch_process_cannot_touch_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source, known, _ = export_fixture(root)
            run_batch(source, root/'batch', known=[str(known)])
            checkpoint = root/'batch/batch-state.json'; before = checkpoint.read_bytes()
            progress = root/'rejected-progress.json'
            with c3r_local.validation_lock(root/'batch', '_batch.lock'):
                process = subprocess.run([sys.executable, '-X', 'utf8', str(SKILL/'scripts/recovery_batch.py'),
                    '--export', str(source), '--output', str(root/'batch'), '--resume',
                    '--progress-file', str(progress)], capture_output=True, text=True, encoding='utf-8', timeout=15)
            self.assertEqual(process.returncode, 1, process.stdout+process.stderr)
            self.assertEqual(checkpoint.read_bytes(), before); self.assertFalse(progress.exists())
            self.assertEqual(run_batch(source, root/'batch', resume=True)['status'], 'already_completed')

    def test_unresolved_source_is_reported_before_other_sources_finish(self):
        with tempfile.TemporaryDirectory() as directory:
            out, _, _ = fixture(Path(directory), 2)
            unblock = threading.Event(); observed = []
            def decoder(path):
                if path.name == 'file-1.bin':
                    if not unblock.wait(10): raise RuntimeError('Test coordination timed out')
                return 'not_checked'
            def file_done(**kwargs):
                if not unblock.is_set():
                    try: observed.extend(json.loads(line) for line in (out/'_exceptions.jsonl').read_text().splitlines())
                    finally: unblock.set()
            progress = types.SimpleNamespace(set_total=lambda *a: None, file_done=file_done, failed_files=0)
            with contextlib.redirect_stdout(io.StringIO()), \
                    patch('c3r_local.ProcessPoolExecutor', ThreadPoolExecutor), patch('c3r_local.decode', side_effect=decoder):
                summary = c3r_local.cmd_validate(types.SimpleNamespace(out=str(out), known=None,
                    workers=2, resume=False, progress=progress))
            self.assertEqual(summary['exceptions'], 2)
            self.assertEqual(len(observed), 1); self.assertTrue(observed[0]['source_complete'])

    def test_early_bad_candidate_waits_for_good_alternative(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); out, known, records = fixture(root, 1)
            alternative = dict(records[0], member='bad-prev.bin', status='needs_inference', variant='prev')
            (out/alternative['member']).write_bytes(b'bad')
            (out/'_c3r_manifest.jsonl').write_text(json.dumps(alternative)+'\n'+json.dumps(records[0])+'\n')
            unblock = threading.Event(); observed = []; real_check = c3r_local.check
            def checker(job):
                if job[0]['member'] == records[0]['member']:
                    if not unblock.wait(10): raise RuntimeError('Test coordination timed out')
                return real_check(job)
            def file_done(**kwargs):
                if not unblock.is_set():
                    try: observed.append((out/'_exceptions.jsonl').read_text())
                    finally: unblock.set()
            progress = types.SimpleNamespace(set_total=lambda *a: None, file_done=file_done, failed_files=0)
            with contextlib.redirect_stdout(io.StringIO()), patch('c3r_local.ProcessPoolExecutor', ThreadPoolExecutor), \
                    patch('c3r_local.check', side_effect=checker):
                summary = c3r_local.cmd_validate(types.SimpleNamespace(out=str(out), known=[str(known)],
                    workers=2, resume=False, progress=progress))
            self.assertEqual(observed, ['']); self.assertEqual(summary['exceptions'], 0)
            self.assertEqual((out/'_exceptions.jsonl').read_text(), '')


if __name__ == '__main__': unittest.main()
