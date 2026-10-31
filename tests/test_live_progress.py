"""Progress integration checks on synthetic local copies only."""
import contextlib
import gzip
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS=Path(__file__).resolve().parents[1]/'scripts'
sys.path.insert(0,str(SCRIPTS))
from recovery_progress import Progress, html_page, watch


class ProgressTests(unittest.TestCase):
    def test_actual_bytes_rate_eta_and_candidate_not_accepted(self):
        now=[0.0]
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'status.json'; stream=io.StringIO()
            progress=Progress('export',p,2,total_bytes=200,stream=stream,clock=lambda:now[0])
            now[0]=2; progress.advance(100)
            row=json.loads(p.read_text(encoding='utf-8'))
            self.assertEqual(row['percent'],50);self.assertEqual(row['speed_bps'],50)
            self.assertEqual(row['eta_seconds'],2)
            now[0]=4; progress.advance(100);progress.file_done();progress.finish('candidate')
            row=json.loads(p.read_text(encoding='utf-8'))
            self.assertEqual(row['percent'],100);self.assertEqual(row['files_completed'],1)
            self.assertEqual(row['accepted_files'],0);self.assertEqual(row['eta_seconds'],0)

    def test_unknown_totals_do_not_create_percent_or_eta(self):
        now=[0.0];progress=Progress('scan',stream=io.StringIO(),clock=lambda:now[0])
        now[0]=2;progress.advance(1000)
        self.assertIsNone(progress.last_snapshot['percent']);self.assertIsNone(progress.last_snapshot['eta_seconds'])
        progress.fail(interrupted=True)
        self.assertEqual(progress.last_snapshot['status'],'interrupted')
        self.assertEqual(progress.last_snapshot['accepted_files'],0)

    def test_status_collision_preserves_existing_data(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'status';p.write_bytes(b'important existing data')
            with self.assertRaises(FileExistsError):Progress('task',p)
            self.assertEqual(p.read_bytes(),b'important existing data')

    def test_monitor_write_failure_does_not_interrupt_work(self):
        with tempfile.TemporaryDirectory() as directory:
            progress=Progress('task',Path(directory)/'status',stream=io.StringIO())
            with patch('recovery_progress.atomic_text',side_effect=OSError('display failure')):
                progress.advance(7);progress.finish('candidate')
            self.assertEqual(progress.processed_bytes,7)
            self.assertEqual(progress.last_snapshot['status'],'completed')

    def test_html_escaped_and_one_snapshot_viewer(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);progress=Progress('phase',p/'status.json',stream=io.StringIO())
            progress.current_file='<script>untrusted()</script>';progress.emit(force=True)
            with contextlib.redirect_stdout(io.StringIO()):watch([p/'status.json'],2,p/'live.html',once=True)
            page=(p/'live.html').read_text(encoding='utf-8')
            self.assertNotIn('<script>untrusted()',page);self.assertIn('&lt;script&gt;',page)
            self.assertIn('location.reload()',page)


class IntegrationTests(unittest.TestCase):
    def tar_bytes(self):
        stream=io.BytesIO(); data=b'actual binary payload\x00\xff'
        with tarfile.open(fileobj=stream,mode='w') as archive:
            info=tarfile.TarInfo('Data/a.bin');info.size=len(data);archive.addfile(info,io.BytesIO(data))
        return stream.getvalue(),data

    def test_archive_cli_json_and_progress_are_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);raw,_=self.tar_bytes();source=p/'valid.tar.gz';source.write_bytes(gzip.compress(raw))
            result=subprocess.run([sys.executable,'-X','utf8',str(SCRIPTS/'verify_backup.py'),str(source),
                                   '--progress-file',str(p/'status.json')],capture_output=True,text=False,encoding=None)
            self.assertEqual(result.returncode,0,result.stderr.decode('utf-8'))
            self.assertTrue(json.loads(result.stdout)['integrity_pass'])
            row=json.loads((p/'status.json').read_text(encoding='utf-8'))
            self.assertEqual(row['processed_bytes'],source.stat().st_size)
            self.assertEqual(row['verified_files'],1);self.assertEqual(row['accepted_files'],0)
            self.assertEqual(row['status'],'completed');self.assertTrue(result.stderr)

    def test_invalid_archive_final_progress_failed(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);raw,_=self.tar_bytes();source=p/'bad.tar.gz';source.write_bytes(gzip.compress(raw+b'bad tail'))
            result=subprocess.run([sys.executable,'-X','utf8',str(SCRIPTS/'verify_backup.py'),str(source),
                                   '--progress-file',str(p/'status.json')],capture_output=True,text=False,encoding=None)
            self.assertNotEqual(result.returncode,0)
            row=json.loads((p/'status.json').read_text(encoding='utf-8'))
            self.assertEqual(row['status'],'failed');self.assertEqual(row['accepted_files'],0)

    def test_binary_stdin_export_preserves_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);raw,data=self.tar_bytes()
            result=subprocess.run([sys.executable,'-X','utf8',str(SCRIPTS/'c3r_local.py'),'extract','-',str(p/'new'),
                                   '--progress-file',str(p/'status.json'),'--total-bytes',str(len(data))],
                                  input=raw,capture_output=True,text=False,encoding=None)
            self.assertEqual(result.returncode,0,result.stderr.decode('utf-8'))
            self.assertEqual((p/'new'/'Data/a.bin').read_bytes(),data)
            row=json.loads((p/'status.json').read_text(encoding='utf-8'))
            self.assertEqual(row['processed_bytes'],len(data));self.assertEqual(row['accepted_files'],0)

    def test_decrypt_progress_does_not_change_content_or_json(self):
        from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
        from decrypt_copy import chacha8_call
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);copies=p/'copies';copies.mkdir()
            plain=b'complete original bytes'*10;iv,key=bytes(range(16)),bytes(range(32))
            file_key,nonce=bytes(range(32)),bytes(range(8));body,_=chacha8_call(plain,file_key,nonce)
            cipher=Cipher(algorithms.AES(key),modes.CBC(iv)).encryptor();footer=bytearray(588)
            footer[:48]=cipher.update(file_key+nonce+nonce)+cipher.finalize()
            footer[568:572]=bytes.fromhex('11223344');footer[572:576]=bytes((0x24,0,0x20,0))
            struct.pack_into('<Q',footer,580,len(plain));source=copies/'input.L0CK3D';source.write_bytes(body+footer)
            secret=p/'master';secret.write_bytes(iv+key)
            result=subprocess.run([sys.executable,'-X','utf8',str(SCRIPTS/'decrypt_copy.py'),
                                   '--copy-root',str(copies),'--input-copy',str(source),'--master-file',str(secret),
                                   '--expected-marker','11223344','--expected-sha256',hashlib.sha256(plain).hexdigest(),
                                   '--output',str(p/'recovered'),'--progress-file',str(p/'status.json')],capture_output=True,text=False,encoding=None)
            self.assertEqual(result.returncode,0,result.stderr.decode('utf-8'))
            self.assertEqual((p/'recovered').read_bytes(),plain);self.assertEqual(source.read_bytes(),body+footer)
            self.assertEqual(json.loads(result.stdout)['sha256'],hashlib.sha256(plain).hexdigest())
            row=json.loads((p/'status.json').read_text(encoding='utf-8'))
            self.assertEqual(row['processed_bytes'],len(plain));self.assertEqual(row['accepted_files'],1)

    def test_multiple_valid_candidates_count_one_accepted_source(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);out=p/'candidates';out.mkdir();known=p/'known';known.mkdir()
            data=b'same original';(known/'file.txt').write_bytes(data)
            records=[]
            for variant in ('prev','next'):
                member='file.__'+variant+'__.txt';(out/member).write_bytes(data)
                records.append(dict(path='/volume/file.txt.L0CK3D',member=member,variant=variant,
                                    status='needs_inference',bytes=len(data),orig=len(data),
                                    sha256=hashlib.sha256(data).hexdigest()))
            (out/'_c3r_manifest.jsonl').write_text('\n'.join(json.dumps(r) for r in records)+'\n',encoding='utf-8')
            result=subprocess.run([sys.executable,'-X','utf8',str(SCRIPTS/'c3r_local.py'),'validate',str(out),
                                   '--known',str(known),'--workers','2','--progress-file',str(p/'status.json')],
                                  capture_output=True,text=False,encoding=None)
            self.assertEqual(result.returncode,0,result.stderr.decode('utf-8'))
            row=json.loads((p/'status.json').read_text(encoding='utf-8'))
            self.assertEqual(row['files_completed'],2);self.assertEqual(row['accepted_files'],1)
            self.assertEqual(json.loads((out/'_summary.json').read_text(encoding='utf-8'))['sources'],1)


if __name__=='__main__':unittest.main(verbosity=2)
