"""Independent-storage regression tests; no NAS, malware or real keys."""
import contextlib
import hashlib
import io
import json
import gzip
from pathlib import Path
import socket
import sys
import tarfile
import struct
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

SKILL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL/'scripts'))
from prepare_session_key import MaterialError, normalize, prepare
from probe_rescue_ports import probe
from c3r_local import cmd_extract, check
from verify_backup import validate


class KeyTests(unittest.TestCase):
    def test_all_explicit_formats_produce_exact_iv_key_order(self):
        key, iv = bytes(range(32)), bytes(range(16, 32))
        payload = json.dumps({'aes_key_hex': key.hex(), 'aes_iv_hex': iv.hex()}).encode()
        solar = ('AES_KEY='+key.hex()+'\r\nAES_IV='+iv.hex()+'\r\n').encode()
        for name, data in [('json', payload), ('solar-key-sys', solar), ('raw-iv-key', iv+key)]:
            self.assertEqual(normalize(data, name), iv+key)

    def test_missing_duplicate_and_invalid_material_refused(self):
        cases = [(b'{"aes_key_hex":"aa"}', 'json'),
                 (b'{"aes_key_hex":"aa","aes_key_hex":"bb"}', 'json'),
                 (b'AES_KEY=aa\nAES_KEY=bb\nAES_IV=cc', 'solar-key-sys'),
                 (b'x'*47, 'raw-iv-key'), (b'x'*49, 'raw-iv-key'),
                 (b'AES_KEY=not_hex\nAES_IV=00', 'solar-key-sys')]
        for data, name in cases:
            with self.assertRaises(MaterialError):
                normalize(data, name)

    def test_output_exclusive_and_source_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory); source = p/'source'; out = p/'master'
            secret = bytes(range(48)); source.write_bytes(secret)
            result = prepare(source, 'raw-iv-key', out)
            self.assertEqual(out.read_bytes(), secret)
            self.assertNotIn(secret.hex(), json.dumps(result))
            with self.assertRaises(FileExistsError):
                prepare(source, 'raw-iv-key', out)
            self.assertEqual(source.read_bytes(), secret)
            self.assertEqual(out.read_bytes(), secret)

    def test_normalized_solar_key_really_unwraps_synthetic_footer(self):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from decrypt_copy import unwrap_record
        iv, key = bytes(range(16)), bytes(range(32))
        file_key, nonce = bytes(range(32, 64)), bytes(range(8))
        session = normalize(('AES_KEY='+key.hex()+'\nAES_IV='+iv.hex()).encode(), 'solar-key-sys')
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        footer = cipher.update(file_key+nonce+nonce)+cipher.finalize()
        self.assertEqual(unwrap_record(footer, session), (file_key, nonce))

    def test_full_copy_recovery_wrong_iv_refusal_and_original_preservation(self):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from decrypt_copy import chacha8_call, decrypt_copy, unwrap_record
        from file_layout import encrypted_segments, RecoveryError
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory); copies = p/'copies'; copies.mkdir()
            iv, key = bytes(range(16)), bytes(range(32)); master = p/'master'
            master.write_bytes(iv+key); file_key, nonce = bytes(range(32, 64)), bytes(range(8))
            plain = bytes(range(251))*25000; expected = hashlib.sha256(plain).hexdigest()
            for mode, parameter in [(0x24, 0), (0x26, 0), (0x25, 20), (0x25, 50)]:
                body = bytearray(plain); counter = 0
                for offset, length in encrypted_segments(len(plain), mode, parameter):
                    for start in range(offset, offset+length, 5*1024*1024):
                        end = min(start+5*1024*1024, offset+length)
                        body[start:end], counter = chacha8_call(bytes(body[start:end]), file_key, nonce, counter)
                footer = bytearray(588); cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
                footer[:48] = cipher.update(file_key+nonce+nonce)+cipher.finalize()
                footer[568:572] = bytes.fromhex('11223344'); footer[572:576] = bytes((mode, parameter, 0x20, 0))
                struct.pack_into('<Q', footer, 580, len(plain))
                case = str(mode)+'-'+str(parameter)
                source = copies/case; source.write_bytes(body+footer); out = p/('output-'+case)
                result = decrypt_copy(source, out, master, copies, expected, bytes.fromhex('11223344'))
                self.assertEqual(out.read_bytes(), plain)
                self.assertEqual(result['verification'], 'known-original-sha256')
                self.assertEqual(source.read_bytes(), body+footer)
                with self.assertRaises(FileExistsError):
                    decrypt_copy(source, out, master, copies, expected, bytes.fromhex('11223344'))
                wrong = bytes([iv[0]^1])+iv[1:]+key; bad = p/'wrong'; bad.write_bytes(wrong)
                # A wrong IV really can pass nonce repetition; full SHA must fail.
                unwrap_record(footer, wrong)
                refused = p/'wrong-output'
                with self.assertRaises(RecoveryError):
                    decrypt_copy(source, refused, bad, copies, expected, bytes.fromhex('11223344'))
                self.assertFalse(refused.exists())


class ArchiveVerificationTests(unittest.TestCase):
    def tar(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w') as archive:
            item = tarfile.TarInfo('data'); item.size=1; archive.addfile(item, io.BytesIO(b'x'))
        return stream.getvalue()

    def test_full_tar_and_single_gzip_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            for name, data in [('valid.tar', self.tar()), ('valid.tar.gz', gzip.compress(self.tar())),
                               ('large.gz', gzip.compress(bytes(8*1024*1024)))]:
                f = p/name; f.write_bytes(data); self.assertTrue(validate(f)['integrity_pass'])

    def test_missing_terminators_nonzero_tail_concat_and_truncated_gzip_refused(self):
        good = self.tar(); missing = good[:1024]
        cases = [('missing.tar', missing), ('missing.tar.gz', gzip.compress(missing)),
                 ('tail.tar.gz', gzip.compress(good+b'nonzero tail')),
                 ('concat.tar.gz', gzip.compress(good)+gzip.compress(bytes(512))),
                 ('truncated.tar.gz', gzip.compress(good)[:-4])]
        with tempfile.TemporaryDirectory() as directory:
            for name, data in cases:
                f = Path(directory)/name; f.write_bytes(data)
                with self.assertRaises((ValueError, EOFError, tarfile.ReadError)):
                    validate(f)

    def test_stale_sha_unknown_format_and_original_conflict_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory); f=p/'file.bin'; f.write_bytes(b'original candidate')
            digest = hashlib.sha256(f.read_bytes()).hexdigest()
            rec = dict(path='source.L0CK3D', member='file.bin', variant='exact', status='exact', bytes=f.stat().st_size, sha256=digest)
            self.assertEqual(check((rec, f, digest, None))['verdict'], 'unverified')
            original = p/'known'; original.write_bytes(b'a different original')
            with patch('c3r_local.decode', return_value='decoded'):
                self.assertEqual(check((rec, f, digest, [original]))['verdict'], 'bad')
            f.write_bytes(b'changed candidate')
            with patch('c3r_local.decode', return_value='decoded'):
                result = check((rec, f, digest, None))
            self.assertFalse(result['sha_ok']); self.assertEqual(result['verdict'], 'bad')


class SavedMemoryTests(unittest.TestCase):
    def test_windows_compatible_bounded_va_and_hash_refusal(self):
        from recover_process_key import read_va
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory); data = b'saved map bytes'; name = 'map-1000-%x.bin' % (0x1000+len(data))
            f = p/name; f.write_bytes(data)
            region = dict(start=0x1000,end=0x1000+len(data),holes=[],file=name,sha256=hashlib.sha256(data).hexdigest())
            self.assertEqual(read_va(p,[region],0x1002,5),data[2:7])
            f.write_bytes(b'bad map content')
            with self.assertRaises(ValueError):read_va(p,[region],0x1002,5)


class PortTests(unittest.TestCase):
    def test_connect_only_no_payload(self):
        listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen()
        port = listener.getsockname()[1]; observed = []
        def server():
            with listener.accept()[0] as c:
                c.settimeout(2); observed.append(c.recv(100))
        worker = threading.Thread(target=server); worker.start()
        try:
            result = probe('127.0.0.1', [port], 1)
            worker.join(3)
            self.assertEqual(result['results'][0]['status'], 'tcp-open')
            self.assertEqual(observed, [b''])
        finally:
            listener.close()
        self.assertEqual(probe('127.0.0.1', [port], 0.2)['results'][0]['status'], 'unreachable-or-closed')


class ExtractTests(unittest.TestCase):
    def archive(self, path, entries):
        with tarfile.open(path, 'w') as archive:
            for name, payload, kind in entries:
                info = tarfile.TarInfo(name)
                if kind == 'link':
                    info.type = tarfile.SYMTYPE; info.linkname = '../outside'
                    archive.addfile(info)
                else:
                    info.size = len(payload); archive.addfile(info, io.BytesIO(payload))

    def extract(self, source, destination):
        with contextlib.redirect_stdout(io.StringIO()):
            cmd_extract(types.SimpleNamespace(stream=str(source), out=str(destination)))

    def test_valid_data_and_receipt_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory); archive = p/'a.tar'; data = b'complete recovered bytes'
            self.archive(archive, [('Data/photo/a.bin', data, 'file')])
            self.extract(archive, p/'new')
            self.assertEqual((p/'new'/'Data/photo/a.bin').read_bytes(), data)
            row = json.loads((p/'new'/'_extracted.jsonl').read_text())
            self.assertEqual(row['sha256'], hashlib.sha256(data).hexdigest())
            with self.assertRaises(FileExistsError):self.extract(archive, p/'new')

    def test_duplicate_never_overwrites_first_member(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory); archive = p/'a.tar'
            self.archive(archive, [('same', b'first', 'file'), ('same', b'second', 'file')])
            with self.assertRaises(FileExistsError):self.extract(archive, p/'new')
            self.assertEqual((p/'new'/'same').read_bytes(), b'first')

    def test_escape_link_and_receipt_collision_refused(self):
        for name, kind in [('../outside', 'file'), ('/absolute', 'file'),
                           ('C:/outside', 'file'), ('link', 'link'),
                           ('_extracted.jsonl', 'file')]:
            with tempfile.TemporaryDirectory() as directory:
                p = Path(directory); archive = p/'a.tar'; self.archive(archive, [(name, b'bad', kind)])
                with self.assertRaises(ValueError):self.extract(archive, p/'new')
                self.assertFalse((p/'outside').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
