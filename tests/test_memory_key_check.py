"""Synthetic memory, crypto and source-preservation tests; no live system."""
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

SKILL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL / 'scripts'))
from memory_key_check import check_memory, scan_patterns
from recovery_progress import Progress

IV, AES_KEY = bytes(range(1, 17)), bytes(range(32, 64))
FILE_KEY, NONCE = bytes(range(64, 96)), bytes(range(8))
MARKER = bytes.fromhex('11223344')


def profile_fixture(root):
    profile = {'packed_sha256': hashlib.sha256(b'synthetic packed identity').hexdigest(),
               'unpacked_sha256': hashlib.sha256(b'synthetic unpacked identity').hexdigest(),
               'entry': {'va': 0x1010, 'hex': bytes(range(128, 160)).hex()},
               'mode_va': 0x2020, 'master_pointer_va': 0x2030,
               'ram_bytes': 5*4096, 'low_ram_end': 5*4096, 'high_ram_start': 0x100000000}
    path = root / 'profile.json'; path.write_text(json.dumps(profile))
    return path, profile


def process_fixture(root, material=IV+AES_KEY, pointer=0x2100, missing=False, bad_exe=False):
    profile_path, profile = profile_fixture(root)
    capture = root / 'capture'; capture.mkdir()
    code = bytearray(4096); code[0x10:0x30] = bytes.fromhex(profile['entry']['hex'])
    rw = bytearray(4096); rw[0x20] = 0x20
    struct.pack_into('<Q', rw, 0x30, pointer); rw[0x100:0x130] = material
    regions = []
    for start, data in ((0x1000, code), (0x2000, rw)):
        name = 'map-%x-%x.bin' % (start, start+len(data))
        (capture/name).write_bytes(data)
        regions.append({'start': start, 'end': start+len(data), 'file': name,
                        'holes': [{'start': 0x2100, 'end': 0x2130}] if missing and start == 0x2000 else [],
                        'sha256': hashlib.sha256(data).hexdigest()})
    manifest = {'schema': 1, 'format': 'linux-process-mappings', 'complete': not missing,
                'exe_sha256': '0'*64 if bad_exe else profile['packed_sha256'], 'regions': regions}
    (capture/'capture.json').write_text(json.dumps(manifest))
    return capture, profile_path


def encrypted_fixture(root, plain=b'a complete synthetic original'):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from decrypt_copy import chacha8_call
    copies = root/'copies'; copies.mkdir()
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(IV)).encryptor()
    footer = bytearray(588)
    footer[:48] = cipher.update(FILE_KEY+NONCE+NONCE)+cipher.finalize()
    footer[568:572] = MARKER; footer[572:576] = bytes((0x24, 0, 0x20, 0))
    struct.pack_into('<Q', footer, 580, len(plain))
    path = copies/'sample.L0CK3D'; path.write_bytes(chacha8_call(plain, FILE_KEY, NONCE)[0]+footer)
    return path, copies, hashlib.sha256(plain).hexdigest()


class MemoryKeyCheckTests(unittest.TestCase):
    def test_process_candidate_verified_against_full_original_and_sources_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); capture, profile = process_fixture(root)
            copy, copies, digest = encrypted_fixture(root)
            before = {p: p.read_bytes() for p in capture.iterdir()}; encrypted_before = copy.read_bytes()
            result = check_memory(capture, root/'new', profile=profile, input_copy=copy,
                                  copy_root=copies, expected_marker=MARKER, expected_sha256=digest)
            self.assertEqual(result['status'], 'verified_for_file')
            self.assertEqual(result['verified_for_file'], 1)
            self.assertEqual((root/'new/process/master-candidate.bin').read_bytes(), IV+AES_KEY)
            self.assertEqual(result['candidates'][0]['verification_level'], 'known-original-sha256')
            self.assertEqual(copy.read_bytes(), encrypted_before)
            self.assertTrue(all(p.read_bytes() == data for p, data in before.items()))

    def test_wrong_iv_passes_footer_but_never_full_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); wrong = bytes([IV[0]^1])+IV[1:]+AES_KEY
            capture, profile = process_fixture(root, material=wrong)
            copy, copies, digest = encrypted_fixture(root)
            result = check_memory(capture, root/'new', profile=profile, input_copy=copy,
                                  copy_root=copies, expected_marker=MARKER, expected_sha256=digest)
            self.assertEqual(result['status'], 'candidate_found')
            self.assertEqual(result['footer_consistent'], 1)
            self.assertEqual(result['verified_for_file'], 0)
            self.assertFalse(list((root/'new').glob('verification-*')))
            self.assertEqual((root/'new/process/master-candidate.bin').read_bytes(), wrong)

    def test_footer_only_does_not_create_plaintext_or_report_verified_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); capture, profile = process_fixture(root)
            copy, copies, _ = encrypted_fixture(root)
            result = check_memory(capture, root/'new', profile=profile, input_copy=copy,
                                  copy_root=copies, expected_marker=MARKER)
            self.assertEqual(result['status'], 'candidate_found')
            self.assertEqual(result['footer_consistent'], 1)
            self.assertEqual(result['verified_for_file'], 0)
            self.assertFalse(list((root/'new').glob('verification-*')))

    def test_adjacent_aes_and_repeated_chacha_are_distinct_deduplicated_candidates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pair = ('AES_KEY='+AES_KEY.hex()+'\nAES_IV='+IV.hex()).encode()
            state = b'expand 32-byte k'+FILE_KEY+bytes(8)+NONCE+NONCE+FILE_KEY
            memory = root/'ram'; memory.write_bytes(pair+b'\0'+state+b'\0'+pair)
            result = check_memory(memory, root/'new')
            self.assertEqual(result['master_candidates'], 1)
            self.assertEqual(result['file_material_candidates'], 1)
            self.assertEqual(result['status'], 'candidate_found')
            self.assertNotIn(AES_KEY.hex(), json.dumps(result))
            self.assertNotIn(IV.hex(), json.dumps(result))

    def test_window_boundary_and_actual_progress_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); out = root/'out'; out.mkdir()
            pair = ('AES_IV='+IV.hex()+'\r\nAES_KEY='+AES_KEY.hex()).encode()
            data = b'\0'*220+pair+b'\0'*600
            progress = Progress('scan', interval=0.001, stream=io.StringIO())
            rows = scan_patterns(io.BytesIO(data), [{'file_offset': 0, 'bytes': len(data)}], out,
                                 progress, chunk_size=256)
            self.assertEqual(len(rows), 1); self.assertEqual(rows[0]['file_offset'], 220)
            self.assertEqual(progress.processed_bytes, len(data))
            self.assertEqual((out/rows[0]['candidate_file']).read_bytes(), IV+AES_KEY)

    def test_lime_gaps_are_not_joined_and_physical_location_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); pair = ('AES_KEY='+AES_KEY.hex()+'\nAES_IV='+IV.hex()).encode()
            pieces = [(0x1000, pair[:60]), (0x9000, pair[60:]), (0xf000, b'\0'*16+pair)]
            data = b''.join(struct.pack('<IIQQ8s', 0x4C694D45, 1, start, start+len(payload)-1, bytes(8))+payload
                            for start, payload in pieces)
            memory = root/'capture.lime'; memory.write_bytes(data)
            result = check_memory(memory, root/'new')
            self.assertEqual(result['coverage']['format'], 'lime')
            self.assertEqual(result['master_candidates'], 1)
            self.assertEqual(result['candidates'][0]['physical_address'], 0xf010)

    def test_qemu_real_synthetic_page_tables_extract_and_validate_master(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); profile_path, profile = profile_fixture(root)
            data = bytearray(profile['ram_bytes'])
            data[0x1010:0x1030] = bytes.fromhex(profile['entry']['hex'])
            struct.pack_into('<Q', data, 0x2008, 0x1005)
            struct.pack_into('<Q', data, 0x2010, 0x4005)
            struct.pack_into('<Q', data, 0x3000, 0x2005)
            data[0x4020] = 0x20; struct.pack_into('<Q', data, 0x4030, 0x2100)
            data[0x4100:0x4130] = IV+AES_KEY
            memory = root/'pc.ram'; memory.write_bytes(data)
            copy, copies, digest = encrypted_fixture(root)
            result = check_memory(memory, root/'new', kind='qemu', profile=profile_path,
                                  input_copy=copy, copy_root=copies, expected_marker=MARKER,
                                  expected_sha256=digest)
            self.assertEqual(result['verified_for_file'], 1)
            self.assertEqual(result['master_candidates'], 1)
            self.assertEqual(memory.read_bytes(), bytes(data))

    def test_unsupported_sample_is_unassessed_instead_of_not_found(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); capture, profile = process_fixture(root, bad_exe=True)
            result = check_memory(capture, root/'new', profile=profile)
            self.assertEqual(result['status'], 'not_assessed')
            self.assertEqual(result['verified_for_file'], 0)

    def test_empty_pointer_and_unreadable_page_are_different_outcomes(self):
        for pointer, missing, expected in [(0, False, 'not_found'), (0x2100, True, 'not_assessed')]:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); capture, profile = process_fixture(root, pointer=pointer, missing=missing)
                result = check_memory(capture, root/'new', profile=profile)
                self.assertEqual(result['status'], expected)

    def test_full_tar_gzip_verification_has_its_actual_evidence_level(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); capture, profile = process_fixture(root)
            packed = io.BytesIO()
            with tarfile.open(fileobj=packed, mode='w') as archive:
                item = tarfile.TarInfo('saved.txt'); item.size = 4; archive.addfile(item, io.BytesIO(b'data'))
            copy, copies, _ = encrypted_fixture(root, gzip.compress(packed.getvalue()))
            result = check_memory(capture, root/'new', profile=profile, input_copy=copy,
                                  copy_root=copies, expected_marker=MARKER, verify_archive='tar-gzip')
            self.assertEqual(result['status'], 'verified_for_file')
            self.assertIn('historical identity not independently proven', result['candidates'][0]['verification_level'])
            self.assertTrue((root/'new/verification-0000.tar.gz').exists())

    def test_broken_archive_is_candidate_not_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); capture, profile = process_fixture(root)
            copy, copies, _ = encrypted_fixture(root, b'not a valid archive')
            result = check_memory(capture, root/'new', profile=profile, input_copy=copy,
                                  copy_root=copies, expected_marker=MARKER, verify_archive='tar')
            self.assertEqual(result['status'], 'candidate_found')
            self.assertEqual(result['verified_for_file'], 0)
            self.assertIn('unverified_plaintext_file', result['candidates'][0])

    def test_existing_output_and_bad_copy_options_preserve_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); memory = root/'ram'; memory.write_bytes(b'unchanged')
            out = root/'out'; out.mkdir(); (out/'keep').write_bytes(b'keep')
            with self.assertRaises(FileExistsError): check_memory(memory, out)
            with self.assertRaises(ValueError): check_memory(memory, root/'new', expected_sha256='1'*64)
            self.assertEqual(memory.read_bytes(), b'unchanged'); self.assertEqual((out/'keep').read_bytes(), b'keep')
            self.assertFalse((root/'new').exists())

    def test_mutating_memory_is_not_assessed_or_verified(self):
        import memory_key_check
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); memory = root/'ram'; memory.write_bytes(b'unchanged')
            original = memory_key_check.scan_patterns
            def changed(*args, **kwargs):
                result = original(*args, **kwargs); memory.write_bytes(b'changed size now')
                return result
            with patch('memory_key_check.scan_patterns', side_effect=changed):
                result = check_memory(memory, root/'new')
            self.assertEqual(result['status'], 'not_assessed')
            self.assertEqual(result['verified_for_file'], 0)

    def test_cli_outputs_only_counts_and_separates_progress(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); pair = ('AES_KEY='+AES_KEY.hex()+'\nAES_IV='+IV.hex()).encode()
            memory = root/'ram'; memory.write_bytes(pair)
            args = [sys.executable, '-X', 'utf8', str(SKILL/'scripts/memory_key_check.py'),
                    '--input', str(memory), '--output', str(root/'new'), '--progress-file', str(root/'progress.json')]
            result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
            self.assertEqual(result.returncode, 3)
            self.assertEqual(json.loads(result.stdout)['status'], 'candidate_found')
            self.assertNotIn(AES_KEY.hex(), result.stdout+result.stderr)
            self.assertEqual(json.loads((root/'progress.json').read_text())['result_level'], 'candidate_found')

    def test_no_pattern_does_not_claim_no_key_in_the_memory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); memory = root/'ram'; memory.write_bytes(IV+AES_KEY+b'\0'*4096)
            result = check_memory(memory, root/'new')
            self.assertEqual(result['status'], 'not_found')
            self.assertIn('No hit is not proof of absence', result['limits'])
            self.assertNotIn('reviewed-process-va', result['coverage']['methods'])

    def test_invalid_lime_is_not_reported_as_a_completed_negative_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); memory = root/'broken.lime'
            memory.write_bytes(struct.pack('<IIQQ8s', 0x4C694D45, 2, 0, 10, bytes(8)))
            result = check_memory(memory, root/'new')
            self.assertEqual(result['status'], 'not_assessed')

    def test_empty_file_hash_does_not_verify_the_aes_key_or_iv(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); capture, profile = process_fixture(root)
            copy, copies, digest = encrypted_fixture(root, b'')
            result = check_memory(capture, root/'new', profile=profile, input_copy=copy,
                                  copy_root=copies, expected_marker=MARKER, expected_sha256=digest,
                                  capture_origin='pre-reboot')
            self.assertEqual(result['status'], 'candidate_found')
            self.assertEqual(result['verified_for_file'], 0)
            self.assertEqual(result['capture_origin'], 'pre-reboot')
            self.assertEqual(result['candidates'][0]['verification'], 'no_encrypted_content_candidate')


if __name__ == '__main__':
    unittest.main()
