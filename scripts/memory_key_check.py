#!/usr/bin/env python3
"""Check saved memory copies and verify candidates without exposing key bytes.

No live acquisition, network access, device reads or executable invocation.
Byte-pattern scans cover labelled AES pairs and a reviewed repeated ChaCha state;
they cannot identify arbitrary AES keys, recover overwritten RAM or prove absence.
"""
import argparse
import contextlib
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tarfile
import zlib

from recovery_progress import Progress, add_progress_options

DEFAULT_PROFILE = Path(__file__).resolve().parents[1] / 'assets/libgld-802ac85d.json'
KEY = rb'AES_KEY[ \t]*=[ \t]*([0-9a-fA-F]{64})(?![0-9a-fA-F])'
IV = rb'AES_IV[ \t]*=[ \t]*([0-9a-fA-F]{32})(?![0-9a-fA-F])'
SEPARATOR = rb'[ \t\r\n;]{1,32}'
PAIR_PATTERNS = [(re.compile(rb'(?<![A-Za-z0-9_])' + KEY + SEPARATOR + IV), False),
                 (re.compile(rb'(?<![A-Za-z0-9_])' + IV + SEPARATOR + KEY), True)]
CONSTANT = b'expand 32-byte k'


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as target:
        target.write(data)
        target.flush()
        os.fsync(target.fileno())


def saved_file(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Saved input cannot be a symbolic link')
    expected = path.lstat()
    if not stat.S_ISREG(expected.st_mode):
        raise ValueError('Only saved regular memory files are supported')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0))
    actual = os.fstat(fd)
    if not stat.S_ISREG(actual.st_mode) or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
        os.close(fd)
        raise ValueError('Only saved regular memory files are supported')
    return os.fdopen(fd, 'rb'), actual


def stamp(info):
    return info.st_size, info.st_mtime_ns, info.st_ctime_ns


def scan_patterns(source, ranges, destination, progress=None, chunk_size=4*1024*1024):
    """Scan bounded windows; never join separated LiME physical ranges."""
    if chunk_size < 256:
        raise ValueError('Scan chunks must be at least 256 bytes')
    candidates, seen = [], set()
    if progress:
        progress.phase = '内存结构扫描'
        progress.set_total(sum(r['bytes'] for r in ranges))

    def add(material, kind, offset, segment):
        digest = hashlib.sha256(material).hexdigest()
        if (kind, digest) in seen:
            return
        if len(candidates) >= 4096:
            raise ValueError('Candidate limit reached; scan is incomplete')
        seen.add((kind, digest))
        name = 'candidate-%04d.bin' % len(candidates)
        private_write(destination / name, material)
        row = {'material_type': kind, 'candidate_file': name, 'file_offset': offset,
               'material_sha256': digest, 'verification': 'structural_candidate'}
        if 'start' in segment:
            row['physical_address'] = segment['start'] + offset - segment['file_offset']
        candidates.append(row)

    for segment in ranges:
        source.seek(segment['file_offset'])
        remaining, consumed, carry = segment['bytes'], 0, b''
        while remaining:
            data = source.read(min(chunk_size, remaining))
            if not data:
                raise ValueError('Memory copy became truncated')
            window = carry + data
            base = segment['file_offset'] + consumed - len(carry)
            for pattern, reversed_order in PAIR_PATTERNS:
                for match in pattern.finditer(window):
                    first, second = match.group(1), match.group(2)
                    iv, key = (first, second) if reversed_order else (second, first)
                    material = bytes.fromhex(iv.decode('ascii') + key.decode('ascii'))
                    if any(material[:16]) and any(material[16:]):
                        add(material, 'aes-iv16-key32', base + match.start(), segment)
            at = window.find(CONSTANT)
            while at >= 0:
                state = window[at:at+104]
                if (len(state) == 104 and state[16:48] == state[72:104]
                        and state[56:64] == state[64:72] and any(state[16:48])):
                    add(state[16:48] + state[56:64], 'chacha-key32-nonce8', base + at, segment)
                at = window.find(CONSTANT, at + 1)
            consumed += len(data)
            remaining -= len(data)
            carry = window[-256:]
            if progress:
                progress.advance(len(data))
    return candidates


def extract_memory(source_path, kind, profile_path, destination, progress):
    source_path = Path(source_path)
    if kind == 'auto':
        if source_path.is_dir():
            kind = 'process-maps'
        else:
            with saved_file(source_path)[0] as source:
                header = source.read(4)
            kind = 'lime' if header in (b'EMiL', b'LiME') else 'elf' if header == b'\x7fELF' else 'raw'
    if kind == 'process-maps':
        import recover_process_key
        profile = json.loads(Path(profile_path).read_text(encoding='utf-8'))
        manifest = source_path / 'capture.json'
        with saved_file(manifest)[0] as saved:
            before = saved.read(8*1024*1024 + 1)
        if len(before) > 8*1024*1024:
            raise ValueError('Saved capture manifest exceeds 8 MiB')
        try:
            result = recover_process_key.recover(source_path, profile, destination / 'process')
        except recover_process_key.NoKeyMaterial:
            if before != manifest.read_bytes():
                raise ValueError('Saved capture manifest changed')
            return [], {'format': kind, 'methods': ['reviewed-process-va'], 'scan_complete': True,
                        'capture_complete': json.loads(before).get('complete')}
        if before != manifest.read_bytes():
            raise ValueError('Saved capture manifest changed')
        candidate = {'material_type': 'aes-iv16-key32',
                     'candidate_file': 'process/' + result['candidate_file'],
                     'verification': 'structural_candidate'}
        return [candidate], {'format': kind, 'methods': ['reviewed-process-va'],
                             'scan_complete': True, 'capture_complete': result['capture_complete']}
    with saved_file(source_path)[0] as source:
        before = os.fstat(source.fileno())
        if kind == 'qemu':
            import recover_ram_keys
            profile = json.loads(Path(profile_path).read_text(encoding='utf-8'))
            if not before.st_size:
                raise ValueError('Empty memory copy')
            with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
                result = recover_ram_keys.recover(data, profile, destination / 'qemu')
            rows = [{'material_type': 'aes-iv16-key32', 'candidate_file': 'qemu/' + r['master_file'],
                     'verification': 'structural_candidate'}
                    for r in result['master_candidates'] if 'master_file' in r]
            rows += [{'material_type': 'chacha-object', 'candidate_file': 'qemu/' + r['file'],
                      'verification': 'structural_candidate'} for r in result['file_objects']]
            coverage = {'format': kind, 'methods': ['reviewed-qemu-page-tables', 'reviewed-chacha-object'],
                        'scan_complete': True, 'input_bytes': before.st_size,
                        'mapping_rejections': sum('error' in r for r in result['master_candidates'])}
        else:
            if kind == 'lime':
                from inspect_lime import read_segments
                ranges, _ = read_segments(source, before.st_size)
            else:
                ranges = [{'file_offset': 0, 'bytes': before.st_size}]
            rows = scan_patterns(source, ranges, destination, progress)
            coverage = {'format': kind, 'methods': ['adjacent-labelled-aes-pair', 'repeated-chacha-state'],
                        'scan_complete': True, 'input_bytes': before.st_size,
                        'scanned_bytes': sum(r['bytes'] for r in ranges),
                        'limits': 'Byte patterns only; no arbitrary AES, ELF VA or physical page-table reconstruction'}
        if stamp(before) != stamp(os.fstat(source.fileno())):
            raise ValueError('Memory copy changed during scanning; candidates remain unassessed')
    return rows, coverage


def check_memory(input_path, output, *, kind='auto', profile=DEFAULT_PROFILE,
                 input_copy=None, copy_root=None, expected_marker=None, expected_sha256=None,
                 verify_archive=False, progress=None, capture_origin='unknown'):
    source = Path(input_path)
    if source.is_symlink():
        raise ValueError('Input cannot be a symbolic link')
    source = source.resolve(strict=True)
    output = Path(output).resolve()
    if output == source or (source.is_dir() and output.is_relative_to(source)):
        raise ValueError('Private output cannot replace or enter the saved capture')
    has_copy = input_copy is not None
    if has_copy != (copy_root is not None) or has_copy != (expected_marker is not None):
        raise ValueError('Copy verification needs input-copy, copy-root and reviewed expected-marker together')
    if (expected_sha256 or verify_archive) and not has_copy:
        raise ValueError('Full verification needs an independent encrypted copy')
    if verify_archive and verify_archive not in ('tar', 'tar-gzip', 'gzip'):
        raise ValueError('Archive validation needs an explicit supported format')
    if expected_sha256 and not re.fullmatch('[0-9a-fA-F]{64}', expected_sha256):
        raise ValueError('Expected SHA-256 must be a complete known-original digest')
    if capture_origin not in ('pre-reboot', 'post-reboot', 'not-rebooted', 'unknown'):
        raise ValueError('Unsupported capture provenance')
    if has_copy:
        from decrypt_copy import readonly_regular
        copy = Path(input_copy)
        root = Path(copy_root).resolve(strict=True)
        if not root.is_dir() or copy.is_symlink() or not copy.resolve(strict=True).is_relative_to(root):
            raise ValueError('Verification copy must be a regular independent file inside copy-root')
        with readonly_regular(copy, independent=True)[0]:
            pass
        if source.is_file() and os.path.samefile(source, copy):
            raise ValueError('Memory and encrypted copy cannot be the same input')
    output.mkdir(mode=0o700)
    report = {'schema': 1, 'status': 'not_assessed', 'capture_origin': capture_origin,
              'master_candidates': 0,
              'file_material_candidates': 0, 'footer_consistent': 0,
              'verified_for_file': 0, 'candidates': [],
              'limits': 'No hit is not proof of absence. Only supplied saved material and listed methods were checked.'}
    try:
        rows, coverage = extract_memory(source, kind, profile, output, progress)
        report['coverage'] = coverage
        unique, seen = [], set()
        for row in rows:
            path = output / row['candidate_file']
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if (row['material_type'], digest) not in seen:
                seen.add((row['material_type'], digest))
                row['material_sha256'] = digest
                unique.append(row)
        report['candidates'] = unique
        report['master_candidates'] = sum(r['material_type'] == 'aes-iv16-key32' for r in unique)
        report['file_material_candidates'] = len(unique) - report['master_candidates']
        report['status'] = 'candidate_found' if unique else 'not_found'
        if not unique and coverage.get('mapping_rejections'):
            report['status'] = 'not_assessed'
        if has_copy and report['master_candidates']:
            from decrypt_copy import decrypt_copy, readonly_regular, unwrap_record
            from file_layout import read_footer
            if progress:
                progress.phase = '内存候选与独立副本验证'
                progress.processed_bytes = progress.last_bytes = 0
                progress.set_total(None)
            with readonly_regular(input_copy, independent=True)[0] as encrypted:
                parsed = read_footer(encrypted, os.fstat(encrypted.fileno()).st_size, expected_marker)
                footer = parsed[0]
                encrypted_bytes = sum(length for _, length in parsed[4])
            for index, row in enumerate(unique):
                if row['material_type'] != 'aes-iv16-key32':
                    continue
                material = output / row['candidate_file']
                try:
                    unwrap_record(footer, material.read_bytes())
                except ValueError:
                    row['verification'] = 'footer_rejected'
                    continue
                row['verification'] = 'footer_consistent_candidate'
                report['footer_consistent'] += 1
                if not encrypted_bytes:
                    row['verification'] = 'no_encrypted_content_candidate'
                    continue
                if not expected_sha256 and not verify_archive:
                    continue
                suffix = {'tar': '.tar', 'tar-gzip': '.tar.gz', 'gzip': '.gz'}.get(verify_archive, '.plain')
                plain = output / ('verification-%04d' % index + suffix)
                try:
                    decoded = decrypt_copy(input_copy, plain, material, copy_root,
                                           expected_sha256, expected_marker)
                    if expected_sha256:
                        level = 'known-original-sha256'
                    else:
                        from verify_backup import validate
                        with contextlib.redirect_stdout(sys.stderr):
                            checked = validate(plain)
                        if checked.get('integrity_pass') is not True:
                            raise ValueError('Whole archive format is unsupported or not valid')
                        level = 'whole-archive-format; historical identity not independently proven'
                    row.update(verification='verified_for_file', verification_level=level,
                               verified_copy_sha256=decoded['sha256'], plaintext_file=plain.name)
                    report['verified_for_file'] += 1
                except (ValueError, OSError, EOFError, tarfile.TarError, zlib.error):
                    row['verification'] = 'full_verification_rejected'
                    if plain.exists():
                        row['unverified_plaintext_file'] = plain.name
            if report['verified_for_file']:
                report['status'] = 'verified_for_file'
        if progress:
            if report['status'] == 'not_assessed':
                progress.fail()
            else:
                progress.file_done(verified=bool(report['verified_for_file']), accepted=bool(expected_sha256 and report['verified_for_file']))
                progress.finish(report['status'])
    except (OSError, ValueError, KeyError, TypeError, struct.error) as error:
        report.update(status='not_assessed', error_type=type(error).__name__,
                      reason=str(error), verified_for_file=0)
        if progress:
            progress.fail()
    private_write(output / 'memory-key-report.json',
                  (json.dumps(report, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))
    return report


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, help='Saved memory file or process mapping directory')
    parser.add_argument('--format', choices=('auto', 'process-maps', 'qemu', 'raw', 'lime', 'elf'), default='auto')
    parser.add_argument('--profile', default=str(DEFAULT_PROFILE))
    parser.add_argument('--capture-origin', choices=('pre-reboot', 'post-reboot', 'not-rebooted', 'unknown'), default='unknown')
    parser.add_argument('--output', required=True, help='New private directory on independent storage')
    parser.add_argument('--input-copy')
    parser.add_argument('--copy-root')
    from file_layout import parse_marker
    parser.add_argument('--expected-marker', type=parse_marker)
    parser.add_argument('--expected-sha256')
    parser.add_argument('--verify-archive', choices=('tar', 'tar-gzip', 'gzip'))
    add_progress_options(parser)
    args = parser.parse_args()
    progress = None
    try:
        progress = Progress('内存密钥检查', args.progress_file, args.progress_interval)
        report = check_memory(args.input, args.output, kind=args.format, profile=args.profile,
                              input_copy=args.input_copy, copy_root=args.copy_root,
                              expected_marker=args.expected_marker, expected_sha256=args.expected_sha256,
                              verify_archive=args.verify_archive, progress=progress,
                              capture_origin=args.capture_origin)
    except (OSError, ValueError) as error:
        if progress:
            progress.fail()
        print(json.dumps({'status': 'not_assessed', 'reason': str(error)}, ensure_ascii=False))
        return 1
    except KeyboardInterrupt:
        if progress:
            progress.fail(interrupted=True)
        return 130
    print(json.dumps({k: report[k] for k in ('status', 'master_candidates', 'file_material_candidates',
                                           'footer_consistent', 'verified_for_file')}, ensure_ascii=False))
    return {'verified_for_file': 0, 'not_assessed': 1, 'not_found': 2, 'candidate_found': 3}[report['status']]


if __name__ == '__main__':
    raise SystemExit(main())
