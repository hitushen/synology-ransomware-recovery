#!/usr/bin/env python3
"""Read archives without extracting or executing their contents."""
import argparse
import collections
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import struct
import tarfile
import time
import zlib
from recovery_progress import Progress, ProgressReader, add_progress_options

CHUNK = 4 * 1024 * 1024


class SingleGzipReader(io.RawIOBase):
    """Bounded single-member gzip reader; reject truncation and trailing streams."""
    def __init__(self, source):
        super().__init__()
        self.source = source
        self.decoder = zlib.decompressobj(31)
        self.pending = b''
        self.finished = False

    def readable(self):
        return True

    def readinto(self, buffer):
        if not buffer or self.finished:
            return 0
        while True:
            if not self.pending:
                self.pending = self.source.read(65536)
                if not self.pending:
                    raise ValueError('Truncated gzip stream')
            data = self.decoder.decompress(self.pending, len(buffer))
            self.pending = self.decoder.unconsumed_tail
            if self.decoder.eof:
                if self.decoder.unused_data or self.source.read(1):
                    raise ValueError('Extra data or concatenated gzip stream')
                self.finished = True
            if data:
                buffer[:len(data)] = data
                return len(data)
            if self.finished:
                return 0


def strict_gzip(source):
    return io.BufferedReader(SingleGzipReader(source), buffer_size=65536)


class TarAuditReader:
    """Track decompressed offsets without retaining archive payload in RAM."""
    def __init__(self, source):
        self.source = source
        self.total = 0
        self.last_nonzero = -1

    def read(self, amount=-1):
        data = self.source.read(amount)
        nonzero_end = len(data.rstrip(b'\0'))
        if nonzero_end:
            self.last_nonzero = self.total + nonzero_end - 1
        self.total += len(data)
        return data

def lfs_oid(path):
    parts = PurePosixPath(path).parts
    if parts and re.fullmatch(r'[0-9a-f]{64}', parts[-1]):
        return parts[-1]
    if (len(parts) >= 3 and re.fullmatch(r'[0-9a-f]{2}', parts[-3])
            and re.fullmatch(r'[0-9a-f]{2}', parts[-2])
            and re.fullmatch(r'[0-9a-f]{60}', parts[-1])):
        return ''.join(parts[-3:])
    return None

def drain(stream):
    digest = hashlib.sha256()
    size = 0
    while data := stream.read(CHUNK):
        digest.update(data)
        size += len(data)
    return size, digest.hexdigest()

def bundle(stream):
    first = stream.readline(256)
    if first not in (b'# v2 git bundle\n', b'# v3 git bundle\n'):
        raise ValueError('Unknown Git bundle version')
    algorithm = 'sha1'
    header_size = len(first)
    while True:
        line = stream.readline(16385)
        header_size += len(line)
        if not line or len(line) > 16384 or header_size > 1024 * 1024:
            raise ValueError('Invalid Git bundle header')
        if line == b'\n':
            break
        if line.startswith(b'@object-format='):
            algorithm = line.strip().split(b'=', 1)[1].decode()
            if algorithm not in ('sha1', 'sha256'):
                raise ValueError('Unsupported Git object hash')
    pack_header = stream.read(12)
    if len(pack_header) != 12 or pack_header[:4] != b'PACK':
        raise ValueError('Git bundle lacks PACK header')
    version, objects = struct.unpack('>II', pack_header[4:])
    if version not in (2, 3):
        raise ValueError('Unsupported Git PACK version')
    digest = hashlib.new(algorithm)
    digest.update(pack_header)
    checksum_size = digest.digest_size
    tail = b''
    while data := stream.read(CHUNK):
        combined = tail + data
        if len(combined) > checksum_size:
            digest.update(combined[:-checksum_size])
        tail = combined[-checksum_size:]
    if len(tail) != checksum_size or digest.digest() != tail:
        raise ValueError('Git PACK trailing hash mismatch')
    return objects

def walk_tar(stream, kind='generic', depth=0, *, inspect_contents=True):
    if depth > 3:
        raise ValueError('Unexpected nested archive depth')
    counts = collections.Counter()
    result = {'members': 0, 'regular_files': 0, 'git_bundles_checked': 0,
              'git_pack_objects': 0, 'lfs_objects_checked': 0, 'lfs_files_without_oid': 0, 'links_not_followed': 0,
              'unsafe_paths_not_extracted': 0, 'gzip_members': [], 'backup_information': None}
    started = time.time()
    audited = TarAuditReader(stream)
    with tarfile.open(fileobj=audited, mode='r|') as archive:
        for member in archive:
            result['members'] += 1
            path = PurePosixPath(member.name)
            counts[path.parts[0] if path.parts else '.'] += 1
            if path.is_absolute() or '..' in path.parts:
                result['unsafe_paths_not_extracted'] += 1
            if not member.isfile():
                if member.issym() or member.islnk():
                    result['links_not_followed'] += 1
                continue
            result['regular_files'] += 1
            with archive.extractfile(member) as body:
                if not inspect_contents:
                    size, _ = drain(body)
                    if size != member.size:
                        raise ValueError('Truncated archive member')
                elif member.name.endswith('backup_information.yml'):
                    if member.size > 1024 * 1024:
                        raise ValueError('Oversized backup metadata')
                    text = body.read().decode('utf-8')
                    info = {}
                    for key in ('gitlab_version', 'backup_id', 'skipped', 'installation_type'):
                        match = re.search(r'^:' + key + r':\s*(.*)$', text, re.M)
                        info[key] = match.group(1).strip().strip("'\"") if match else None
                    result['backup_information'] = info
                elif member.name.endswith('.gz'):
                    with strict_gzip(body) as expanded:
                        if member.name.endswith('.tar.gz'):
                            child_kind = 'lfs' if 'lfs' in path.name.lower() else 'generic'
                            checked = walk_tar(expanded, child_kind, depth + 1)
                            checked['remaining_decompressed_bytes'] = checked['tar_trailing_bytes']
                            checked['gzip_crc_and_length_pass'] = True
                        else:
                            size, digest = drain(expanded)
                            checked = {'gzip_crc_and_length_pass': True, 'decompressed_bytes': size,
                                       'decompressed_sha256': digest}
                    result['gzip_members'].append({'member': member.name, 'validation': checked})
                elif member.name.endswith('.bundle'):
                    result['git_pack_objects'] += bundle(body)
                    result['git_bundles_checked'] += 1
                elif kind == 'lfs':
                    size, digest = drain(body)
                    oid = lfs_oid(path)
                    if size != member.size or (oid is not None and digest != oid):
                        raise ValueError('LFS object SHA256 mismatch: ' + member.name)
                    result['lfs_objects_checked' if oid else 'lfs_files_without_oid'] += 1
                elif path.name == 'gitlab-secrets.json':
                    if member.size > 4 * 1024 * 1024:
                        raise ValueError('Oversized secrets JSON')
                    data = body.read()
                    decoded = json.loads(data)
                    if not isinstance(decoded, dict):
                        raise ValueError('Unexpected secrets JSON structure')
                    result['secrets_json'] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                                              'top_level_keys': len(decoded)}
                else:
                    size, _ = drain(body)
                    if size != member.size:
                        raise ValueError('Truncated archive member')
            if time.time() - started > 20:
                print(json.dumps({'event': 'archive_validation', 'kind': kind, 'members_checked': result['members']}), flush=True)
                started = time.time()
        result['tar_body_end_offset'] = archive.offset
    # tarfile accepts a single zero block or even EOF without the two required
    # end blocks, and its stream buffer may already contain trailing bytes.
    # Audit all bytes, including read-ahead and the remainder, before passing.
    drain(audited)
    end = result['tar_body_end_offset']
    trailing = audited.total - end
    if trailing < 1024 or audited.total % 512 or audited.last_nonzero >= end:
        raise ValueError('TAR requires two zero end blocks and only aligned zero trailing bytes')
    result.update(tar_trailing_bytes=trailing, tar_trailing_nonzero_bytes=0,
                  tar_terminator_pass=True, contents_inspected=inspect_contents)
    result['top_level_counts'] = dict(counts)
    return result

def validate(path, expected_sha256=None, progress=None, *, inspect_tar_contents=True):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('Use a regular independent saved file')
    if expected_sha256 is not None and not re.fullmatch(r'[0-9a-fA-F]{64}', expected_sha256):
        raise ValueError('Expected SHA256 must be 64 hexadecimal characters')
    before = path.stat()
    result = {'path': str(path), 'bytes': before.st_size}
    if progress:
        progress.set_total(before.st_size, 1, path.name)
    if path.name.endswith('.tar'):
        with path.open('rb') as stream:
            checked = walk_tar(ProgressReader(stream, progress) if progress else stream,
                               inspect_contents=inspect_tar_contents)
        result.update(format='tar', validation=checked, integrity_pass=True)
    elif path.name.endswith('.gz'):
        with path.open('rb') as source, strict_gzip(ProgressReader(source, progress) if progress else source) as expanded:
            if path.name.endswith('.tar.gz'):
                checked = walk_tar(expanded)
                checked['remaining_decompressed_bytes'] = checked['tar_trailing_bytes']
            else:
                size, digest = drain(expanded)
                checked = {'decompressed_bytes': size, 'decompressed_sha256': digest}
        result.update(format='gzip', validation=checked, gzip_crc_and_length_pass=True, integrity_pass=True)
    elif path.name.endswith('.json'):
        with path.open('r') as source:
            data = json.load(source)
        result.update(format='json', json_type=type(data).__name__, syntax_pass=True)
    elif path.name.endswith('.dump'):
        with path.open('rb') as source:
            magic = source.read(5)
        result.update(format='postgres-custom', header_pass=magic == b'PGDMP',
                      limitation='Header checked only; use original SHA256 and later pg_restore validation')
    else:
        result.update(format='opaque', limitation='Requires original checksum or application-specific validation')
    if expected_sha256 is not None:
        if progress:
            progress.phase = '历史原件 SHA 校验'
            progress.processed_bytes = progress.last_bytes = 0
            progress.set_total(before.st_size, 1, path.name)
        with path.open('rb') as source:
            _, actual = drain(ProgressReader(source, progress) if progress else source)
        if actual != expected_sha256.lower():
            raise ValueError('Known-original SHA256 mismatch')
        result['matches_expected_sha256'] = True
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        # SMB may finalize mtime after close; only an exact content hash can clear this ambiguity.
        if expected_sha256 is None:
            raise ValueError('Recovered file metadata changed during validation; recheck content hash')
        with path.open('rb') as source:
            _, actual_sha256 = drain(source)
        if actual_sha256 != expected_sha256:
            raise ValueError('Recovered contents changed during validation')
        result['metadata_changed_but_content_sha256_verified'] = True
    if progress:
        progress.file_done(verified=result.get('integrity_pass') is True,
                           accepted=result.get('matches_expected_sha256') is True)
    return result

def self_test():
    import tempfile
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        content = b'blob contents'
        oid = hashlib.sha256(content).hexdigest()
        packed = io.BytesIO()
        with tarfile.open(fileobj=packed, mode='w') as archive:
            for name in (oid, './' + oid[:2] + '/' + oid[2:4] + '/' + oid[4:]):
                entry = tarfile.TarInfo(name)
                entry.size = len(content)
                archive.addfile(entry, io.BytesIO(content))
        inner = gzip.compress(packed.getvalue())
        path = root / 'backup.tar'
        with tarfile.open(path, mode='w') as archive:
            entry = tarfile.TarInfo('lfs.tar.gz')
            entry.size = len(inner)
            archive.addfile(entry, io.BytesIO(inner))
        result = validate(path)
        assert result['integrity_pass']
        assert result['validation']['gzip_members'][0]['validation']['lfs_objects_checked'] == 2
        assert lfs_oid('./tmp/incomplete-upload') is None
        bad = io.BytesIO()
        with tarfile.open(fileobj=bad, mode='w') as archive:
            entry = tarfile.TarInfo('aa/bb/' + '0' * 60)
            entry.size = len(content)
            archive.addfile(entry, io.BytesIO(content))
        bad.seek(0)
        try:
            walk_tar(bad, 'lfs')
            raise AssertionError('Bad sharded LFS hash accepted')
        except ValueError:
            pass
        with path.open('ab') as output:
            output.write(b'nonzero trailer')
        try:
            validate(path)
            raise AssertionError('Nonzero TAR trailer accepted')
        except ValueError:
            pass
        pack = b'PACK' + struct.pack('>II', 2, 0)
        good = b'# v2 git bundle\n' + b'0' * 40 + b' refs/heads/main\n\n' + pack + hashlib.sha1(pack).digest()
        assert bundle(io.BytesIO(good)) == 0
        try:
            bundle(io.BytesIO(good[:-1] + b'X'))
            raise AssertionError('Bad PACK checksum accepted')
        except ValueError:
            pass
    print('Archive self-test passed: nested gzip, LFS hash, PACK hash, trailing-data detection')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', nargs='?')
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--expected-sha256')
    add_progress_options(parser)
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        if not args.path:
            parser.error('path is required unless --self-test is used')
        progress = Progress('归档完整校验', args.progress_file, args.progress_interval)
        try:
            result = validate(args.path, args.expected_sha256, progress)
        except BaseException as error:
            progress.fail(interrupted=isinstance(error, KeyboardInterrupt))
            raise
        if result.get('integrity_pass') is False or result.get('header_pass') is False:
            progress.fail()
        else:
            progress.finish('known-original' if result.get('matches_expected_sha256') else
                            'format-verified' if result.get('integrity_pass') else 'unverified')
        print(json.dumps(result, indent=2))
        if result.get('integrity_pass') is False or result.get('header_pass') is False:
            raise SystemExit(1)
