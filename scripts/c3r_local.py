#!/usr/bin/env python3
"""本地端：接收 c3r_btrfs.py 的输出，解包、验证、挑选最佳候选、生成统计。

依赖：Python 3.8+；可选 Pillow（图片完整解码）、pillow-heif（HEIC）、ffmpeg（视频/音频解码，需在 PATH 中）。
没有这些依赖时对应格式记为 not_checked，不会误判为失败。

子命令：
  extract  STREAM.tar|-  OUT_DIR          解包 tar 流（- 为 stdin），边写边算 SHA-256 -> OUT_DIR/_extracted.jsonl
  validate OUT_DIR [--known DIR ...] [--workers N]
                                          核对 SHA、完整解码、与已知原件对照，为每个源文件选最佳候选
                                          -> _validation.jsonl、_best.jsonl、_summary.json
  apply-patch  DIR                       把 *.c3rpatch 打到同名已导出文件上（原字节存 *.c3rbak）
  revert-patch DIR [--only FILE]          用 *.c3rbak 回退补丁
  report   SURVEY.jsonl.gz [--depth N]   按目录层级汇总 survey 结果（文件数 / 原始字节）
"""
import argparse
import collections
import contextlib
import gzip
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import uuid
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from pathlib import Path, PurePosixPath, PureWindowsPath
from recovery_progress import Progress, add_progress_options

IMG = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.tif', '.tiff', '.heic', '.heif'}
AV = {'.mp4', '.mov', '.m4v', '.avi', '.mkv', '.3gp', '.mts', '.m2ts', '.ts', '.wmv', '.flv', '.webm',
      '.mp3', '.flac', '.m4a', '.aac', '.wav', '.ogg'}
# ffmpeg 输出到空 muxer 时，iPhone 可变帧率视频会触发这类时间戳警告，与数据完整性无关
BENIGN = (b'non monotonically increasing dts to muxer', b'Last message repeated')


def sha256(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(8 << 20), b''):
            h.update(b)
    return h.hexdigest()


def decode(p):
    ext = p.suffix.lower()
    if ext in IMG:
        try:
            from PIL import Image
            Image.MAX_IMAGE_PIXELS = None
            try:
                from pillow_heif import register_heif_opener
                register_heif_opener()
            except ImportError:
                if ext in ('.heic', '.heif'):
                    return 'not_checked'
        except ImportError:
            return 'not_checked'
        try:
            with Image.open(p) as im:
                for index in range(getattr(im, 'n_frames', 1)):
                    im.seek(index)
                    im.load()
            return 'decoded'
        except Exception as e:
            return 'decode_error: %s' % e
    if ext in AV:
        if not shutil.which('ffmpeg'):
            return 'not_checked'
        r = subprocess.run(['ffmpeg', '-v', 'error', '-xerror', '-i', str(p),
                            '-map', '0:v?', '-map', '0:a?', '-f', 'null', '-'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=False, encoding=None)
        err = b'\n'.join(l for l in r.stderr.splitlines() if not any(k in l for k in BENIGN))
        return 'decoded' if r.returncode == 0 and not err.strip() else 'decode_error: %s' % err[:300].decode('utf-8', 'replace')
    if ext in ('.tar', '.gz'):
        from verify_backup import validate
        try:
            # Archive auditors may emit periodic details; keep worker output
            # out of the parent CLI's single structured result.
            with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink):
                checked = validate(p)
            return 'decoded' if checked.get('integrity_pass') else 'not_checked'
        except Exception as error:
            return 'decode_error: %s' % error
    return 'not_checked'


def cmd_extract(args):
    # This integrated copy uses a fresh directory and exclusive files: never
    # silently overwrite prior recovery outputs or follow archive link members.
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=False)
    src = sys.stdin.buffer if args.stream == '-' else open(args.stream, 'rb')
    n = 0
    progress = getattr(args, 'progress', None)
    try:
        with tarfile.open(fileobj=src, mode='r|') as tar, open(out / '_extracted.jsonl', 'x', encoding='utf-8') as log:
            for m in tar:
                posix = PurePosixPath(m.name)
                win = PureWindowsPath(m.name)
                parts = posix.parts
                if (not m.isfile() or not parts or '..' in parts or posix.is_absolute()
                        or win.drive or '\\' in m.name or ':' in m.name or m.name == '_extracted.jsonl'):
                    raise ValueError('Refusing unsafe, linked or receipt-colliding archive member')
                if os.name == 'nt' and any(part.endswith((' ', '.')) or PureWindowsPath(part).is_reserved()
                                            or any(c in part for c in '<>"|?*') for part in parts):
                    raise ValueError('Member needs a reversible Windows filename map before extraction')
                dest = out.joinpath(*parts)
                if not dest.resolve().is_relative_to(out.resolve()):
                    raise ValueError('Archive path leaves the new output directory')
                dest.parent.mkdir(parents=True, exist_ok=True)
                h = hashlib.sha256()
                length = 0
                # Existing files, duplicate names and case collisions refuse.
                with tar.extractfile(m) as f, open(dest, 'xb') as d:
                    for b in iter(lambda: f.read(8 << 20), b''):
                        h.update(b)
                        d.write(b)
                        length += len(b)
                        if progress and m.name != '_c3r_manifest.jsonl':
                            progress.advance(len(b), m.name)
                if length != m.size:
                    raise ValueError('Archive member length mismatch; output is unaccepted')
                log.write(json.dumps({'name': m.name, 'size': length, 'sha256': h.hexdigest()}, ensure_ascii=False) + '\n')
                log.flush()
                n += 1
                if progress and m.name != '_c3r_manifest.jsonl':
                    progress.file_done()
    finally:
        if args.stream != '-':
            src.close()
    print('extracted %d members -> %s' % (n, out))


def known_index(dirs):
    idx = {}
    for d in dirs or []:
        for p in Path(d).rglob('*'):
            if p.is_file():
                size = p.stat().st_size
                names = {p.name.lower()}
                head, sep, rest = p.name.partition('-')
                if sep and head.isdigit():
                    names.add(rest.lower())   # 兼容整理时加的 "0056-原名" 序号前缀
                for nm in names:
                    idx.setdefault((nm, size), []).append(p)
    return idx


def file_identity(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('Validation requires an independent regular file')
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def check(job):
    rec, p, ext_sha, known = job[:4]
    options = job[4] if len(job) > 4 else {}
    row = {'path': rec['path'], 'member': rec['member'], 'variant': rec['variant'], 'status': rec['status'],
           'bytes': rec.get('bytes')}
    # Always reread the current file; the extraction log may be stale after
    # patching, interruption or later modifications.
    before = file_identity(p) if p.is_file() and not p.is_symlink() else None
    actual_sha = sha256(p) if before is not None else None
    row['sha_ok'] = actual_sha == rec['sha256'] and p.exists()
    row['extraction_log_sha_matches'] = ext_sha == actual_sha if ext_sha is not None else None
    cached = options.get('cached') or {}
    reused = (row['sha_ok'] and cached.get('sha_ok') is True
              and cached.get('verdict') == 'ok' and cached.get('decode') == 'decoded'
              and cached.get('cache_key') == options.get('cache_key'))
    row['decode'] = 'decoded' if reused else decode(p) if row['sha_ok'] else 'missing'
    row['decode_reused'] = bool(reused)
    if 'cache_key' in options:
        row['cache_key'] = options['cache_key']
    if known:
        # 同名同大小可能有多个副本；任一一致即算一致，全部不一致才算不一致（本地副本本身也可能有坏块）
        row['known_original_match'] = False
        for original in known:
            original_before = file_identity(original)
            original_sha = sha256(original)
            if file_identity(original) != original_before:
                raise ValueError('Known original changed during hash validation')
            if original_sha == rec['sha256']:
                if sha256(original) != original_sha or file_identity(original) != original_before:
                    raise ValueError('Known original changed during hash validation')
                row['known_original_match'] = True
                break
    try:
        row['changed_during_check'] = before is not None and file_identity(p) != before
        # Windows st_ctime is creation time; a same-size write followed by
        # restored mtime can leave every stat field unchanged. After expensive
        # checks, reread content rather than treating metadata as proof.
        row['content_rechecked_after_validation'] = False
        if row['sha_ok'] and not row['changed_during_check'] and (known or (not reused and row['decode'] == 'decoded')):
            row['content_rechecked_after_validation'] = True
            row['changed_during_check'] = sha256(p) != actual_sha or file_identity(p) != before
    except (OSError, ValueError):
        row['changed_during_check'] = before is not None
    if row['changed_during_check']:
        row.update(sha_ok=False, decode='file_changed', decode_reused=False)
    if not row['sha_ok'] or row.get('known_original_match') is False:
        row['verdict'] = 'bad'
    elif row.get('known_original_match') is True or row['decode'] == 'decoded':
        row['verdict'] = 'ok'
    elif row['decode'] == 'not_checked':
        row['verdict'] = 'unverified'
    else:
        row['verdict'] = 'bad'
    return row


@contextlib.contextmanager
def validation_lock(out, lock_name='_validation.lock'):
    """One validator per output directory; OS releases the lock after a crash."""
    path = Path(out) / lock_name
    if path.is_symlink():
        raise ValueError('Validation lock cannot be a link')
    with path.open('a+b') as handle:
        if not handle.tell():
            handle.write(b'0'); handle.flush()
        handle.seek(0)
        if os.name == 'nt':
            import msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == 'nt':
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def load_validation_journal(path):
    """Read once on explicit resume; discard only an interrupted final record."""
    path = Path(path)
    if not path.exists():
        return {}
    if path.is_symlink():
        raise ValueError('Validation journal cannot be a link')
    rows, end = {}, 0
    with path.open('rb') as source:
        while line := source.readline():
            try:
                row = json.loads(line)
            except (ValueError, UnicodeError):
                if line.endswith(b'\n'):
                    raise ValueError('Invalid complete validation journal record')
                break
            rows[row['cache_key']] = row
            end = source.tell()
    if end != path.stat().st_size:
        with path.open('r+b') as target:
            target.truncate(end)
    return rows


def cmd_validate(args):
    out = Path(args.out)
    with validation_lock(out):
        return _validate_batch(args, out)


def select_source(rs):
    good = [r for r in rs if r['verdict'] == 'ok']
    pick = next((r for r in good if r.get('known_original_match')), good[0] if good else rs[0])
    if not good:
        kind = 'unverified' if any(r['verdict'] == 'unverified' for r in rs) else 'failed'
    elif pick['status'] == 'exact':
        kind = 'exact_' + ('decoded' if pick['decode'] == 'decoded' else 'sha_only')
    elif pick['status'] == 'needs_inference':
        kind = 'inferred_decoded' if pick['decode'] == 'decoded' else 'inferred_unverifiable'
    else:
        kind = 'partial_' + ('decoded' if pick['decode'] == 'decoded' else 'unverified')
    if len(good) > 1 and pick['status'] != 'exact':
        kind += '_multi_candidates_ok'
    return dict(pick, outcome=kind, candidates=len(rs))


def source_exception(row):
    full_original = row.get('known_original_match') is True and row['sha_ok']
    format_checked_exact = row['status'] == 'exact' and row['verdict'] == 'ok' and row['decode'] == 'decoded'
    if full_original or format_checked_exact:
        return None
    reason = (row.get('error_type') or 'sha_mismatch_or_missing' if not row['sha_ok'] else
              'known_original_mismatch' if row.get('known_original_match') is False else
              row['decode'] if row['verdict'] == 'bad' else
              'inferred_or_partial' if row['verdict'] == 'ok' else row['verdict'])
    if row.get('changed_during_check'):
        reason = 'file_changed'
    return {'path': row['path'], 'member': row['member'], 'outcome': row['outcome'],
            'reason': reason, 'detail': row.get('error'),
            'action': 'review_unresolved_source', 'source_complete': True}


def _validate_batch(args, out):
    with (out / '_c3r_manifest.jsonl').open(encoding='utf-8') as source:
        manifest = [json.loads(line) for line in source]
    extracted = {}
    if (out / '_extracted.jsonl').exists():
        with (out / '_extracted.jsonl').open(encoding='utf-8') as source:
            for line in source:
                record = json.loads(line)
                extracted[record['name']] = record['sha256']
    known = known_index(args.known)
    jobs, skipped = [], collections.Counter()
    for rec in manifest:
        if 'member' not in rec:
            skipped[rec['status']] += 1
            continue
        orig_name = os.path.basename(rec['path'])[:-len('.L0CK3D')]
        jobs.append((rec, out / rec['member'], extracted.get(rec['member']), known.get((orig_name.lower(), rec['orig']))))
    progress = getattr(args, 'progress', None)
    if progress:
        progress.set_total(None, len(jobs))
    journal_path = out / '_validation_journal.jsonl'
    if journal_path.is_symlink():
        raise ValueError('Validation journal cannot be a link')
    cached = load_validation_journal(journal_path) if getattr(args, 'resume', False) else {}
    version = hashlib.sha256(Path(__file__).read_bytes().replace(b'\r\n', b'\n')).hexdigest()
    prepared = []
    for job in jobs:
        rec, path, extract_sha, originals = job
        key = hashlib.sha256(json.dumps({'record': rec, 'extract_sha': extract_sha,
              'known': [str(p.resolve()) for p in originals or []], 'validator': version},
              sort_keys=True, ensure_ascii=False).encode('utf-8')).hexdigest()
        prepared.append((*job, {'cache_key': key, 'cached': cached.get(key)}))
    completed_rows = []
    accepted_sources = set()
    outstanding = collections.Counter(job[0]['path'] for job in prepared)
    source_rows = collections.defaultdict(list)
    exceptions = []
    validation_run_id = uuid.uuid4().hex
    exception_path = out / '_exceptions.jsonl'
    if exception_path.is_symlink():
        raise ValueError('Exception report cannot be a link')
    workers = args.workers
    if workers < 1:
        raise ValueError('Workers must be positive')
    with journal_path.open('a' if getattr(args, 'resume', False) else 'w', encoding='utf-8') as journal, \
            exception_path.open('w', encoding='utf-8') as exception_report:
        def emit_exception(row):
            row['validation_run_id'] = validation_run_id
            exceptions.append(row)
            exception_report.write(json.dumps(row, ensure_ascii=False) + '\n')
            exception_report.flush()
        for rec in manifest:
            if 'member' not in rec and rec['status'] not in ('not_encrypted', 'cancelled'):
                emit_exception({'path': rec.get('path'), 'outcome': 'not_extracted',
                                'reason': rec['status'], 'action': 'review_unresolved_source',
                                'source_complete': True})
        with ProcessPoolExecutor(workers) as ex:
            remaining = iter(enumerate(prepared))
            pending = {}
            def fill():
                while len(pending) < workers*2:
                    try:
                        index, job = next(remaining)
                    except StopIteration:
                        return
                    pending[ex.submit(check, job)] = index
            fill()
            while pending:
                done, _ = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    index = pending.pop(future)
                    try:
                        row = future.result()
                    except Exception as error:
                        rec = prepared[index][0]
                        row = {k: rec.get(k) for k in ('path', 'member', 'variant', 'status', 'bytes')}
                        row.update(sha_ok=False, decode='worker_error', verdict='bad',
                                   error_type=type(error).__name__, error=str(error)[:300], decode_reused=False,
                                   cache_key=prepared[index][4]['cache_key'])
                    completed_rows.append((index, row))
                    journal.write(json.dumps(row, ensure_ascii=False) + '\n')
                    journal.flush()
                    source_rows[row['path']].append((index, row))
                    outstanding[row['path']] -= 1
                    if outstanding[row['path']] == 0:
                        final_rows = [r for _, r in sorted(source_rows.pop(row['path']))]
                        exception = source_exception(select_source(final_rows))
                        if exception:
                            emit_exception(exception)
                    if len(completed_rows) % 64 == 0:
                        os.fsync(journal.fileno())
                    if progress:
                        progress.current_file = row['member']
                        accepted = (row.get('known_original_match') is True and row['sha_ok']
                                    and row['path'] not in accepted_sources)
                        if accepted:
                            accepted_sources.add(row['path'])
                        if row['verdict'] == 'bad':
                            progress.failed_files += 1
                        progress.file_done(verified=row['decode']=='decoded', accepted=accepted)
                fill()
        journal.flush(); os.fsync(journal.fileno())
        exception_report.flush(); os.fsync(exception_report.fileno())
    # Live progress follows actual completion; output selection retains the
    # original manifest order for deterministic candidate preferences.
    rows = [row for _, row in sorted(completed_rows, key=lambda pair: pair[0])]
    with open(out / '_validation.jsonl', 'w', encoding='utf-8') as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')
    by_src = collections.defaultdict(list)
    for r in rows:
        by_src[r['path']].append(r)
    outcomes, best = collections.Counter(), []
    for src, rs in by_src.items():
        pick = select_source(rs)
        outcomes[pick['outcome']] += 1
        best.append(pick)
    with open(out / '_best.jsonl', 'w', encoding='utf-8') as f:
        for r in best:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')
    km = collections.Counter(r.get('known_original_match') for r in rows if 'known_original_match' in r)
    summary = {'sources': len(by_src), 'outcomes': dict(outcomes), 'not_extracted': dict(skipped),
               'validation_run_id': validation_run_id,
               'decode_reused': sum(r.get('decode_reused', False) for r in rows),
               'known_original_match': {str(k): v for k, v in km.items()},
               'note': '结果基于当前文件回读 SHA；not_checked 单列未验证，已知原件不匹配须查明版本/损坏；'
                       'exact 仍需映射与适用的逐块校验，不能仅凭标签归因原件损坏'}
    summary['exceptions'] = len(exceptions)
    (out / '_summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=1), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False, indent=1))
    return summary


def _records(path):
    import struct
    with open(path, 'rb') as f:
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                return
            off, ln = struct.unpack('<QQ', hdr)
            yield off, f.read(ln)


def cmd_apply_patch(args):
    """把 c3r_btrfs.py patch 导出的 *.c3rpatch 打到同名已导出文件上；被覆盖的原字节存为 *.c3rbak，可用 revert-patch 回退。"""
    import struct
    root = Path(args.dir)
    done = 0
    for pf in root.rglob('*.c3rpatch'):
        target = Path(str(pf)[:-len('.c3rpatch')].rsplit('.', 1)[0])
        bak = Path(str(target) + '.c3rbak')
        if not target.exists() or bak.exists():
            continue
        with open(target, 'r+b') as t, open(bak, 'wb') as b:
            for off, data in _records(pf):
                t.seek(off)
                old = t.read(len(data))
                b.write(struct.pack('<QQ', off, len(old)) + old)
                t.seek(off)
                t.write(data)
        done += 1
    print('patched %d files' % done)


def cmd_revert_patch(args):
    root = Path(args.dir)
    n = 0
    for bak in root.rglob('*.c3rbak'):
        target = Path(str(bak)[:-len('.c3rbak')])
        if args.only and str(target) not in set(args.only):
            continue
        with open(target, 'r+b') as t:
            for off, data in _records(bak):
                t.seek(off)
                t.write(data)
        bak.unlink()
        n += 1
    print('reverted %d files' % n)


def cmd_report(args):
    rows = [json.loads(l) for l in gzip.open(args.survey, 'rt', encoding='utf-8', errors='surrogateescape')]
    c, b, eb = collections.Counter(), collections.Counter(), collections.Counter()
    for x in rows:
        parts = x['path'].strip('/').split('/')
        meta = any(s in ('@eaDir', '#recycle') for s in parts)
        key = ('/'.join(parts[:args.depth]), 'meta' if meta else 'file', x['status'])
        c[key] += 1
        b[key] += x.get('orig', 0)
        for k, v in (x.get('bytes') or {}).items():
            eb[(key, k)] += v
    tot, totb = collections.Counter(), collections.Counter()
    print('%-60s %-5s %-20s %9s %10s' % ('dir', 'kind', 'status', 'files', 'GB'))
    for key in sorted(c, key=lambda k: (k[0], -b[k])):
        print('%-60s %-5s %-20s %9d %10.2f' % (key[0][:60], key[1], key[2], c[key], b[key] / 1e9))
        if key[1] == 'file':
            tot[key[2]] += c[key]
            totb[key[2]] += b[key]
    print('\n总计（不含 @eaDir/#recycle）：')
    for s in sorted(tot, key=lambda s: -totb[s]):
        print('  %-22s %9d 个  %10.2f GB' % (s, tot[s], totb[s] / 1e9))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    e = sub.add_parser('extract')
    e.add_argument('stream')
    e.add_argument('out')
    e.add_argument('--total-bytes', type=int, help='Known payload bytes; omit when unknown, not TAR container size')
    add_progress_options(e)
    v = sub.add_parser('validate')
    v.add_argument('out')
    v.add_argument('--known', action='append', help='已知原件目录（同名同大小即对照），可多次')
    v.add_argument('--workers', type=int, default=max(1, (os.cpu_count() or 2) // 2))
    v.add_argument('--resume', action='store_true', help='Resume journal: reread SHA, reuse successful full decode for unchanged bytes')
    add_progress_options(v)
    a = sub.add_parser('apply-patch')
    a.add_argument('dir')
    rv = sub.add_parser('revert-patch')
    rv.add_argument('dir')
    rv.add_argument('--only', action='append', help='只回退这些目标文件（完整路径）')
    r = sub.add_parser('report')
    r.add_argument('survey')
    r.add_argument('--depth', type=int, default=3)
    args = ap.parse_args()
    if args.cmd in ('extract', 'validate'):
        args.progress = Progress('导出落盘' if args.cmd=='extract' else '文件校验',
                                 args.progress_file, args.progress_interval,
                                 total_bytes=getattr(args, 'total_bytes', None))
    try:
        {'extract': cmd_extract, 'validate': cmd_validate, 'report': cmd_report,
         'apply-patch': cmd_apply_patch, 'revert-patch': cmd_revert_patch}[args.cmd](args)
    except BaseException as error:
        if hasattr(args, 'progress'):
            args.progress.fail(interrupted=isinstance(error, KeyboardInterrupt))
        raise
    if hasattr(args, 'progress'):
        args.progress.finish('candidate' if args.cmd=='extract' else 'checks-completed')


if __name__ == '__main__':
    main()
