#!/usr/bin/env python3
"""Run a saved Btrfs export through archive checks, extraction and validation.

Only reads a saved TAR and writes a new independent local batch directory.
No NAS connection, source repair, executable sample or arbitrary shell command.
"""
import argparse
import contextlib
import datetime
import json
import os
from pathlib import Path
import stat
import sys
import types
import uuid

from c3r_local import cmd_extract, cmd_validate
from recovery_progress import Progress, atomic_text
from verify_backup import validate


def fingerprint(path):
    if path.is_symlink():
        raise ValueError('Saved export cannot be a symbolic link')
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('Only a saved regular TAR export is supported')
    return {'path': str(path.resolve()), 'device': info.st_dev, 'inode': info.st_ino,
            'bytes': info.st_size, 'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}


def write_state(root, state):
    state['updated_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    atomic_text(root / 'batch-state.json', json.dumps(state, ensure_ascii=False, indent=2) + '\n')


def reset_phase(progress, phase):
    progress.phase = phase
    progress.processed_bytes = progress.last_bytes = 0
    progress.files_completed = progress.verified_files = progress.accepted_files = progress.failed_files = 0
    progress.total_files = None
    progress.set_total(None)


def run_batch(export, output, *, workers=2, known=None, resume=False, progress_file=None):
    source = Path(export).resolve(strict=True)
    if Path(export).is_symlink() or source.suffix.lower() != '.tar':
        raise ValueError('Use a saved uncompressed Btrfs TAR export')
    identity = fingerprint(source)
    root = Path(output).resolve()
    if root == source:
        raise ValueError('Batch output cannot replace the saved export')
    if workers < 1:
        raise ValueError('Workers must be positive')
    known_paths = [str(Path(path).resolve()) for path in known or []]
    if resume:
        if Path(output).is_symlink():
            raise ValueError('Batch output cannot be a symbolic link')
        state_path = root / 'batch-state.json'
        if state_path.is_symlink() or state_path.stat().st_size > 8*1024*1024:
            raise ValueError('Invalid batch checkpoint')
        state = json.loads(state_path.read_text(encoding='utf-8'))
        if state.get('schema') != 1 or state.get('input') != identity:
            raise ValueError('Saved export identity differs; use a new batch directory')
        if known is None:
            known_paths = state.get('known_directories', [])
        if state.get('validated') and known_paths == state.get('known_directories', []):
            return {'status': 'already_completed', 'previous_status': state['status'],
                    'verification_time_utc': state['verification_time_utc'],
                    'summary': state['summary'], 'new_checks_run': False,
                    'limits': 'Returns prior receipts; does not revalidate subsequently changed files'}
        state['validated'] = False
    else:
        root.mkdir(mode=0o700)
        state = {'schema': 1, 'input': identity, 'archive_checked': False,
                 'extracted': False, 'validated': False, 'status': 'running'}
    state['known_directories'] = known_paths
    candidates = root / 'candidates'
    snapshot = Path(progress_file) if progress_file else root / ('progress-' + uuid.uuid4().hex + '.json')
    progress = Progress('批量归档检查', snapshot)
    state['progress_file'] = str(snapshot.resolve())
    state['workers'] = workers
    log_path = root / 'batch-output.log'
    if log_path.is_symlink():
        raise ValueError('Batch log cannot be a link')
    try:
        with log_path.open('a', encoding='utf-8') as log, contextlib.redirect_stdout(log):
            if not state['archive_checked']:
                state.update(stage='archive_check', status='running'); write_state(root, state)
                checked = validate(source, progress=progress)
                if not checked.get('integrity_pass'):
                    raise ValueError('Complete source archive check did not pass')
                if fingerprint(source) != identity:
                    raise ValueError('Saved export changed during archive validation')
                state['archive_checked'] = True; write_state(root, state)
            if not state['extracted']:
                if candidates.exists():
                    raise ValueError('Interrupted extraction is preserved; use a new batch output for export retry')
                reset_phase(progress, '批量导出落盘')
                state.update(stage='extract', status='running'); write_state(root, state)
                cmd_extract(types.SimpleNamespace(out=str(candidates), stream=str(source), progress=progress))
                if not (candidates / '_c3r_manifest.jsonl').is_file():
                    raise ValueError('Btrfs export does not contain a recovery manifest')
                if fingerprint(source) != identity:
                    raise ValueError('Saved export changed during extraction')
                state['extracted'] = True; write_state(root, state)
            reset_phase(progress, '批量文件校验')
            state.update(stage='validate', status='running'); write_state(root, state)
            summary = cmd_validate(types.SimpleNamespace(out=str(candidates), known=known_paths,
                                   workers=workers, resume=resume, progress=progress))
            state.update(validated=True, summary=summary, stage='finished',
                         status='completed_with_exceptions' if summary['exceptions'] else 'completed',
                         verification_time_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                         exception_file=str((candidates / '_exceptions.jsonl').resolve()))
            write_state(root, state)
            progress.finish(state['status'])
    except BaseException as error:
        state.update(status='interrupted' if isinstance(error, KeyboardInterrupt) else 'needs_attention',
                     error_type=type(error).__name__, reason=str(error))
        write_state(root, state)
        progress.fail(interrupted=isinstance(error, KeyboardInterrupt))
        raise
    return {'status': state['status'], 'summary': summary,
            'checkpoint': str((root / 'batch-state.json').resolve()),
            'exceptions': state['exception_file'], 'progress_file': state['progress_file'],
            'new_checks_run': True}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--export', required=True)
    parser.add_argument('--output', required=True, help='New directory on independent storage')
    parser.add_argument('--workers', type=int, default=2)
    parser.add_argument('--known', action='append')
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--progress-file', help='New status file; omit for a generated path in checkpoint')
    args = parser.parse_args()
    try:
        result = run_batch(args.export, args.output, workers=args.workers, known=args.known,
                           resume=args.resume, progress_file=args.progress_file)
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError) as error:
        print(json.dumps({'status': 'needs_attention', 'error_type': type(error).__name__,
                          'reason': str(error)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 2 if result.get('summary', {}).get('exceptions') else 0


if __name__ == '__main__':
    raise SystemExit(main())
