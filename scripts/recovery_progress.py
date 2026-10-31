#!/usr/bin/env python3
"""Throttled stderr progress, atomic private snapshots and a local live viewer.

Measures actual stage work. Exported, verified and accepted files stay separate.
"""
import argparse
import datetime
import html
import json
import math
import os
from pathlib import Path
import sys
import tempfile
import time
import uuid


def atomic_text(path, payload):
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                         prefix='.recovery-progress-', delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def gib(value):
    return '未知' if value is None else '%.2f GiB' % (value / 1024**3)


def describe(row):
    percent = '总量未知' if row['percent'] is None else '%.1f%%' % row['percent']
    speed = '未知' if row['speed_bps'] is None else '%.1f MiB/s' % (row['speed_bps']/1024**2)
    eta = '未知' if row['eta_seconds'] is None else '%d秒' % row['eta_seconds']
    count = str(row['files_completed']) + '/' + ('?' if row['total_files'] is None else str(row['total_files']))
    if row.get('file_percent') is not None:
        count += ' (%.1f%%)' % row['file_percent']
    return ('[{phase}] {status} {percent} | {done}/{total} | {speed} | 预计剩余 {eta} | '
            '阶段文件 {count} 格式验证 {verified} 已验收 {accepted} 失败 {failed} | {current}').format(
        phase=row['phase'], status=row['status'], percent=percent, done=gib(row['processed_bytes']),
        total=gib(row['total_bytes']), speed=speed, eta=eta, count=count,
        verified=row['verified_files'], accepted=row['accepted_files'], failed=row['failed_files'],
        current=row['current_file'])


class Progress:
    def __init__(self, phase, snapshot_path=None, interval=2.0, total_bytes=None,
                 total_files=None, stream=None, clock=time.monotonic):
        if not math.isfinite(interval) or interval <= 0:
            raise ValueError('Progress interval must be finite and positive')
        if any(value is not None and (not isinstance(value, int) or value < 0)
               for value in (total_bytes, total_files)):
            raise ValueError('Known progress totals must be nonnegative integers')
        self.phase = phase
        self.path = Path(snapshot_path) if snapshot_path else None
        if self.path is not None:
            # Exclusive reservation prevents a monitor from overwriting input,
            # an accepted result, or another worker's current status file.
            with self.path.open('x', encoding='utf-8') as reservation:
                reservation.write('{}\n')
        self.interval = interval
        self.stream = sys.stderr if stream is None else stream
        self.clock = clock
        self.started = self.clock()
        self.last_emit = self.started
        self.last_bytes = 0
        self.task_id = uuid.uuid4().hex
        self.total_bytes = total_bytes
        self.total_files = total_files
        self.processed_bytes = 0
        self.files_completed = self.verified_files = self.accepted_files = self.failed_files = 0
        self.current_file = ''
        self.status = 'running'
        self.level = 'unverified'
        self.last_snapshot = None
        self.display_warning_sent = False
        self.emit(force=True)

    def set_total(self, total_bytes, total_files=None, current_file=None):
        if any(value is not None and (not isinstance(value, int) or value < 0)
               for value in (total_bytes, total_files)):
            raise ValueError('Known progress totals must be nonnegative integers')
        self.total_bytes = total_bytes
        if total_files is not None:
            self.total_files = total_files
        if current_file is not None:
            self.current_file = current_file
        self.emit(force=True)

    def advance(self, count, current_file=None):
        if count < 0:
            raise ValueError('Progress cannot advance by negative bytes')
        self.processed_bytes += count
        if current_file is not None:
            self.current_file = current_file
        self.emit()

    def file_done(self, verified=False, accepted=False):
        self.files_completed += 1
        self.verified_files += int(verified)
        self.accepted_files += int(accepted)
        self.emit()

    def finish(self, level='candidate'):
        self.status = 'completed'
        self.level = level
        self.emit(force=True)

    def fail(self, interrupted=False):
        self.status = 'interrupted' if interrupted else 'failed'
        self.failed_files += int(not interrupted)
        self.emit(force=True)

    def emit(self, force=False):
        now = self.clock()
        if not force and now-self.last_emit < self.interval:
            return
        elapsed = now-self.started
        sample_seconds = now-self.last_emit
        speed = ((self.processed_bytes-self.last_bytes)/sample_seconds
                 if sample_seconds > 0 and self.processed_bytes > self.last_bytes else None)
        remaining = None if self.total_bytes is None else max(0, self.total_bytes-self.processed_bytes)
        percent = (None if self.total_bytes is None else
                   (100.0 if self.total_bytes == 0 and self.status == 'completed' else
                    min(100.0, self.processed_bytes/self.total_bytes*100) if self.total_bytes else 0.0))
        row = dict(schema=1, task_id=self.task_id, pid=os.getpid(), phase=self.phase, status=self.status,
                   updated_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   elapsed_seconds=round(elapsed, 3), processed_bytes=self.processed_bytes,
                   total_bytes=self.total_bytes, percent=percent,
                   denominator_exceeded=self.total_bytes is not None and self.processed_bytes>self.total_bytes,
                   speed_bps=speed, eta_seconds=(0 if remaining==0 and self.status=='completed' else
                                                math.ceil(remaining/speed) if remaining is not None and speed else None),
                   files_completed=self.files_completed, total_files=self.total_files,
                   file_percent=(None if self.total_files is None else
                                 min(100.0,self.files_completed/self.total_files*100) if self.total_files else
                                 100.0 if self.status=='completed' else 0.0),
                   verified_files=self.verified_files, accepted_files=self.accepted_files,
                   failed_files=self.failed_files, current_file=self.current_file, result_level=self.level)
        self.last_snapshot = row
        self.last_emit, self.last_bytes = now, self.processed_bytes
        # Display/storage errors do not change or delete recovery output.
        try:
            if self.path:
                atomic_text(self.path, json.dumps(row, ensure_ascii=False, indent=2)+'\n')
            print(describe(row), file=self.stream, flush=True)
        except (OSError, UnicodeError):
            if not self.display_warning_sent:
                self.display_warning_sent = True
                try:
                    print('Progress display/snapshot update failed; recovery work continues.',
                          file=self.stream, flush=True)
                except (OSError, UnicodeError):
                    pass


class ProgressReader:
    def __init__(self, source, progress):
        self.source, self.progress = source, progress

    def read(self, amount=-1):
        data = self.source.read(amount)
        self.progress.advance(len(data))
        return data


def updated_local(row):
    stamp = datetime.datetime.fromisoformat(row['updated_utc'])
    return stamp.astimezone(datetime.timezone(datetime.timedelta(hours=8))).strftime('%Y-%m-%d %H:%M:%S')+'（北京时间）'


def html_page(rows, interval):
    cards = ''.join('<pre>'+html.escape(describe(row)+'\n最近数据更新：'+updated_local(row))+'</pre>' for row in rows)
    return ('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>恢复实时进度</title>'
            '<style>body{background:#111827;color:#e5e7eb;font:16px system-ui;padding:32px}'
            'pre{white-space:pre-wrap;background:#1f2937;padding:20px;border-radius:12px}</style>'
            '<h1>恢复实时进度</h1><p>字节百分比属于当前阶段；导出、格式验证与最终验收分别统计。</p>'
            +cards+'<p>总量未知时不估算百分比；查看器刷新不代表后台任务有新进展。</p>'
            '<script>setTimeout(()=>location.reload(),'+str(int(interval*1000))+');</script></html>')


def watch(paths, interval, html_path=None, once=False):
    if html_path:
        html_path = Path(html_path)
        if any(html_path.resolve()==Path(p).resolve() for p in paths):
            raise ValueError('HTML output cannot replace a status input')
        with html_path.open('x', encoding='utf-8'):
            pass
    while True:
        rows = []
        for path in paths:
            try:
                row = json.loads(Path(path).read_text(encoding='utf-8'))
                if row.get('schema') != 1:
                    continue
                rows.append(row)
            except (OSError, ValueError):
                continue  # atomic replacement or a producer not yet started
        if sys.stdout.isatty() and not once:
            print('\x1b[2J\x1b[H', end='')
        print('\n'.join(describe(row)+' | 数据更新 '+updated_local(row) for row in rows) or '等待恢复任务进度…', flush=True)
        if html_path:
            atomic_text(html_path, html_page(rows, interval))
        if once:
            return
        time.sleep(interval)


def add_progress_options(parser):
    parser.add_argument('--progress-file', help='New status JSON on independent storage; one per task')
    parser.add_argument('--progress-interval', type=float, default=2.0, help='stderr/status update interval in seconds')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    viewer = sub.add_parser('watch')
    viewer.add_argument('files', nargs='+')
    viewer.add_argument('--interval', type=float, default=2.0)
    viewer.add_argument('--html', help='New local HTML dashboard, refreshed while watcher runs')
    viewer.add_argument('--once', action='store_true')
    args = parser.parse_args()
    if not math.isfinite(args.interval) or not 0.2 <= args.interval <= 60:
        parser.error('Interval must be between 0.2 and 60 seconds')
    try:
        watch(args.files, args.interval, args.html, args.once)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
