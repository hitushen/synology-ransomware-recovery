#!/usr/bin/env python3
"""Create a bounded private AI review report after scripted validation finishes.

Reads exception receipts once. No AI/API calls, NAS access, retries or payload
execution. Groups repeated failures and retains byte offsets for follow-up.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat

from c3r_local import IMG, AV

FORMATS = IMG | AV | {'.tar', '.gz', '.zip', '.7z', '.xz', '.sql', '.json', '.pdf',
                     '.docx', '.xlsx', '.pptx', '.db', '.sqlite', '.dump', '.bin', '.txt'}
HINTS = {
    'decode_error': 'Compare a representative with an independent original or another complete candidate; inspect the failing format.',
    'sha_mismatch_or_missing': 'Check transfer receipts, extraction records and later changes; preserve prior outputs.',
    'known_original_mismatch': 'Check original version/provenance before concluding that the candidate is damaged.',
    'file_changed': 'Keep the candidate and original static, then revalidate only the affected scope.',
    'unverified_format': 'Use an appropriate format/application validator; retain unverified status until evidence passes.',
    'inferred_or_partial': 'Look for missing ranges, older roots/extents or complete copies; retain partial/candidate status.',
    'not_extracted': 'Inspect the source plan and available extents/copies for the affected entries.',
    'read_or_worker_error': 'Inspect representative read/worker errors; distinguish per-file failure from a storage-wide problem.',
    'other': 'Inspect representative evidence before selecting a new recovery route.',
}


def issue_kind(row):
    reason = str(row.get('reason', ''))
    if reason.startswith('decode_error:'):
        return 'decode_error'
    if reason in HINTS:
        return reason
    outcome = str(row.get('outcome', ''))
    if outcome == 'not_extracted':
        return 'not_extracted'
    if outcome == 'unverified':
        return 'unverified_format'
    if outcome.startswith(('partial_', 'inferred_')):
        return 'inferred_or_partial'
    if reason.endswith(('Error', 'Exception')) or row.get('detail'):
        return 'read_or_worker_error'
    return 'other'


def identity(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('Exception input must be a regular independent file')
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def build_report(source, *, representatives=3, max_groups=12):
    if not 1 <= representatives <= 10 or not 1 <= max_groups <= 50:
        raise ValueError('Use 1..10 representatives and 1..50 groups')
    source = Path(source)
    before = identity(source)
    groups = {}
    digest = hashlib.sha256()
    total = offset = 0
    run_id = None
    with source.open('rb') as stream:
        while line := stream.readline(1024*1024+1):
            if len(line) > 1024*1024 or not line.endswith(b'\n'):
                raise ValueError('Incomplete or oversized exception receipt; wait for batch completion')
            row = json.loads(line)
            if not isinstance(row, dict) or row.get('source_complete') is not True:
                raise ValueError('Only source-complete exception receipts can be summarized')
            current = row.get('validation_run_id')
            if not isinstance(current, str) or not current or len(current) > 128:
                raise ValueError('Exception receipt lacks a valid validation run ID')
            if run_id is not None and current != run_id:
                raise ValueError('Mixed validation runs; summarize one finished run at a time')
            run_id = current
            digest.update(line)
            total += 1
            kind = issue_kind(row)
            suffix = Path(str(row.get('member') or row.get('path') or '')).suffix.lower()
            format_kind = suffix if suffix in FORMATS else 'other'
            key = (kind, format_kind)
            if key not in groups:
                groups[key] = {'group_id': hashlib.sha256(json.dumps(key).encode()).hexdigest()[:16],
                               'issue': kind, 'format': format_kind, 'exception_records': 0,
                               'representatives': [], 'next_check': HINTS[kind]}
            group = groups[key]
            group['exception_records'] += 1
            if len(group['representatives']) < representatives:
                display_path = str(row.get('path') or row.get('member') or '')
                group['representatives'].append({'record_number': total, 'byte_offset': offset,
                    'path_display': display_path[:160], 'path_truncated': len(display_path) > 160,
                    'outcome': str(row.get('outcome', ''))[:100],
                    'reason': str(row.get('reason', ''))[:200],
                    'detail': str(row.get('detail') or '')[:200]})
            offset += len(line)
    if identity(source) != before:
        raise ValueError('Exception receipts changed during summarization; wait for batch completion')
    ordered = sorted(groups.values(), key=lambda group: (-group['exception_records'], group['group_id']))
    shown = ordered[:max_groups]
    covered = sum(group['exception_records'] for group in shown)
    return {'schema': 1, 'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'review_mode': 'after_batch', 'ai_review_needed': total > 0,
            'input': {'path': str(source.resolve()), 'bytes': offset, 'sha256': digest.hexdigest(),
                      'validation_run_id': run_id},
            'exception_records': total, 'groups_total': len(ordered), 'groups_shown': len(shown),
            'groups_omitted': len(ordered)-len(shown), 'records_in_shown_groups': covered,
            'records_in_omitted_groups': total-covered, 'groups': shown,
            'limits': 'Exception receipts only; this report is not evidence of new recovery or key discovery. '
                      'Counts are receipt entries, not a whole-NAS recovery denominator. '
                      'Omitted groups remain unresolved; use offsets to inspect private source receipts.'}


def write_report(source, output, **options):
    output = Path(output)
    report = build_report(source, **options)
    # Exclusive creation preserves prior reviews and recovery outputs.
    with output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    return {'report_path': str(output.resolve()), 'review_mode': report['review_mode'],
            'ai_review_needed': report['ai_review_needed'], 'exception_records': report['exception_records'],
            'groups_total': report['groups_total'], 'groups_shown': report['groups_shown']}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, help='Finished _exceptions.jsonl on independent storage')
    parser.add_argument('--output', required=True, help='New private JSON review report')
    parser.add_argument('--representatives', type=int, default=3)
    parser.add_argument('--max-groups', type=int, default=12)
    args = parser.parse_args()
    try:
        result = write_report(args.input, args.output, representatives=args.representatives, max_groups=args.max_groups)
    except (OSError, ValueError) as error:
        print(json.dumps({'status': 'needs_attention', 'error_type': type(error).__name__, 'reason': str(error)}))
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
