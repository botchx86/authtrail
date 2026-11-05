"""Standard-library-only parser, correlation engine, and CLI."""
import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone, timedelta
import gzip
import html
import ipaddress
import json
from pathlib import Path
import re
import sys
import zlib
from . import __version__

from .models import Event, finding


from .parsing import parse_line


from .detection import investigate, investigate_distributed
from .config import load_config
from .incidents import group_incidents



from .reporting import render_html
from .storage import atomic_write, check_outputs
from collections import Counter


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError('must be at least 1')
    return number


def parse_offset(value):
    if not re.fullmatch(r'[+-]\d{2}:\d{2}', value):
        raise argparse.ArgumentTypeError('use an offset such as +00:00 or -05:00')
    hours, minutes = map(int, value[1:].split(':'))
    if hours > 23 or minutes > 59:
        raise argparse.ArgumentTypeError('invalid UTC offset')
    return timezone(timedelta(minutes=(hours * 60 + minutes) * (-1 if value[0] == '-' else 1)))


def main(argv=None):
    parser = argparse.ArgumentParser(description='Investigate exported SSH authentication logs offline.')
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('--max-events', type=positive, default=100000, help='abort above this event count (default 100000)')
    parser.add_argument('--max-line-bytes', type=positive, default=65536)
    parser.add_argument('logs', nargs='+', type=Path, help='auth.log / secure files, including .gz rotations')
    parser.add_argument('--year', type=int, required=True, help='year for traditional syslog timestamps (one year per run)')
    parser.add_argument('--timezone', type=parse_offset, default=timezone.utc, metavar='+HH:MM', help='offset for timestamps without a timezone (default +00:00)')
    parser.add_argument('--config', type=Path, help='saved JSON rule settings; CLI flags override individual settings')
    parser.add_argument('--distributed-sources', type=positive)
    parser.add_argument('--distributed-failures', type=positive)
    parser.add_argument('--distributed-window', type=positive)
    parser.add_argument('--incident-gap', type=positive)
    parser.add_argument('--exclude-user', action='append', default=None)
    parser.add_argument('--window', type=positive, default=None, help='correlation window in seconds (default 300)')
    parser.add_argument('--failures', type=positive, default=None, help='failures per account (default 5)')
    parser.add_argument('--users', type=positive, default=None, help='distinct attempted accounts (default 5)')
    parser.add_argument('--exclude-source', action='append', default=None, metavar='IP/CIDR', help='known source to exclude; repeatable')
    parser.add_argument('--json', type=Path, dest='json_path')
    parser.add_argument('--html', type=Path, dest='html_path')
    parser.add_argument('--compact-json', action='store_true', help='store each event once and reference its ID')
    parser.add_argument('--strict', action='store_true', help='fail on malformed input or no usable events')
    parser.add_argument('--min-events', type=positive, default=None)
    parser.add_argument('--group-by', choices=['source', 'account', 'either'], default='source')
    args = parser.parse_args(argv)
    try:
        settings = load_config(args.config)
    except (OSError, ValueError) as exc:
        parser.error(f'configuration: {exc}')
    for key, value in settings.items():
        if getattr(args, key) is None:
            setattr(args, key, value)
    if not 1 <= args.year <= 9999:
        parser.error('--year must be between 1 and 9999')
    try:
        networks = [ipaddress.ip_network(item, strict=False) for item in args.exclude_source]
    except ValueError as exc:
        parser.error(str(exc))
    inputs = {path.resolve() for path in args.logs}
    if args.config:
        inputs.add(args.config.resolve())
    outputs = [path.resolve() for path in (args.json_path, args.html_path) if path]
    if inputs.intersection(outputs) or len(outputs) != len(set(outputs)):
        parser.error('report paths must differ from input logs, configuration, and from each other')
    try:
        check_outputs(inputs, outputs)
    except ValueError as exc:
        parser.error(str(exc))
    diagnostics = []
    file_stats = []
    stats = dict(lines=0, parsed=0, ignored=0, malformed=0, excluded=0, duplicates=0)
    events, seen = [], Counter()
    try:
        for path in args.logs:
            before = stats.copy()
            occurrences = Counter()
            opener = gzip.open if path.suffix == '.gz' else open
            with opener(path, 'rt', encoding='utf-8', errors='replace') as stream:
                number = 0
                while True:
                    raw = stream.readline(args.max_line_bytes + 1)
                    if not raw:
                        break
                    number += 1
                    if len(raw.encode('utf-8')) > args.max_line_bytes:
                        raise ValueError(f'{path}:{number}: line exceeds configured limit')
                    stats['lines'] += 1
                    try:
                        event = parse_line(raw, path, number, args.year, args.timezone)
                    except (ValueError, OverflowError) as exc:
                        if len(diagnostics) < 20:
                            diagnostics.append(dict(file=str(path), line=number, reason=str(exc)))
                        stats['malformed'] += 1
                        continue
                    if event is None:
                        stats['ignored'] += 1
                        continue
                    if event.user in args.exclude_user or any(ipaddress.ip_address(event.source_ip) in net for net in networks):
                        stats['excluded'] += 1
                        continue
                    # Identical log records across overlapping rotations count once.
                    identity = (event.timestamp, event.host, event.raw)
                    occurrences[identity] += 1
                    if occurrences[identity] <= seen[identity]:
                        stats['duplicates'] += 1
                        continue
                    if len(events) >= args.max_events:
                        raise ValueError('event limit exceeded; split the export or increase --max-events')
                    events.append(event)
                    stats['parsed'] += 1
            seen |= occurrences
            file_stats.append(dict(file=str(path), **{key: stats[key] - before[key] for key in stats}))
        stats['parsed'] = len(events)
        if (args.min_events is not None and len(events) < args.min_events) or (args.strict and (not events or stats['malformed'])):
            print('authtrail: input quality requirements not met; no reports written', file=sys.stderr)
            return 2
        from collections import defaultdict
        outcomes = defaultdict(set)
        for event in events:
            outcomes[(event.host, event.user, event.timestamp)].add(event.outcome)
        ambiguous = sum(len(values) > 1 for values in outcomes.values())
        if ambiguous:
            diagnostics.append(dict(reason='Equal-time success/failure order is uncertain; successes processed first', groups=ambiguous))
        findings = investigate(events, args.window, args.failures, args.users)
        findings += investigate_distributed(events, args.distributed_window, args.distributed_sources, args.distributed_failures)
        from .detection import distributed_success
        findings += distributed_success(events, args.distributed_window, args.distributed_sources, args.distributed_failures)
        findings.sort(key=lambda f: (f['end'], f['host'], f['rule'], f['accounts']))
        report = dict(tool_version=__version__, schema_version=3, configuration=dict(year=args.year, timezone=str(args.timezone),
                      window_seconds=args.window, failure_threshold=args.failures, account_threshold=args.users,
                      excluded_sources=args.exclude_source, excluded_users=args.exclude_user,
                      distributed_sources=args.distributed_sources, distributed_failures=args.distributed_failures,
                      distributed_window=args.distributed_window, incident_gap=args.incident_gap,
                      group_by=args.group_by, strict=args.strict, min_events=args.min_events, max_events=args.max_events,
                      max_line_bytes=args.max_line_bytes), stats=stats, input_files=file_stats, diagnostics=diagnostics,
                      findings=findings, incidents=group_incidents(findings, args.incident_gap, args.group_by))
        if args.json_path:
            from .reporting import compact_report
            payload = compact_report(report) if args.compact_json else report
            atomic_write(args.json_path, json.dumps(payload, indent=2) + '\n')
        if args.html_path:
            atomic_write(args.html_path, render_html(report))
    except (OSError, EOFError, zlib.error, ValueError) as exc:
        print(f'authtrail: {exc}', file=sys.stderr)
        return 2
    print(f'AuthTrail: {len(events)} events, {len(report["findings"])} findings, {len(report["incidents"])} investigations')
    for item in report['findings']:
        source = item.get('source_ip') or ', '.join(item['source_ips'])
        print('{} {}: {} <- {} ({} events)'.format(item['severity'].upper(), item['rule'], ascii(item['host']), ascii(source), len(item['evidence'])))
    if not events:
        print('Warning: no usable authentication events; check format, exclusions, and input files.', file=sys.stderr)
    print(f'Input: {stats["ignored"]} ignored, {stats["malformed"]} malformed, {stats["excluded"]} excluded, {stats["duplicates"]} duplicates')
    if stats['malformed']:
        print(f'Warning: {stats["malformed"]} authentication records could not be parsed; see JSON diagnostics.', file=sys.stderr)
    return 0
