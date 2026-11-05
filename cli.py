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

PREFIX = re.compile(r'^(?P<stamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d\d-\d\dT\S+)\s+(?P<host>\S+)\s+sshd(?:-session)?(?:\[\d+\])?:\s+(?P<message>.*)$')
LOGIN = re.compile(r'^(?P<outcome>Failed|Accepted) (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+(?:\s|$)')

@dataclass(frozen=True)
class Event:
    timestamp: datetime
    host: str
    user: str
    source_ip: str
    outcome: str
    method: str
    file: str
    line: int
    raw: str

    def record(self):
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result


def parse_line(raw, file, line, year, offset):
    match = PREFIX.match(raw)
    if not match:
        return None
    login = LOGIN.match(match['message'])
    if not login:
        if match['message'].startswith(('Failed ', 'Accepted ')):
            raise ValueError('unsupported or malformed login message')
        return None
    stamp = match['stamp']
    if re.match(r'^\d{4}-', stamp):
        moment = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=offset)
    else:
        moment = datetime.strptime(f'{year} {stamp}', '%Y %b %d %H:%M:%S').replace(tzinfo=offset)
    address = str(ipaddress.ip_address(login['ip']))
    return Event(moment.astimezone(timezone.utc), match['host'], login['user'], address,
                 login['outcome'].lower(), login['method'], str(file), line, raw.rstrip('\n'))


from .detection import investigate, investigate_distributed
from .config import load_config
from .incidents import group_incidents


def finding(rule, severity, host, source, evidence, explanation, triggered_at=None):
    return dict(rule=rule, severity=severity, host=host, source_ip=source,
                triggered_at=triggered_at or evidence[-1].timestamp.isoformat(),
                event_count=len(evidence), failure_count=sum(e.outcome == "failed" for e in evidence),
                accounts=sorted({item.user for item in evidence}), start=evidence[0].timestamp.isoformat(),
                end=evidence[-1].timestamp.isoformat(), explanation=explanation,
                evidence=[item.record() for item in evidence])


def render_html(report):
    esc = lambda value: html.escape(str(value), quote=True)
    cards = []
    for item in report['findings']:
        rows = ''.join('<tr>' + ''.join(f'<td>{esc(event[key])}</td>' for key in
                       ('timestamp', 'user', 'outcome', 'method', 'file', 'line', 'raw')) + '</tr>'
                       for event in item['evidence'])
        cards.append(f"<article><h2>{esc(item['severity'].upper())} · {esc(item['rule'])}</h2>"
                     f"<p>{esc(item['host'])} ← {esc(item.get('source_ip') or ', '.join(item['source_ips']))}</p><p>{esc(item['explanation'])}</p>"
                     f'<details><summary>{len(item["evidence"])} evidence events</summary><div class="scroll"><table>'
                     '<tr><th>UTC time</th><th>Account</th><th>Outcome</th><th>Method</th><th>File</th><th>Line</th><th>Original log</th></tr>'
                     f'{rows}</table></div></details></article>')
    investigations = []
    for incident in report.get('incidents', []):
        rows = ''.join('<tr>' + ''.join(f'<td>{esc(event[key])}</td>' for key in
                       ('timestamp', 'source_ip', 'user', 'outcome', 'file', 'line', 'raw')) + '</tr>'
                       for event in incident['timeline'])
        investigations.append(f"<article><h2>{esc(incident['id'])} · {esc(incident['host'])}</h2>"
                              f"<p>{esc(incident['severity'].upper())} · {esc(', '.join(incident['rules']))}</p>"
                              f"<p>{esc(incident['start'])} to {esc(incident['end'])}</p>"
                              f'<details><summary>{incident["event_count"]} unique timeline events</summary>'
                              '<div class="scroll"><table><tr><th>UTC time</th><th>Source</th><th>Account</th>'
                              '<th>Outcome</th><th>File</th><th>Line</th><th>Original log</th></tr>'
                              f'{rows}</table></div></details></article>')
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
            '<title>AuthTrail investigation</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 20px;background:#101827;color:#e5edf7}'
            'article{background:#1c2940;padding:20px;margin:16px 0;border-radius:10px}h1{color:#65dbc7}td,th{text-align:left;padding:9px;border-bottom:1px solid #43516a}'
            '.scroll{overflow:auto}td{vertical-align:top}summary{cursor:pointer}</style><h1>AuthTrail</h1>'
            f'<p>{report["stats"]["parsed"]} authentication events · {len(cards)} findings · timestamps in UTC</p>'
            '<p>Findings are investigation leads, not proof of compromise.</p>'
            f'<p>Run configuration: {esc(json.dumps(report["configuration"]))}</p>'
            f'<p>Input statistics: {esc(json.dumps(report["stats"]))}</p>'
            f'<p>Input files: {esc(json.dumps(report.get("input_files", [])))}</p>'
            f'<p>Parse diagnostics (up to 20): {esc(json.dumps(report.get("diagnostics", [])))}</p>'
            + ('<h2>Grouped investigations</h2>' + ''.join(investigations) if investigations else '')
            + '<h2>Individual findings</h2>' + ''.join(cards) + ('<p>No findings matched the configured thresholds.</p>' if not cards else '') + '</html>')


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
    diagnostics = []
    file_stats = []
    stats = dict(lines=0, parsed=0, ignored=0, malformed=0, excluded=0, duplicates=0)
    events, seen = [], set()
    try:
        for path in args.logs:
            before = stats.copy()
            opener = gzip.open if path.suffix == '.gz' else open
            with opener(path, 'rt', encoding='utf-8', errors='replace') as stream:
                for number, raw in enumerate(stream, 1):
                    stats['lines'] += 1
                    try:
                        event = parse_line(raw, path, number, args.year, args.timezone)
                    except ValueError as exc:
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
                    if identity in seen:
                        stats['duplicates'] += 1
                        continue
                    seen.add(identity)
                    events.append(event)
                    stats['parsed'] += 1
            file_stats.append(dict(file=str(path), **{key: stats[key] - before[key] for key in stats}))
        stats['parsed'] = len(events)
        findings = investigate(events, args.window, args.failures, args.users)
        findings += investigate_distributed(events, args.distributed_window, args.distributed_sources, args.distributed_failures)
        findings.sort(key=lambda f: (f['end'], f['host'], f['rule'], f['accounts']))
        report = dict(schema_version=3, configuration=dict(year=args.year, timezone=str(args.timezone),
                      window_seconds=args.window, failure_threshold=args.failures, account_threshold=args.users,
                      excluded_sources=args.exclude_source, excluded_users=args.exclude_user,
                      distributed_sources=args.distributed_sources, distributed_failures=args.distributed_failures,
                      distributed_window=args.distributed_window, incident_gap=args.incident_gap), stats=stats, input_files=file_stats, diagnostics=diagnostics,
                      findings=findings, incidents=group_incidents(findings, args.incident_gap))
        if args.json_path:
            args.json_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        if args.html_path:
            args.html_path.write_text(render_html(report), encoding='utf-8')
    except (OSError, EOFError) as exc:
        print(f'authtrail: {exc}', file=sys.stderr)
        return 2
    print(f'AuthTrail: {len(events)} events, {len(report["findings"])} findings, {len(report["incidents"])} investigations')
    for item in report['findings']:
        print(f'{item["severity"].upper():6} {item["rule"]}: {item["host"]} ← {item.get("source_ip") or ', '.join(item["source_ips"])} ({len(item["evidence"])} events)')
    if not events:
        print('Warning: no usable authentication events; check format, exclusions, and input files.', file=sys.stderr)
    print(f'Input: {stats["ignored"]} ignored, {stats["malformed"]} malformed, {stats["excluded"]} excluded, {stats["duplicates"]} duplicates')
    if stats['malformed']:
        print(f'Warning: {stats["malformed"]} authentication records could not be parsed; see JSON diagnostics.', file=sys.stderr)
    return 0
