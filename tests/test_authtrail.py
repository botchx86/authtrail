import unittest
from datetime import timezone
from authtrail.cli import parse_line, investigate, render_html

def event(n, user='deploy', outcome='Failed', host='web01'):
    return parse_line(f'2026-11-01T12:00:{n:02d}Z {host} sshd[42]: {outcome} password for {user} from 192.0.2.45 port 22 ssh2', 'auth.log', n+1, 2026, timezone.utc)

class Tests(unittest.TestCase):
    def test_patterns(self):
        events = [event(i) for i in range(5)] + [event(5, outcome='Accepted')] + [event(10+i, user=f'user{i}') for i in range(5)]
        findings = investigate(events)
        self.assertEqual([f['rule'] for f in findings], ['repeated_failures', 'success_after_failures', 'many_accounts'])
        self.assertEqual(len(findings[1]['evidence']), 6)
    def test_host_isolation(self):
        self.assertEqual(investigate([event(i, host=f'host{i}') for i in range(5)]), [])
    def test_window_and_order(self):
        events = [event(i*10) for i in range(5)]
        self.assertEqual(investigate(events, window=10), [])
        self.assertEqual(len(investigate(events[::-1], window=40)), 1)
    def test_account_isolation(self):
        findings = investigate([event(i) for i in range(5)] + [event(5, user='other', outcome='Accepted')])
        self.assertEqual(len(findings), 1)
    def test_html_escaping(self):
        report = dict(stats={'parsed':1}, configuration={}, findings=investigate([event(0, user='<script>')], failures=1))
        self.assertNotIn('<script>', render_html(report))
        self.assertIn('&lt;script&gt;', render_html(report))
    def test_ipv6(self):
        raw = 'Nov  1 12:00:00 host sshd[1]: Failed password for invalid user root from 2001:db8::1 port 22 ssh2'
        self.assertEqual(parse_line(raw, 'x', 1, 2026, timezone.utc).source_ip, '2001:db8::1')

class ExpandedTests(unittest.TestCase):
    def test_complete_burst(self):
        findings = investigate([event(i) for i in range(12)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['event_count'], 12)
        self.assertEqual(findings[0]['triggered_at'], event(4).timestamp.isoformat())
        self.assertEqual(findings[0]['end'], event(11).timestamp.isoformat())

    def test_rearms_after_gap(self):
        events = [event(i) for i in range(5)] + [event(i) for i in range(30,35)]
        self.assertEqual(len(investigate(events, window=10)), 2)

    def test_success_resets_account(self):
        events = [event(i) for i in range(5)] + [event(5, outcome='Accepted')] + [event(i) for i in range(6,11)]
        findings = investigate(events)
        self.assertEqual(sum(f['rule'] == 'repeated_failures' for f in findings), 2)
        self.assertEqual(sum(f['rule'] == 'success_after_failures' for f in findings), 1)

    def test_many_accounts_complete_burst(self):
        findings = investigate([event(i, user=f'u{i}') for i in range(10)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['event_count'], 10)

    def test_parser_variants(self):
        for process in ('sshd', 'sshd[12]', 'sshd-session[12]'):
            raw = f'2026-11-01T13:00:00.123+01:00 server {process}: Accepted keyboard-interactive/pam for bob from ::1 port 22 ssh2'
            item = parse_line(raw, 'x', 1, 2026, timezone.utc)
            self.assertEqual(item.timestamp.hour, 12)
            self.assertEqual(item.timestamp.microsecond, 123000)
            self.assertEqual(item.method, 'keyboard-interactive/pam')

    def test_malformed_and_unrelated(self):
        with self.assertRaises(ValueError):
            parse_line('Nov  1 12:00:00 host sshd[1]: Failed password for bob from bad-ip port 22 ssh2', 'x', 1, 2026, timezone.utc)
        with self.assertRaises(ValueError):
            parse_line('Nov  1 12:00:00 host sshd[1]: Accepted broken', 'x', 1, 2026, timezone.utc)
        self.assertIsNone(parse_line('Nov  1 12:00:00 host sshd[1]: session closed', 'x', 1, 2026, timezone.utc))

    def test_reports_and_quality(self):
        import contextlib
        import gzip
        import io
        import json
        import tempfile
        from pathlib import Path
        from authtrail.cli import main
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            logs = '\n'.join(event(i).raw for i in range(8)) + '\n'
            (root/'auth.log').write_text(logs + 'unrelated\nNov  1 12:00:00 host sshd[1]: Accepted broken\n')
            with gzip.open(root/'auth.gz', 'wt') as f:
                f.write(logs)
            args = [str(root/'auth.log'), str(root/'auth.gz'), '--year', '2026', '--json', str(root/'out.json'), '--html', str(root/'out.html')]
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 0)
            report = json.loads((root/'out.json').read_text())
            self.assertEqual(report['stats']['duplicates'], 8)
            self.assertEqual(report['stats']['malformed'], 1)
            self.assertEqual(report['stats']['ignored'], 1)
            self.assertEqual(report['input_files'][0]['parsed'], 8)
            self.assertEqual(report['diagnostics'][0]['line'], 10)
            self.assertEqual(report['findings'][0]['event_count'], 8)
            self.assertIn('Parse diagnostics', (root/'out.html').read_text())
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(args + ['--exclude-source', '192.0.2.0/24']), 0)
            self.assertEqual(json.loads((root/'out.json').read_text())['stats']['parsed'], 0)
