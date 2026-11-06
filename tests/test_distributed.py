import contextlib
from dataclasses import replace
from datetime import timedelta
import io
import json
from pathlib import Path
import tempfile
import unittest
from authtrail.cli import main, investigate, parse_line
from authtrail.config import load_config
from authtrail.detection import investigate_distributed
from authtrail.incidents import group_incidents
from test_core import event


def attack(count=10, spacing=1, host='host', user='admin'):
    base = event(0, user=user, host=host)
    return [replace(base, timestamp=base.timestamp+timedelta(seconds=i*spacing),
                    source_ip=f'192.0.2.{i%5+1}', line=i+1, raw=f'event {i}') for i in range(count)]

class DistributedTests(unittest.TestCase):
    def test_account_and_host_rules(self):
        findings = investigate_distributed(attack())
        self.assertEqual({f['rule'] for f in findings}, {'distributed_account', 'distributed_host'})
        self.assertTrue(all(f['event_count'] == 10 for f in findings))
        self.assertTrue(all(len(f['source_ips']) == 5 for f in findings))

    def test_host_rule_with_distinct_accounts(self):
        findings = investigate_distributed([replace(e, user=f'u{i}') for i,e in enumerate(attack())])
        self.assertEqual([f['rule'] for f in findings], ['distributed_host'])

    def test_one_source_and_separate_hosts(self):
        self.assertEqual(investigate_distributed([replace(e, source_ip='192.0.2.1') for e in attack()]), [])
        self.assertEqual(investigate_distributed([replace(e, host=f'h{i}') for i,e in enumerate(attack())]), [])

    def test_slow_attack_window(self):
        self.assertEqual(investigate_distributed(attack(spacing=180)), [])
        self.assertEqual(len(investigate_distributed(attack(spacing=180), window=3600)), 2)

    def test_boundaries_and_rearming(self):
        records = attack(spacing=10)
        self.assertEqual(len(investigate_distributed(records, window=90)), 2)
        self.assertEqual(investigate_distributed(records, window=89), [])
        later = [replace(e, timestamp=e.timestamp+timedelta(hours=1), raw=e.raw+' later') for e in records]
        self.assertEqual(len(investigate_distributed(records+later)), 4)

    def test_complete_burst_and_success_ignored(self):
        records = attack(count=20)
        records.append(replace(records[-1], outcome='accepted'))
        findings = investigate_distributed(records)
        self.assertTrue(all(f['event_count'] == 20 for f in findings))

class IncidentTests(unittest.TestCase):
    def test_deduplicates_overlapping_rules(self):
        findings = investigate_distributed(attack())
        groups = group_incidents(findings)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]['event_count'], 10)
        self.assertEqual(groups[0]['finding_indexes'], [0,1])

    def test_unrelated_and_separated_findings(self):
        a = investigate([event(i) for i in range(5)])[0]
        b = dict(a, accounts=['other'], evidence=[dict(e, user='other', source_ip='203.0.113.1', raw=e['raw']+' other') for e in a['evidence']])
        self.assertEqual(len(group_incidents([a,b])), 2)
        self.assertEqual(len(group_incidents([a,dict(a,host='other')])), 2)
        later = dict(a, start='2026-11-01T14:00:00+00:00', end='2026-11-01T14:00:05+00:00')
        self.assertEqual(len(group_incidents([a,later])), 2)

class ConfigAndFixtureTests(unittest.TestCase):
    def test_config_validation(self):
        for data in ({'unknown':1}, {'window':True}, {'users':0}, {'exclude_user':'backup'}, {'exclude_source':['bad']}):
            with self.subTest(data=data), tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp)/'config.json'; path.write_text(json.dumps(data))
                with self.assertRaises(ValueError): load_config(path)

    def test_fixture_and_cli_precedence(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'report.json'
            args=[str(root/'examples/logs/scenarios.log'),'--year','2026','--config',str(root/'examples/config/config.json'),'--json',str(output),'--html',str(Path(tmp)/'report.html')]
            with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(main(args),0)
            report=json.loads(output.read_text())
            self.assertEqual(report['schema_version'],3)
            self.assertEqual(report['stats']['excluded'],8)
            self.assertEqual({f['host'] for f in report['findings']},{'edge','target'})
            self.assertEqual(len(report['incidents']),2)
            self.assertEqual(next(i for i in report['incidents'] if i['host']=='target')['severity'],'high')
            self.assertIn('Grouped investigations',(Path(tmp)/'report.html').read_text())
            with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(main(args+['--distributed-window','3600']),0)
            report=json.loads(output.read_text())
            self.assertIn('slow',{f['host'] for f in report['findings']})
            self.assertEqual(report['configuration']['distributed_window'],3600)
