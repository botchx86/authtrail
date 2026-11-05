import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from dataclasses import replace
from datetime import timedelta
from authtrail.cli import main, investigate
from authtrail.storage import atomic_write, check_outputs
from authtrail.detection import distributed_success
from authtrail.incidents import group_incidents
from test_authtrail import event
from test_v03 import attack

class RegressionTests(unittest.TestCase):
    def test_hardlinks_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            a=Path(tmp)/'a'; b=Path(tmp)/'b'; a.write_text('original'); os.link(a,b)
            with self.assertRaises(ValueError): check_outputs([a],[b])
            self.assertEqual(a.read_text(),'original')
    def test_failed_replace_preserves_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'report';p.write_text('original')
            with patch('authtrail.storage.os.replace',side_effect=OSError('failed')):
                with self.assertRaises(OSError): atomic_write(p,'new')
            self.assertEqual(p.read_text(),'original')
            self.assertEqual(len(list(Path(tmp).iterdir())),1)
    def test_distributed_success(self):
        records=attack(); success=replace(records[-1],timestamp=records[-1].timestamp+timedelta(seconds=1),outcome='accepted')
        self.assertEqual(len(distributed_success(records+[success])),1)
        self.assertEqual(distributed_success(records+[replace(success,user='other')]),[])
    def test_same_timestamp_order_independent(self):
        records=[event(i) for i in range(4)]; fail=event(4); success=event(4,outcome='Accepted')
        self.assertEqual(investigate(records+[fail,success]),investigate(records+[success,fail]))
    def test_occurrence_deduplication_and_strict_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);a=root/'a';b=root/'b';out=root/'out'
            raw=event(1).raw+'\n';a.write_text(raw*5);b.write_text(raw*3)
            args=[str(a),str(b),'--year','2026','--json',str(out)]
            with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(main(args),0)
            report=json.loads(out.read_text());self.assertEqual(report['stats']['parsed'],5);self.assertEqual(report['stats']['duplicates'],3)
            a.write_text('unsupported\n')
            with contextlib.redirect_stderr(io.StringIO()): self.assertEqual(main([str(a),'--year','2026','--strict']),2)
    def test_no_account_only_default_merge(self):
        a=investigate([event(i) for i in range(5)])[0]
        b=dict(a,evidence=[dict(e,source_ip='203.0.113.1',file='other') for e in a['evidence']])
        self.assertEqual(len(group_incidents([a,b])),2)
        joined=group_incidents([a,b],group_by='account');self.assertEqual(len(joined),1)
        self.assertTrue(joined[0]['relationships'])
