import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from authtrail.cli import main
from authtrail.config import load_config
from authtrail.reporting import compact_report
from test_core import event

class ReleaseTests(unittest.TestCase):
    def test_model_records_are_not_shared_mutable_state(self):
        e=event(1); a=e.record(); a['user']='changed'
        self.assertEqual(e.record()['user'],'deploy')
    def test_defaults_are_independent(self):
        a=load_config(None);a['exclude_user'].append('root')
        self.assertEqual(load_config(None)['exclude_user'],[])
    def test_limits_preserve_existing_output(self):
        for flag,value in [('--max-events','1'),('--max-line-bytes','10')]:
            with self.subTest(flag=flag),tempfile.TemporaryDirectory() as tmp:
                p=Path(tmp)/'log';out=Path(tmp)/'out';out.write_text('original')
                p.write_text(event(1).raw+'\n'+event(2).raw+'\n')
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(main([str(p),'--year','2026',flag,value,'--json',str(out)]),2)
                self.assertEqual(out.read_text(),'original')
    def test_compact_report_references(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'log';out=Path(tmp)/'out'
            p.write_text('\n'.join(event(i).raw for i in range(10)))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(p),'--year','2026','--compact-json','--json',str(out)]),0)
            report=json.loads(out.read_text())
            self.assertEqual(len(report['events']),10)
            for f in report['findings']:
                self.assertTrue(all(i in report['events'] for i in f['evidence_ids']))
    def test_corrupt_gzip(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'bad.gz';p.write_bytes(b'not gzip')
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main([str(p),'--year','2026']),2)
