import contextlib
import errno
import io
import os
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch
from datetime import timezone
from authtrail.cli import main
from authtrail.parsing import parse_line
from authtrail.storage import atomic_write
from authtrail.config import load_config

class AdversarialTests(unittest.TestCase):
    def test_random_malformed_input(self):
        rng=random.Random(1404)
        for _ in range(5000):
            raw=''.join(chr(rng.randrange(1,128)) for _ in range(rng.randrange(200)))
            self.assertIsNone(parse_line(raw,'fuzz',1,2026,timezone.utc))
    def test_duplicate_config_key_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'config';p.write_text('{"window":10,"window":100}')
            with self.assertRaises(ValueError):load_config(p)
    def test_write_failures_preserve_previous_report(self):
        for error in (OSError(errno.ENOSPC,'disk full'),PermissionError('denied'),KeyboardInterrupt()):
            with self.subTest(error=type(error)),tempfile.TemporaryDirectory() as tmp:
                p=Path(tmp)/'report';p.write_text('original')
                with patch('authtrail.storage.os.fsync',side_effect=error):
                    with self.assertRaises(type(error)):atomic_write(p,'new')
                self.assertEqual(p.read_text(),'original')
                self.assertEqual(list(Path(tmp).iterdir()),[p])
    def test_output_private_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'report';atomic_write(p,'new')
            self.assertEqual(p.stat().st_mode & 0o777,0o600)
    def test_truncated_gzip_and_missing_input(self):
        import gzip
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'bad.gz';p.write_bytes(gzip.compress(b'hello')[:-5])
            for path in (p,Path(tmp)/'missing'):
                with contextlib.redirect_stderr(io.StringIO()):self.assertEqual(main([str(path),'--year','2026']),2)
    def test_total_bytes_and_encoding_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'log';p.write_text('ignored\n'*20)
            with contextlib.redirect_stderr(io.StringIO()):self.assertEqual(main([str(p),'--year','2026','--max-input-bytes','10']),2)
            p.write_bytes(b'\xff\xfe')
            with contextlib.redirect_stderr(io.StringIO()):self.assertEqual(main([str(p),'--year','2026']),2)
    @unittest.skipUnless(hasattr(os,'mkfifo'),'requires POSIX')
    def test_fifo_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'fifo';os.mkfifo(p)
            with contextlib.redirect_stderr(io.StringIO()):self.assertEqual(main([str(p),'--year','2026']),2)
