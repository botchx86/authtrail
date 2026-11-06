"""Synthetic OpenSSH format compatibility fixtures; not production data."""
from datetime import timezone
import unittest
from authtrail.parsing import parse_line

class FormatTests(unittest.TestCase):
    def test_openssh_formats(self):
        fixtures = [
            ('Nov  6 10:00:00 debian sshd[100]: Failed password for invalid user admin from 192.0.2.1 port 12345 ssh2', 'failed', 'admin'),
            ('Nov  6 10:00:00 rhel sshd[101]: Accepted publickey for deploy from 2001:db8::1 port 12345 ssh2: ED25519 SHA256:example', 'accepted', 'deploy'),
            ('2026-11-06T10:00:00.123456+00:00 ubuntu sshd-session[102]: Failed keyboard-interactive/pam for root from 192.0.2.2 port 12345 ssh2', 'failed', 'root'),
            ('2026-11-06T11:00:00+01:00 host sshd: Accepted password for alice from ::1 port 12345 ssh2', 'accepted', 'alice'),
        ]
        for raw, outcome, user in fixtures:
            with self.subTest(raw=raw):
                event = parse_line(raw, 'synthetic', 1, 2026, timezone.utc)
                self.assertEqual((event.outcome, event.user), (outcome, user))
                self.assertEqual(event.timestamp.hour, 10)
    def test_unsupported_formats_are_explicitly_not_claimed(self):
        self.assertIsNone(parse_line('{"MESSAGE":"Accepted password"}', 'synthetic', 1, 2026, timezone.utc))
        self.assertIsNone(parse_line('Nov  6 10:00:00 host sshd[1]: pam_unix(sshd:auth): authentication failure', 'synthetic', 1, 2026, timezone.utc))
