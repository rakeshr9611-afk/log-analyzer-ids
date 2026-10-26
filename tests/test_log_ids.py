import argparse
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import log_ids  # noqa: E402

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


def config(**overrides):
    cfg = dict(window=60, ssh_threshold=5, user_enum_threshold=5,
               notfound_threshold=20, year=2026)
    cfg.update(overrides)
    return argparse.Namespace(**cfg)


def load(name):
    with open(os.path.join(SAMPLES, name)) as f:
        return f.readlines()


class SSHTests(unittest.TestCase):
    def setUp(self):
        self.log_type, self.alerts = log_ids.analyze(load("auth.log"), config())

    def categories(self, ip):
        return {a.category for a in self.alerts if a.ip == ip}

    def test_detects_ssh_log(self):
        self.assertEqual(self.log_type, "ssh")

    def test_brute_force_and_compromise(self):
        cats = self.categories("203.0.113.45")
        self.assertIn("SSH brute force", cats)
        self.assertIn("Login after brute force", cats)
        self.assertEqual(self.alerts[0].severity, "CRITICAL")

    def test_user_enumeration(self):
        self.assertIn("SSH user enumeration", self.categories("198.51.100.7"))

    def test_invalid_user_lines_not_double_counted(self):
        alert = next(a for a in self.alerts
                     if a.ip == "198.51.100.7" and a.category == "SSH brute force")
        self.assertEqual(alert.count, 7)

    def test_single_typo_is_not_flagged(self):
        self.assertEqual(self.categories("192.168.1.20"), set())


class WebTests(unittest.TestCase):
    def setUp(self):
        self.log_type, self.alerts = log_ids.analyze(load("access.log"), config())

    def categories(self, ip):
        return {a.category for a in self.alerts if a.ip == ip}

    def test_detects_web_log(self):
        self.assertEqual(self.log_type, "web")

    def test_sqli_xss_and_scanner(self):
        cats = self.categories("203.0.113.99")
        self.assertIn("Web attack: SQL injection", cats)
        self.assertIn("Web attack: Cross-site scripting", cats)
        self.assertIn("Scanner user agent", cats)

    def test_traversal_and_command_injection(self):
        cats = self.categories("198.51.100.23")
        self.assertIn("Web attack: Path traversal", cats)
        self.assertIn("Web attack: Command injection", cats)
        self.assertIn("Web attack: Sensitive file probe", cats)

    def test_directory_scan(self):
        self.assertIn("Web directory scan", self.categories("192.0.2.77"))

    def test_normal_user_is_not_flagged(self):
        self.assertEqual(self.categories("192.168.1.50"), set())


class WindowTests(unittest.TestCase):
    def test_sliding_window_peak(self):
        from datetime import datetime, timedelta
        base = datetime(2026, 1, 1)
        times = [base + timedelta(seconds=s) for s in (0, 10, 20, 200, 205)]
        self.assertEqual(log_ids.sliding_window_peak(times, timedelta(seconds=60)), 3)


if __name__ == "__main__":
    unittest.main()
