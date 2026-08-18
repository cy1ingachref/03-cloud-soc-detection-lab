#!/usr/bin/env python3
"""
tests/test_detections.py — Prove the detection engine fires on simulated attacks.

We import run_detections.py directly (importlib, no install) and feed it
hand-built event streams. Each test asserts the corresponding Sigma rule alerts.

Run:  python -m unittest tests.test_detections -v
"""

import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DETECTIONS = os.path.join(HERE, "..", "detections", "run_detections.py")
RULES = os.path.join(HERE, "..", "rules")

spec = importlib.util.spec_from_file_location("run_detections", DETECTIONS)
rd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rd)


def rule_by_title(title):
    for f in os.listdir(RULES):
        if f.endswith(".yml"):
            r = rd.load_rule(os.path.join(RULES, f))
            if r["title"] == title:
                return r
    raise FileNotFoundError("rule not found: %s" % title)


def mk_event(outcome, user, ip, ts):
    return {
        "timestamp": ts,
        "event": {"outcome": outcome, "user": user, "target": user},
        "source": {"ip": ip},
    }


class TestBruteForceRule(unittest.TestCase):
    def test_fires_on_burst(self):
        rule = rule_by_title("Account Brute Force Detected")
        events = [mk_event("failure", "admin", "203.0.113.45",
                           "2026-08-18T10:00:%02dZ" % i) for i in range(8)]
        alerts = rd.evaluate(rule, events)
        self.assertTrue(alerts, "brute-force rule must fire on 8 failures")
        self.assertGreater(alerts[0]["count"], 5)

    def test_no_fire_on_single(self):
        rule = rule_by_title("Account Brute Force Detected")
        events = [mk_event("failure", "admin", "203.0.113.45", "2026-08-18T10:00:00Z")]
        self.assertFalse(rd.evaluate(rule, events))


class TestImpossibleTravelRule(unittest.TestCase):
    def test_fires_on_two_ips(self):
        rule = rule_by_title("Impossible Travel for a Single Account")
        events = [
            mk_event("success", "admin", "10.0.0.1", "2026-08-18T10:00:00Z"),
            mk_event("success", "admin", "192.0.2.50", "2026-08-18T10:05:00Z"),
        ]
        alerts = rd.evaluate(rule, events)
        self.assertTrue(alerts, "impossible-travel rule must fire on two IPs")

    def test_no_fire_single_ip(self):
        rule = rule_by_title("Impossible Travel for a Single Account")
        events = [mk_event("success", "admin", "10.0.0.1", "2026-08-18T10:00:00Z")]
        self.assertFalse(rd.evaluate(rule, events))


class TestYamlParser(unittest.TestCase):
    def test_parse_rule(self):
        rule = rule_by_title("Account Brute Force Detected")
        self.assertEqual(rule["level"], "high")
        self.assertIn("failure", rule["selection"].get("event.outcome", ""))


if __name__ == "__main__":
    unittest.main(verbosity=2)
