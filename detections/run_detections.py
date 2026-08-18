#!/usr/bin/env python3
"""
run_detections.py — A minimal Sigma-compatible detection engine (stdlib only).

This is a TEACHING implementation of how Sigma rules map to runtime detections.
It parses our simplified Sigma YAML (selection + a count-based condition) and
evaluates it against JSON auth logs. Real Sigma uses pySigma + a backend
(Elasticsearch/SQL/Splunk); here we implement the exact subset our rules use so
the lab runs with zero dependencies and is fully testable.

Condition grammar supported:
  selection                                   -> any matching event
  selection | count(field) by group > N in Mm -> threshold over a time window

Run:
  python run_detections.py logs/auth.log
  python run_detections.py logs/auth.log --es http://localhost:9200   (ships alerts)
"""

import argparse
import json
import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone

# We use a tiny YAML parser for OUR specific rule format (no PyYAML dependency).
# It handles the subset we use: nested mappings, lists, and inline scalars.
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.path.join(HERE, "..", "rules")


# ---- minimal YAML reader for our rule schema -------------------------------
def parse_simple_yaml(text):
    """Parse the subset of YAML our rules use. Returns a nested dict."""
    lines = text.splitlines()
    root = {}
    stack = [(-1, root)]
    for raw in lines:
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        key, _, val = raw.strip().partition(":")
        key = key.strip()
        val = val.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if val == "":
            node = {}
            parent[key] = node
            stack.append((indent, node))
        else:
            parent[key] = _scalar(val)
    return root


def _scalar(v):
    if v.startswith('"') and v.endswith('"'):
        return v[1:-1]
    if v.startswith("'") and v.endswith("'"):
        return v[1:-1]
    return v


# ---- condition evaluator ---------------------------------------------------
COUNT_RE = re.compile(
    r"selection\s*\|\s*count\((\w+\.\w+)\)\s*by\s*(\w+\.\w+)\s*>\s*(\d+)\s*in\s*(\d+)m"
)


def load_rule(path):
    with open(path, "r", encoding="utf-8") as fh:
        doc = parse_simple_yaml(fh.read())
    detection = doc.get("detection", {})
    condition = detection.get("condition", "selection")
    selection = detection.get("selection", {})
    return {
        "id": doc.get("id"),
        "title": doc.get("title"),
        "level": doc.get("level"),
        "selection": selection,
        "condition": condition,
    }


def event_matches(ev, selection):
    for k, v in selection.items():
        # k like "event.outcome"; support dotted paths
        cur = ev
        for part in k.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return False
        if cur != v:
            return False
    return True


def to_seconds(ts):
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc).timestamp()
    except ValueError:
        return time.time()


def evaluate(rule, events):
    """Return list of alert dicts fired by this rule over the event stream."""
    sel = [e for e in events if event_matches(e, rule["selection"])]
    m = COUNT_RE.search(rule["condition"])
    if m:
        field, group, thr, window = m.groups()
        thr = int(thr)
        window = int(window) * 60
        buckets = defaultdict(list)
        for e in sel:
            gv = _dot(e, group)
            buckets[gv].append(e)
        alerts = []
        for gv, evs in buckets.items():
            evs.sort(key=lambda x: to_seconds(x["timestamp"]))
            # sliding window count
            for i in range(len(evs)):
                t0 = to_seconds(evs[i]["timestamp"])
                cnt = sum(1 for e in evs if t0 <= to_seconds(e["timestamp"]) <= t0 + window)
                if cnt > thr:
                    alerts.append({
                        "rule": rule["title"],
                        "level": rule["level"],
                        "group": {group: gv},
                        "count": cnt,
                        "first_seen": evs[i]["timestamp"],
                    })
                    break
        return alerts
    # plain selection
    if sel:
        return [{"rule": rule["title"], "level": rule["level"], "count": len(sel)}]
    return []


def _dot(ev, path):
    cur = ev
    for part in path.split("."):
        cur = cur.get(part, {}) if isinstance(cur, dict) else {}
    return cur


def load_events(path):
    events = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def ship_to_es(alerts, es_url):
    """Best-effort POST each alert to Elasticsearch (index: soc-alerts)."""
    try:
        import urllib.request
        for a in alerts:
            body = json.dumps(a).encode()
            req = urllib.request.Request(
                es_url.rstrip("/") + "/soc-alerts/_doc",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=5)
    except Exception as exc:  # noqa: BLE001
        print("  [warn] could not ship to ES: %s" % exc, file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile")
    ap.add_argument("--rules", default=RULES_DIR)
    ap.add_argument("--es", help="Elasticsearch URL to ship alerts")
    args = ap.parse_args()

    events = load_events(args.logfile)
    print("Loaded %d events from %s" % (len(events), args.logfile))

    total = 0
    for fname in sorted(os.listdir(args.rules)):
        if not fname.endswith(".yml"):
            continue
        rule = load_rule(os.path.join(args.rules, fname))
        alerts = evaluate(rule, events)
        for a in alerts:
            total += 1
            print("  [ALERT] %-8s %s %s" % (a["level"].upper(), a["rule"], a.get("group", "")))
        if args.es:
            ship_to_es(alerts, args.es)
    print("Total alerts fired: %d" % total)
    return 0 if total > 0 else 1  # CI-friendly: 1 if nothing detected


if __name__ == "__main__":
    sys.exit(main())
