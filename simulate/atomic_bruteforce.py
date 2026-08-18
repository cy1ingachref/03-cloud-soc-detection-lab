#!/usr/bin/env python3
"""
atomic_bruteforce.py — Atomic Red Team-style T1110 simulation.

Writes realistic authentication log lines in JSON-per-line format to a file
(or stdout in --loop mode for the Docker generator). This emulates what an
attacker doing password spraying / brute force would produce, so the detection
pipeline has something real to alert on.

Schema (matches the Sigma rules: source.ip is top-level, event.* holds outcome/user/target):
  {"timestamp": ISO,
   "event": {"outcome": "failure"|"success", "user": "...", "target": "..."},
   "source": {"ip": "1.2.3.4"}}

Run:
  python atomic_bruteforce.py                  -> writes one burst to stdout
  python atomic_bruteforce.py --out logs/auth.log
  python atomic_bruteforce.py --out logs/auth.log --loop   (Docker generator)
"""

import argparse
import functools
import json
import os
import random
import sys
import time
from datetime import datetime, timezone


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Module-level output stream so emit() has a stable signature everywhere.
STREAM = sys.stdout


def emit(user, outcome, ip):
    rec = {
        "timestamp": now_iso(),
        "event": {
            "outcome": outcome,
            "user": user,
            "target": user,
        },
        "source": {"ip": ip},
    }
    STREAM.write(json.dumps(rec) + "\n")
    STREAM.flush()


def burst(target_user, n_failures=8, attacker_ip="203.0.113.45"):
    """A classic password-spray burst: many failures for one account, then a
    success from the attacker IP AND a second success from a different IP
    (impossible travel) so the live demo triggers both detections."""
    for _ in range(n_failures):
        emit(target_user, "failure", attacker_ip)
    emit(target_user, "success", attacker_ip)
    emit(target_user, "success", "198.51.100.23")  # different /16 -> impossible travel


def loop(out_path):
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "a", encoding="utf-8") as fh:
        global STREAM
        STREAM = fh
        users = ["admin", "alice", "bob", "root", "svc_backup"]
        while True:
            u = random.choice(users)
            for _ in range(random.randint(6, 12)):
                emit(u, "failure", "203.0.113.%d" % random.randint(1, 254))
            emit(u, "success", "198.51.100.%d" % random.randint(1, 254))  # different /16 -> travel
            time.sleep(5)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", help="write to file instead of stdout")
    ap.add_argument("--loop", action="store_true", help="continuously generate (Docker)")
    args = ap.parse_args()

    if args.loop:
        loop(args.out)
        return

    global STREAM
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        STREAM = open(args.out, "w", encoding="utf-8")
    burst("admin")
    burst("root")
    if args.out:
        STREAM.close()


if __name__ == "__main__":
    main()
