# GUIDE — 03 Cloud SOC / Detection-as-Code Lab (step by step, code by code)

This guide explains every file and how the detection pipeline works, then shows
how to prove it fires. The detection engine (`run_detections.py`) is a teaching
re-implementation of Sigma so the lab runs with ZERO dependencies and is fully
testable — real Sigma uses pySigma + a backend; we implement the exact subset
our rules need.

────────────────────────────────────────────────────────────────────────────
STEP 1 — The architecture
────────────────────────────────────────────────────────────────────────────
  simulate/atomic_bruteforce.py  -> writes JSON auth logs (the "attack")
            |
            v
  logs/auth.log  (or streamed to Elasticsearch in Docker)
            |
            v
  detections/run_detections.py  -> applies Sigma rules -> ALERTS
            |
            v
  Elasticsearch + Kibana (Docker)  -> visualize alerts at :5601

────────────────────────────────────────────────────────────────────────────
STEP 2 — Sigma rules (rules/*.yml)
────────────────────────────────────────────────────────────────────────────
Sigma is the open standard for writing detections ONCE and running them on any
SIEM. Our two rules:

  sigma_auth_bruteforce.yml
    logsource: authentication
    selection: event.outcome == failure
    condition: count(event.user) by event.target > 5 in 1m
    -> MITRE T1110. Alerts when one account fails auth >5x in a minute.

  sigma_impossible_travel.yml
    selection: event.outcome == success
    condition: count(event.user) by source.ip > 1 in 10m
    -> MITRE T1078. Alerts when one account succeeds from >1 IP in 10 min.

Each rule has id, title, status, description, author, date, logsource,
detection{selection, condition}, fields, falsepositives, level.

────────────────────────────────────────────────────────────────────────────
STEP 3 — The simulator (simulate/atomic_bruteforce.py)
────────────────────────────────────────────────────────────────────────────
Atomic Red Team (by Red Canary) is a library of small, safe tests for each
MITRE technique. Our simulator does T1110: it emits JSON auth events:

  {"timestamp": ISO, "event": {"outcome": "failure"|"success",
   "user": "...", "target": "...", "source": {"ip": "1.2.3.4"}}}

- burst(user): 8 failures + 1 success for one account (the spray).
- loop(): continuous generation for the Docker `generator` service, including
  a different source /16 on the success to trigger impossible travel.

Why JSON lines? It's the universal log interchange format — easy to parse and
to ship to any SIEM.

────────────────────────────────────────────────────────────────────────────
STEP 4 — The detection engine (detections/run_detections.py)
────────────────────────────────────────────────────────────────────────────
Pure stdlib. Key functions:

  parse_simple_yaml(text): a tiny YAML reader for OUR rule schema (no PyYAML).
    Walks indented lines into a nested dict. (In prod you'd use the `sigma`
    package; we keep it dependency-free for the demo.)

  load_rule(path): reads a .yml into {id,title,level,selection,condition}.

  event_matches(ev, selection): checks a log event against the selection dict,
    supporting dotted paths like "event.outcome".

  evaluate(rule, events): the core. Two modes:
    - count condition (regex COUNT_RE): buckets events by the `by` field, then
      sliding-window counts within the time window and alerts if > threshold.
    - plain selection: alerts if any event matches.

  load_events(path): reads JSON-lines log file into a list of dicts.
  ship_to_es(alerts, es_url): best-effort POST each alert to Elasticsearch.
  main(): loads events, runs every rule in --rules, prints ALERTS, optionally
    ships to --es. Exit 1 if nothing detected (CI-friendly: "did it catch it?").

────────────────────────────────────────────────────────────────────────────
STEP 5 — Tests (tests/test_detections.py)
────────────────────────────────────────────────────────────────────────────
Proves the engine fires correctly:
  - 8 failures -> brute-force alerts (count > 5)
  - 1 failure -> no alert
  - two success IPs -> impossible-travel alerts
  - one IP -> no impossible-travel alert
  - YAML parser reads level/selection

────────────────────────────────────────────────────────────────────────────
STEP 6 — Docker stack (docker-compose.yml)
────────────────────────────────────────────────────────────────────────────
  elasticsearch  single-node, security off, healthcheck
  kibana         dashboards at :5601
  generator      runs atomic_bruteforce.py --loop -> logs/auth.log
  detector       runs run_detections.py -> ships alerts to ES (index soc-alerts)

Run:  docker compose up -d
Then open http://localhost:5601 and create an index pattern on `soc-alerts`.

────────────────────────────────────────────────────────────────────────────
STEP 7 — VERIFY (standalone, no Docker)
────────────────────────────────────────────────────────────────────────────
  python simulate/atomic_bruteforce.py --out logs/auth.log
  python detections/run_detections.py logs/auth.log
  python -m unittest tests.test_detections -v

You should see [ALERT] HIGH Account Brute Force and [ALERT] MEDIUM Impossible
Travel, and all unit tests pass. THAT is the proof the detection works.

────────────────────────────────────────────────────────────────────────────
STEP 8 — CV / LinkedIn line
────────────────────────────────────────────────────────────────────────────
"Built a detection-as-code lab: Sigma rules (T1110 brute force, T1078
impossible travel) evaluated by a stdlib engine against Atomic Red Team-style
simulated auth logs, with a Dockerized ELK stack for visualization and unit
tests proving each alert fires."
