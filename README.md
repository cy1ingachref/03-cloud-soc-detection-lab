# 03 — Cloud SOC / Detection-as-Code Lab

**Hireability:** This is blue-team depth that almost no student has. It shows
you can BUILD and OPERATE a detection pipeline: collect logs, write detections
as code (Sigma), simulate real attacks (Atomic Red Team), and PROVE the alerts
fire. That is the exact skill set of a Detection Engineer / SOC analyst, and
it pairs perfectly with your red-team pentest experience — making you a
rare "purple team" candidate.

**The story:** After finding flaws at E-Tafakna, the natural next question is
"how would we know if someone exploited this?" This lab answers it: a local
ELK/Wazuh-style stack that ingests auth logs, Sigma rules that encode the
detections, and an Atomic Red Team simulation that proves the alert triggers.

## What it contains
- `docker-compose.yml` — Elasticsearch + Kibana + a log generator + detection runner
- `rules/sigma_auth_bruteforce.yml` — Sigma rule: detect password-spray / brute force
- `rules/sigma_impossible_travel.yml` — Sigma rule: impossible travel (geo anomaly)
- `simulate/atomic_bruteforce.py` — Atomic Red Team-style T1110 simulation (writes auth logs)
- `detections/run_detections.py` — loads Sigma rules, matches against logs, emits alerts
- `tests/test_detections.py` — proves each rule fires on the simulated attack
- `GUIDE.md` — step-by-step

> Requires Docker + Python 3.7+. ELK is heavy; the detection logic is also run
> standalone (no Elasticsearch needed) via `detections/run_detections.py` so you
> can demo the Sigma matching on any machine.

## Quick start (standalone, no Docker needed to verify detections)
```
python simulate/atomic_bruteforce.py > logs/auth.log
python detections/run_detections.py logs/auth.log
python -m unittest tests.test_detections -v
```
This proves the detection pipeline works without standing up the full stack.

## Full stack (Docker)
```
docker compose up -d        # starts ES + Kibana + generator + runner
# Kibana at http://localhost:5601  (observe the brute-force alert)
```

See `GUIDE.md` for the code-by-code walkthrough and how to write your own rules.
