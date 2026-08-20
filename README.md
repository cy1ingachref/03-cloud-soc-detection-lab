# 03 — Cloud SOC / Detection-as-Code Lab

A hands-on Detection-as-Code lab demonstrating log collection, Sigma rule development, simulation of adversary behavior, and end-to-end validation using unit tests and an optional ELK-like stack. Designed to show that you can both write detections and operate a detection pipeline.

Why this project matters

- Demonstrates practical detection engineering and operational skills (valuable for SOC/Detection Engineer roles).
- Shows how to validate detections with reproducible simulations and unit tests.
- Provides both a lightweight standalone mode and a full Docker stack for realistic demos.

What’s included

- `docker-compose.yml` — optional ELK/Kibana-style stack for full-stack demos
- `rules/` — Sigma rules (e.g., auth brute-force, impossible travel)
- `simulate/atomic_bruteforce.py` — attacker simulation that generates auth logs
- `detections/run_detections.py` — Sigma loader and matcher for log files
- `tests/test_detections.py` — unit tests that prove rules fire on simulated attacks
- `GUIDE.md` — walkthrough for each component and how to author Sigma rules

Quick start (standalone)

# generate logs and run detections
python simulate/atomic_bruteforce.py > logs/auth.log
python detections/run_detections.py logs/auth.log
python -m unittest tests.test_detections -v

Full stack (Docker)

# start Elasticsearch + Kibana + generator + runner
docker compose up -d
# open Kibana at http://localhost:5601 to observe alerts

Notes

- The detection logic can run standalone without Elasticsearch to make demos and CI validation lightweight.
- See GUIDE.md for instructions on extending rules and integrating with SIEMs.
