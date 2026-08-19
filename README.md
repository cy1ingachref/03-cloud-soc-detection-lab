# 03 — Cloud SOC / Detection-as-Code Lab

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)  
[![CI](https://img.shields.io/badge/CI-Docker%20Compose-blue)](#)  

## Overview

A hands-on lab that demonstrates building a lightweight cloud SOC pipeline locally. The project shows how to collect logs, express detections as Sigma rules, simulate attacks using Atomic Red Team-style scripts, and validate that alerts fire using an autograder-style test harness.

This README was upgraded to a full professional template automatically. See CHANGELOG below for details.

---

## Quick links
- Repository: https://github.com/cy1ingachref/03-cloud-soc-detection-lab
- Local demo: scripts in `simulate/` and `detections/`

## Features
- Docker Compose-based ELK-style stack for ingesting and visualizing logs
- Sigma rules for common threats (brute force, impossible travel)
- Simulation scripts that generate realistic auth logs for testing
- Test harness to assert detections fire reliably

## Requirements
- Docker and docker-compose
- Python 3.7+ for simulation and detection scripts

## Quick start (standalone detections)
Run the simulation and detection locally without Docker:

```bash
python simulate/atomic_bruteforce.py > logs/auth.log
python detections/run_detections.py logs/auth.log
python -m unittest tests.test_detections -v
```

## Full stack (Docker Compose)

```bash
docker compose up -d
# Open Kibana at http://localhost:5601 to inspect alerts
```

## Configuration
- `rules/*.yml` - Sigma rules that encode detection logic
- `docker-compose.yml` - service definitions for Elasticsearch/Kibana + runner
- `detections/` - detection runner that can operate standalone or push to ES

## Development & Testing
Run unit tests and linter where applicable:

```bash
python -m unittest discover -v
```

## Contributing
1. Fork the repo and create a branch from `main`.
2. Run tests locally and ensure all pass.
3. Open a PR with a clear description of your change.

See CONTRIBUTING.md for details (auto-generated placeholder).

## License
MIT License — see LICENSE file.

## Maintainer
- Achref Ferjani — https://github.com/cy1ingachref

## CHANGELOG
- 2026-08-19: README upgraded to full professional template by automated process.
