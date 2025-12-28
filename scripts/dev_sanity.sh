#!/bin/sh
set -eu

# dev_sanity.sh
#
# Purpose:
# - A lightweight smoke test for local development.
# - Validates CLI parsing/config wiring and a short end-to-end generation run.
#
# What it does:
# 1) Runs an estimate-only invocation (no PCAP generation) to confirm the CLI,
#    config, and estimator are wired correctly.
# 2) Runs a short `--smoke` generation to confirm packet creation and buffered
#    PCAP writers work.
#
# How it runs:
# - Uses `PYTHONPATH=src` so it can run from a source checkout.
# - Writes output under `temp_pcaps*/` (delete these directories after runs).
#
# Usage:
# - Run inside your venv: `./scripts/dev_sanity.sh`
#
# Estimate-only run to validate CLI and config wiring.
PYTHONPATH=src python -m net_traffic_sim --estimate-only --target-size 1 --duration 1 --output-dir temp_pcaps

# Short smoke generation to validate packet creation and writers.
PYTHONPATH=src python -m net_traffic_sim --target-size 1 --duration 1 --output-dir temp_pcaps --smoke
