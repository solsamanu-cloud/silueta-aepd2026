#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
PY="${SILUETA_PYTHON:-$PWD/.venv/bin/python}"
"$PY" bin/check-dependencies.py
mkdir -p state captures/live
"$PY" -m silueta.synthetic captures/synthetic.pcap --duration 180
exec "$PY" live/server.py --replay captures/synthetic.pcap --port "${PORT:-8798}"
