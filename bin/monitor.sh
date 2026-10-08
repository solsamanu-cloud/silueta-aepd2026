#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
PY="${SILUETA_PYTHON:-$PWD/.venv/bin/python}"
mkdir -p state captures/live logs
"$PY" -c 'from live import policy; policy.capture_filter()'
sudo systemd-run --unit=silueta-consent-monitor --collect --property=KillMode=mixed --property=TimeoutStopSec=60 \
  --working-directory="$PWD" /usr/bin/systemd-inhibit --what=sleep:idle --mode=block \
  --why="SILUETA: monitorización autorizada" "$PY" "$PWD/bin/monitor.py"
printf '%s\n' 'Estado: systemctl status silueta-consent-monitor' 'Parada con guardado: touch state/continuous-monitor.stop' 'GUI de consulta: http://127.0.0.1:8798/services'
