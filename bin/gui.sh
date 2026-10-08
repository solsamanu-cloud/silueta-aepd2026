#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PORT="${1:-8798}"
[[ "$PORT" =~ ^[0-9]+$ ]] && ((PORT>=1024 && PORT<=65535)) || { echo 'Puerto inválido'; exit 2; }
[[ $EUID -ne 0 ]] || { echo 'Ejecuta como usuario normal, sin sudo delante.'; exit 2; }
for tool in tshark tcpdump iw sudo systemd-inhibit; do command -v "$tool" >/dev/null || { echo "Falta $tool"; exit 2; }; done
PYTHON="${SILUETA_PYTHON:-$ROOT/.venv/bin/python}"
[[ -x "$PYTHON" ]] || { echo 'Crea .venv e instala requirements.txt'; exit 2; }
"$PYTHON" - "$PORT" <<'PY'
import socket,sys
with socket.socket() as s:
    try:s.bind(('127.0.0.1',int(sys.argv[1])))
    except OSError:sys.exit('Puerto ocupado. Reutiliza la app abierta o elige otro puerto; no se detuvo ningún proceso.')
PY
"$PYTHON" bin/check-dependencies.py
mkdir -p state captures/live logs
# The declaration is made in the browser; sudo authorizes only the capture process.
sudo -v
keepalive=''
cleanup(){ [[ -z "$keepalive" ]] || kill "$keepalive" 2>/dev/null || true; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
(while sleep 60; do sudo -n -v || exit; done) & keepalive=$!
echo "SILUETA: http://127.0.0.1:$PORT/ · servidor local; deja este terminal abierto."
"$PYTHON" -u live/server.py --port "$PORT"
