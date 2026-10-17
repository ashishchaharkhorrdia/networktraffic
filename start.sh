#!/usr/bin/env bash
# CyberNinjas Startup Script

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

echo "=========================================================="
echo " Starting CyberNinjas Network Security Operations Suite"
echo "=========================================================="

# Check Python3
if ! command -v python3 &> /dev/null; then
    echo "[!] Error: Python 3 is not installed."
    exit 1
fi

PORT="${PORT:-8000}"
HOST="${HOST:-0.0.0.0}"

python3 main.py --host "$HOST" --port "$PORT"
