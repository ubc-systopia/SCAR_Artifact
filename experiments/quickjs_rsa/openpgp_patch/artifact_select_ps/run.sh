#!/usr/bin/env bash
# Reproduce the results from the included traces (Path A in README.md).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PY="${PYTHON:-python3}"
if [ -x "$HERE/.venv/bin/python3" ]; then PY="$HERE/.venv/bin/python3"; fi

"$PY" -c 'import numpy' 2>/dev/null || {
    echo "numpy is required: python3 -m venv .venv && .venv/bin/pip install numpy" >&2
    exit 1
}

cd "$HERE/analysis"
"$PY" reproduce.py
echo
"$PY" verify.py
