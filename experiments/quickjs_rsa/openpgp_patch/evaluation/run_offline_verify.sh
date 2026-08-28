#!/usr/bin/env bash
# Reproduce the Part 2 decode from the traces in ../data/traces and check it
# against the published numbers. No capture hardware and no build required,
# needs only numpy, takes about ten seconds.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PY="${PYTHON:-python3}"
for cand in "$HERE/../../../../.venv/bin/python3" "$HERE/.venv/bin/python3"; do
	if [ -x "$cand" ]; then
		PY="$cand"
		break
	fi
done

"$PY" -c 'import numpy' 2>/dev/null || {
	echo "numpy is required: python3 -m venv .venv && .venv/bin/pip install numpy" >&2
	exit 1
}

cd "$HERE"
"$PY" reproduce.py
echo
"$PY" verify.py
