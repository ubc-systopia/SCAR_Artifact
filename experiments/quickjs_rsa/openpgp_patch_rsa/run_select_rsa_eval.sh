#!/usr/bin/env bash
# End-to-end Flush+Reload run against the SELECT-patched modExp: victim +
# quickjs_select_rsa_fr attacker, then windowed hit-count decode.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BUILD="${ROOT}/build"
CPUS="${CPUS:-1,3,5,7,9,11,13,15}"
VICTIM_RUNS="${VICTIM_RUNS:-20}"
WAITING_TIME="${WAITING_TIME:-2000}"
ROUND_CYCLES="${ROUND_CYCLES:-6000000000}"
KEY_ID="${KEY_ID:-0}"

VICTIM_BIN="${BUILD}/src/runtime/quickjs/quickjs_rt"
ATTACKER_BIN="${BUILD}/experiments/quickjs_rsa/quickjs_select_rsa_fr"
VICTIM_JS="${ROOT}/experiments/quickjs_rsa/openpgp_patch_rsa/js/openpgp_select_rsa.js"
EXTRACT="${ROOT}/experiments/quickjs_rsa/openpgp_patch_rsa/evaluation/extract_select_rsa.py"

for f in "$VICTIM_BIN" "$ATTACKER_BIN"; do
	if [ ! -x "$f" ]; then
		echo "Missing binary: $f (build quickjs_rt and quickjs_select_rsa_fr first)" >&2
		exit 1
	fi
done

cd "$BUILD"

echo "== Starting victim =="
taskset -c "$CPUS" "$VICTIM_BIN" "$VICTIM_JS" &
VICTIM_PID=$!

cleanup() {
	if kill -0 "$VICTIM_PID" 2>/dev/null; then
		kill "$VICTIM_PID" 2>/dev/null || true
		wait "$VICTIM_PID" 2>/dev/null || true
	fi
}
trap cleanup EXIT

sleep 1

echo "== Starting select+modExp FR attacker (VICTIM_RUNS=${VICTIM_RUNS}, WAITING_TIME=${WAITING_TIME}, ROUND_CYCLES=${ROUND_CYCLES}, KEY_ID=${KEY_ID}) =="
VICTIM_RUNS="$VICTIM_RUNS" WAITING_TIME="$WAITING_TIME" ROUND_CYCLES="$ROUND_CYCLES" KEY_ID="$KEY_ID" \
	taskset -c "$CPUS" "$ATTACKER_BIN" "$VICTIM_RUNS"
ATTACKER_STATUS=$?

wait "$VICTIM_PID" 2>/dev/null || true
trap - EXIT

if [ "$ATTACKER_STATUS" -ne 0 ]; then
	echo "Attacker exited with status $ATTACKER_STATUS" >&2
	exit "$ATTACKER_STATUS"
fi

TRACE_DIR="${BUILD}/output/quickjs_select_rsa_fr/quickjs_select_rsa_fr_key$(printf '%05d' "$KEY_ID")_r$(printf '%05d' "$VICTIM_RUNS")"
echo "== Trace directory: ${TRACE_DIR} =="
ls -la "$TRACE_DIR" || { echo "No trace directory produced" >&2; exit 1; }

echo "== Decoding ${TRACE_DIR} =="
cd "${ROOT}/experiments/quickjs_rsa/openpgp_patch_rsa/evaluation"
PYTHON="${ROOT}/.venv/bin/python3"
[ -x "$PYTHON" ] || PYTHON=python3
"$PYTHON" "$EXTRACT" -d "$TRACE_DIR" --id "$KEY_ID"
