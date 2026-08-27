#!/usr/bin/env bash
# End-to-end Prime+Scope run against the SELECT-patched modExp: victim +
# quickjs_select_rsa_ps attacker. Companion to run_select_rsa_eval.sh (FR).
set -uo pipefail

# repo root: attack/ -> artifact_select_ps/ -> openpgp_patch/ -> quickjs_rsa/
#            -> experiments/ -> SCAR_Artifact
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../../.." && pwd)"
BUILD="${ROOT}/build"
# CPUS="${CPUS:-1,3,5,7,9,11,13,15}"
CPUS="${CPUS:-12,14}"
VICTIM_RUNS="${VICTIM_RUNS:-5}"
# which libbf cache line(s) to probe: or (default) | and | both
PROBE_LINE="${PROBE_LINE:-or}"
ROUND_CYCLES="${ROUND_CYCLES:-4000000000}"
KEY_ID="${KEY_ID:-0}"

VICTIM_BIN="${BUILD}/src/runtime/quickjs/quickjs_rt"
ATTACKER_BIN="${BUILD}/experiments/quickjs_rsa/quickjs_select_rsa_ps"
VICTIM_JS="${ROOT}/experiments/quickjs_rsa/openpgp_patch/js/openpgp_select_rsa.js"

for f in "$VICTIM_BIN" "$ATTACKER_BIN"; do
	[ -x "$f" ] || { echo "Missing binary: $f" >&2; exit 1; }
done

cd "$BUILD"

echo "== Starting victim =="
taskset -c "$CPUS" "$VICTIM_BIN" "$VICTIM_JS" &
VICTIM_PID=$!

cleanup() {
	kill "$VICTIM_PID" 2>/dev/null || true
	wait "$VICTIM_PID" 2>/dev/null || true
}
trap cleanup EXIT

sleep 1

echo "== Starting Prime+Scope attacker (VICTIM_RUNS=${VICTIM_RUNS}, KEY_ID=${KEY_ID}, PROBE_LINE=${PROBE_LINE}) =="
VICTIM_RUNS="$VICTIM_RUNS" ROUND_CYCLES="$ROUND_CYCLES" KEY_ID="$KEY_ID" \
	PROBE_LINE="$PROBE_LINE" \
	taskset -c "$CPUS" "$ATTACKER_BIN" "$VICTIM_RUNS"
ATTACKER_STATUS=$?

wait "$VICTIM_PID" 2>/dev/null || true
trap - EXIT

TRACE_DIR="${BUILD}/output/quickjs_select_rsa_ps/quickjs_select_rsa_ps_key$(printf '%05d' "$KEY_ID")_r$(printf '%05d' "$VICTIM_RUNS")"
echo "== Trace directory: ${TRACE_DIR} =="
ls -la "$TRACE_DIR" 2>/dev/null || echo "No trace directory produced" >&2

exit "$ATTACKER_STATUS"
