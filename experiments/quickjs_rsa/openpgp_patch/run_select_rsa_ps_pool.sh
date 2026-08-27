#!/usr/bin/env bash
# Key-pool driver for the Prime+Scope attack on the SELECT-patched modExp.
#
# run_select_rsa_ps.sh runs one key. This runs a pool of them: one victim +
# attacker pair per key, VICTIM_RUNS signatures each, so the evaluation matches
# the shape of the section 5.1 key-pool result (100 keys x 128 runs).
#
# The run is long (see pool_run.log for measured per-key times), so it is
# resumable and fault tolerant: a key whose output directory already holds
# VICTIM_RUNS traces is skipped, and a key that fails or times out is logged and
# left behind rather than aborting the pool. Re-running the script picks up
# whatever is missing.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BUILD="${ROOT}/build"
CPUS="${CPUS:-1,3,5,7,9,11,13,15}"
NUM_KEYS="${NUM_KEYS:-100}"
FIRST_KEY="${FIRST_KEY:-0}"
VICTIM_RUNS="${VICTIM_RUNS:-128}"
ROUND_CYCLES="${ROUND_CYCLES:-4000000000}"
# Per-key wall-clock ceiling. One signature is ~1s of victim work plus the
# attacker's cycle budget; 30s per run leaves generous margin, so a key that
# blows through this is wedged, not slow.
KEY_TIMEOUT="${KEY_TIMEOUT:-$((30 * VICTIM_RUNS))}"
GZIP_TRACES="${GZIP_TRACES:-1}"

VICTIM_BIN="${BUILD}/src/runtime/quickjs/quickjs_rt"
ATTACKER_BIN="${BUILD}/experiments/quickjs_rsa/quickjs_select_rsa_ps"
VICTIM_JS="${ROOT}/experiments/quickjs_rsa/openpgp_patch/js/openpgp_select_rsa.js"
# Not a knob: quickjs_select_rsa_ps.c builds this path itself from its
# test_name, so the driver has to look in the same place.
OUT_ROOT="${BUILD}/output/quickjs_select_rsa_ps"
LOG="${LOG:-${OUT_ROOT}/pool_run.log}"

for f in "$VICTIM_BIN" "$ATTACKER_BIN"; do
	[ -x "$f" ] || { echo "Missing binary: $f" >&2; exit 1; }
done

mkdir -p "$OUT_ROOT"
cd "$BUILD"

# Count trace files (raw or gzipped) already present for a key directory.
count_traces() {
	local dir="$1"
	[ -d "$dir" ] || { echo 0; return; }
	find "$dir" -maxdepth 1 -name 'r*.out' -o -maxdepth 1 -name 'r*.out.gz' \
		2>/dev/null | wc -l
}

VICTIM_PID=""
cleanup_victim() {
	[ -n "$VICTIM_PID" ] || return 0
	kill "$VICTIM_PID" 2>/dev/null
	wait "$VICTIM_PID" 2>/dev/null
	VICTIM_PID=""
}
trap 'cleanup_victim; exit 130' INT TERM

printf '# pool run started %s (keys %d..%d, runs %d)\n' \
	"$(date -Is)" "$FIRST_KEY" "$((FIRST_KEY + NUM_KEYS - 1))" "$VICTIM_RUNS" \
	>> "$LOG"

LAST_KEY=$((FIRST_KEY + NUM_KEYS - 1))
for KEY_ID in $(seq "$FIRST_KEY" "$LAST_KEY"); do
	TRACE_DIR="${OUT_ROOT}/quickjs_select_rsa_ps_key$(printf '%05d' "$KEY_ID")_r$(printf '%05d' "$VICTIM_RUNS")"

	have=$(count_traces "$TRACE_DIR")
	if [ "$have" -ge "$VICTIM_RUNS" ]; then
		echo "== key ${KEY_ID}: already have ${have} traces, skipping =="
		continue
	fi

	echo "== key ${KEY_ID}: collecting ${VICTIM_RUNS} traces =="
	start=$(date +%s)

	taskset -c "$CPUS" "$VICTIM_BIN" "$VICTIM_JS" \
		> "${OUT_ROOT}/victim_key$(printf '%05d' "$KEY_ID").log" 2>&1 &
	VICTIM_PID=$!
	sleep 1

	VICTIM_RUNS="$VICTIM_RUNS" ROUND_CYCLES="$ROUND_CYCLES" KEY_ID="$KEY_ID" \
		timeout -k 30 "$KEY_TIMEOUT" \
		taskset -c "$CPUS" "$ATTACKER_BIN" "$VICTIM_RUNS" \
		> "${OUT_ROOT}/attacker_key$(printf '%05d' "$KEY_ID").log" 2>&1
	status=$?

	# The attacker signals SYNC_CTX_EXIT on a clean finish; on a failure (e.g.
	# an eviction-set build failure, which happens occasionally) the victim
	# can be left parked on its barrier with no one to release it. An
	# unbounded `wait` here wedges the whole pool run on a single bad key
	# (observed: key 88 sat for over an hour) -- so wait only briefly for a
	# clean exit, then kill unconditionally.
	for _ in $(seq 1 10); do
		kill -0 "$VICTIM_PID" 2>/dev/null || break
		sleep 1
	done
	cleanup_victim

	got=$(count_traces "$TRACE_DIR")
	elapsed=$(( $(date +%s) - start ))

	if [ "$GZIP_TRACES" = "1" ] && [ "$got" -gt 0 ]; then
		find "$TRACE_DIR" -maxdepth 1 -name 'r*.out' -print0 2>/dev/null \
			| xargs -0 -r gzip -f
	fi

	printf 'key %5d status %3d traces %5d/%d %6ds\n' \
		"$KEY_ID" "$status" "$got" "$VICTIM_RUNS" "$elapsed" | tee -a "$LOG"

	if [ "$status" -ne 0 ] || [ "$got" -lt "$VICTIM_RUNS" ]; then
		echo "   (key ${KEY_ID} incomplete; continuing with the pool)" >&2
	fi
done

printf '# pool run finished %s\n' "$(date -Is)" >> "$LOG"
echo "== done; per-key status in ${LOG} =="
