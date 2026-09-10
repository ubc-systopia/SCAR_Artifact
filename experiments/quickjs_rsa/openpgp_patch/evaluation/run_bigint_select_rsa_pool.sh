#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
BUILD="${ROOT}/build"
CPUS="${CPUS:-1,3,5,7,9,11,13,15}"
NUM_KEYS="${NUM_KEYS:-100}"
FIRST_KEY="${FIRST_KEY:-0}"
VICTIM_RUNS="${VICTIM_RUNS:-128}"
ROUND_CYCLES="${ROUND_CYCLES:-4000000000}"
KEY_TIMEOUT="${KEY_TIMEOUT:-$((30 * VICTIM_RUNS))}"
GZIP_TRACES="${GZIP_TRACES:-1}"

VICTIM_BIN="${BUILD}/src/runtime/quickjs/quickjs_rt"
ATTACKER_BIN="${BUILD}/experiments/quickjs_rsa/quickjs_bigint_select_rsa"
VICTIM_JS="${ROOT}/experiments/quickjs_rsa/openpgp_patch/js/openpgp_bigint_select_rsa.js"
OUT_ROOT="${BUILD}/output/quickjs_bigint_select_rsa"
LOG="${LOG:-${OUT_ROOT}/pool_run.log}"

for f in "$VICTIM_BIN" "$ATTACKER_BIN"; do
	[ -x "$f" ] || { echo "Missing binary: $f" >&2; exit 1; }
done

mkdir -p "$OUT_ROOT"
cd "$BUILD"

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
	TRACE_DIR="${OUT_ROOT}/quickjs_bigint_select_rsa_key$(printf '%05d' "$KEY_ID")_r$(printf '%05d' "$VICTIM_RUNS")"

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
