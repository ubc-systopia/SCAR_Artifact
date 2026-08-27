#!/usr/bin/env bash
# Escalate VICTIM_RUNS (repeated-trace count) for quickjs_rsa_fr until the
# confidence-band-voted known-bit accuracy clears a target, or we give up.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD="${ROOT}/build"

CPUS="${CPUS:-1,3,5,7,9,11,13,15}"
WAITING_TIME="${WAITING_TIME:-10000}"
TARGET_ACC="${TARGET_ACC:-0.99}"
# Escalating trace-batch sizes; each attempt is an independent batch (not
# accumulated on top of the previous one).
read -ra BATCHES <<<"${BATCHES:-10 20 40 80 160}"

VICTIM_BIN="${BUILD}/src/runtime/quickjs/quickjs_rt"
ATTACKER_BIN="${BUILD}/experiments/quickjs_rsa/quickjs_rsa_fr"
VICTIM_JS="${ROOT}/experiments/quickjs_rsa/js/openpgp_rsa.js"
EXTRACT="${ROOT}/experiments/quickjs_rsa/evaluation/extract_openpgp_rsa.py"
PYTHON="${ROOT}/.venv/bin/python3"
[ -x "$PYTHON" ] || PYTHON=python3

for f in "$VICTIM_BIN" "$ATTACKER_BIN"; do
	if [ ! -x "$f" ]; then
		echo "Missing binary: $f" >&2
		exit 1
	fi
done

cd "$BUILD"

for n in "${BATCHES[@]}"; do
	echo "== Batch: VICTIM_RUNS=${n}, WAITING_TIME=${WAITING_TIME} =="

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

	VICTIM_RUNS="$n" WAITING_TIME="$WAITING_TIME" \
		taskset -c "$CPUS" "$ATTACKER_BIN" "$n"
	ATTACKER_STATUS=$?

	wait "$VICTIM_PID" 2>/dev/null || true
	trap - EXIT

	if [ "$ATTACKER_STATUS" -ne 0 ]; then
		echo "  attacker exited with status $ATTACKER_STATUS, skipping batch" >&2
		continue
	fi

	TRACE_DIR="${BUILD}/output/quickjs_openpgp_rsa_fr_r$(printf '%05d' "$n")"
	if [ ! -d "$TRACE_DIR" ]; then
		echo "  no trace directory produced ($TRACE_DIR), skipping batch" >&2
		continue
	fi
	ntraces=$(ls "$TRACE_DIR"/*.out 2>/dev/null | wc -l)
	echo "  ${ntraces} trace files in ${TRACE_DIR}"

	cd "${ROOT}/experiments/quickjs_rsa/evaluation"
	rm -f "$TRACE_DIR"/*.inf # force fresh inference, not stale cache
	out="$("$PYTHON" "$EXTRACT" -d "$TRACE_DIR" --at FR \
		--sample-interval "$WAITING_TIME" --id 0 2>&1)" || {
		echo "  extraction failed" >&2
		echo "$out" | tail -20 >&2
		cd "$BUILD"
		continue
	}
	cd "$BUILD"

	line="$(echo "$out" | grep -E '^Key 000 \|' || true)"
	echo "  $line"

	acc="$(echo "$line" | sed -n 's/.*acc \([0-9.]*\).*/\1/p')"
	unknown="$(echo "$line" | sed -n 's/.*unknown *\([0-9]*\).*/\1/p')"

	if [ -z "$acc" ]; then
		echo "  could not parse accuracy, skipping batch" >&2
		continue
	fi

	reached="$("$PYTHON" -c "print(1 if float('$acc') >= float('$TARGET_ACC') else 0)")"
	if [ "$reached" = "1" ]; then
		echo
		echo "== Reached target: acc=${acc} >= ${TARGET_ACC} at VICTIM_RUNS=${n} (unknown=${unknown}) =="
		exit 0
	fi
done

echo
echo "== Did not reach ${TARGET_ACC} within batches: ${BATCHES[*]} =="
exit 1
