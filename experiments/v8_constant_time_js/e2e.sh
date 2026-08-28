#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${BUILD:-${ROOT}/build}"
SRC="${ROOT}/experiments/v8_constant_time_js"
BIN="${BUILD}/experiments/v8_constant_time_js/v8_ctjs_ecdh"
POOL="${ROOT}/experiments/v8_ecdh/ec_key_pool"
OUT="${BUILD}/experiments/v8_constant_time_js/output"
EXTRACT="${SRC}/evaluation/extract_v8_ctjs_ecdh.py"
CPUS="${CPUS:-5,7,9,11,13,15}"
KEYS="${KEYS:-100}"
RUNS="${RUNS:-100}"
WARMUP="${WARMUP:-5}"
ATTEMPTS="${ATTEMPTS:-8}"
TAG="${TAG:-paper}"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python3}"
[ -x "$PYTHON" ] || PYTHON=python3

[ -x "$BIN" ] || {
	echo "no binary at $BIN; build it with: cmake --build build --target v8_ctjs_ecdh" >&2
	exit 1
}
"$PYTHON" -c 'import numpy, pandas, bokeh, rich' 2>/dev/null || {
	echo "the decoder needs the project venv: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
	exit 1
}

exec 9>"${TMPDIR:-/tmp}/v8_ctjs_capture.lock"
flock -n 9 || { echo "another capture is running" >&2; exit 1; }

mkdir -p "$OUT"
log="${OUT}/${TAG}_batch.log"
: > "$log"
raw="${OUT}/v8_ctjs_ecdh_r$(printf '%05d' "$RUNS")"

for k in $(seq 0 $((KEYS - 1))); do
	dst="${OUT}/pp_${TAG}_k${k}_r$(printf '%05d' "$RUNS")"
	ok=0
	for attempt in $(seq 1 "$ATTEMPTS"); do
		rm -rf "$raw" "$dst"
		(
			cd "$(dirname "$OUT")" || exit 1
			taskset -c "$CPUS" "$BIN" -pp -runs="$RUNS" -warmup="$WARMUP" \
				"$SRC/js/ecdh_ctjs_eval.js" "$SRC/js/ecdh_ctjs_repeat.js" \
				"$POOL/ec_key_${k}.json"
		) >>"$log" 2>&1
		[ -d "$raw" ] || continue
		mv "$raw" "$dst"
		health=$("$PYTHON" "$EXTRACT" --health "$dst")
		verdict=$?
		echo "key $k attempt $attempt: $health" | tee -a "$log"
		[ "$verdict" = 0 ] && { ok=1; break; }
	done
	[ "$ok" = 1 ] || echo "key $k: unhealthy after $ATTEMPTS attempts" | tee -a "$log"
done

echo "traces in $OUT (capture log in $log)"
echo

exec "$PYTHON" "$EXTRACT" --all_keys "$OUT" --tag "$TAG" --runs "$RUNS" --keys "$KEYS"
