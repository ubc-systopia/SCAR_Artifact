#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Times every selector in js/impl/ on QuickJS and V8, writing raw per-call
timing CSVs to results/<engine>_<impl>.csv.

Usage: ./run_eval.sh [-n samples] [-b bits] [-s seed] [-c cpu]

  -n  timed measurements, cond drawn per measurement (default 200000)
  -b  operand bit-length (default 4095)
  -s  PRNG seed, so operands match across engines (default 1)
  -c  CPU to pin to with taskset (default 11)

Override the engine binaries with QJS_BIN and D8_BIN. d8 is optional:
without it only the QuickJS pass runs, which is what the paper prints.
EOF
}

SAMPLES="${SAMPLES:-200000}"
BITS="${BITS:-4095}"
SEED="${SEED:-1}"
PIN_CPU="${PIN_CPU:-11}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PATCH_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT="$(cd "$PATCH_DIR/../../.." && pwd)"

QJS_BIN="${QJS_BIN:-$ROOT/third_party/quickjs/qjs}"
D8_BIN="${D8_BIN:-$ROOT/third_party/v8/out.gn/x64.release/d8}"

while getopts "n:b:s:c:h" opt; do
	case "$opt" in
		n) SAMPLES="$OPTARG" ;;
		b) BITS="$OPTARG" ;;
		s) SEED="$OPTARG" ;;
		c) PIN_CPU="$OPTARG" ;;
		h) usage; exit 0 ;;
		*) echo "bad option" >&2; exit 1 ;;
	esac
done

BENCH="$PATCH_DIR/js/bench.mjs"
RESULTS="$PATCH_DIR/results"

TASKSET=""
if command -v taskset >/dev/null 2>&1; then
	TASKSET="taskset -c $PIN_CPU"
fi

if [ ! -x "$QJS_BIN" ]; then
	echo "[!] qjs not found/executable: $QJS_BIN" >&2
	echo "    the paper's figure is QuickJS-only, so this one is required" >&2
	echo "    (override with QJS_BIN)" >&2
	exit 1
fi

HAVE_D8=1
if [ ! -x "$D8_BIN" ]; then
	HAVE_D8=0
	echo "[!] d8 not found/executable: $D8_BIN" >&2
	echo "    skipping the V8 pass; it only feeds plot_violin.py --engines quickjs,v8," >&2
	echo "    which the paper does not print (override with D8_BIN)" >&2
fi

mkdir -p "$RESULTS"

echo "[*] samples     : $SAMPLES   bits=$BITS  seed=$SEED"
echo "[*] qjs         : $QJS_BIN"
echo "[*] d8          : $D8_BIN"
echo "[*] pin cpu     : ${TASKSET:-(taskset unavailable)}"
echo "[*] sel func    :" $(for p in "$PATCH_DIR"/js/impl/*.mjs; do basename "$p" .mjs; done)
echo "[*] results dir : $RESULTS"

run_one() {
	local engine="$1" impl_module="$2" impl="$3"
	local out="$RESULTS/${engine}_${impl}.csv"
	echo "[*] running $engine / $impl -> $(basename "$out")"
	if [ "$engine" = quickjs ]; then
		$TASKSET "$QJS_BIN" "$BENCH" "$impl_module" "$SAMPLES" "$BITS" "$SEED" > "$out"
	else
	$TASKSET "$D8_BIN" --module --single-threaded "$BENCH" -- "$impl_module" "$SAMPLES" "$BITS" "$SEED" > "$out"
	fi
	local n
	n=$(grep -vc '^#' "$out" || true)
	echo "    -> $((n - 1)) measurements"
}

for p in "$PATCH_DIR"/js/impl/*.mjs; do
	impl="$(basename "$p" .mjs)"
	impl_module="./impl/${impl}.mjs"
	run_one quickjs "$impl_module" "$impl"
	if [ "$HAVE_D8" -eq 1 ]; then
		run_one v8 "$impl_module" "$impl"
	fi
done

echo "[*] done. CSVs in $RESULTS/"
ls -la "$RESULTS"/*.csv
