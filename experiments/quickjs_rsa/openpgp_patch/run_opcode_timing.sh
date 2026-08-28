#!/usr/bin/env bash
set -euo pipefail

SAMPLES="${1:-100}"
BITS="${2:-4095}"
RUNS="${RUNS:-5}"
PIN_CPU="${PIN_CPU:-10}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE_DIR="$(cd "$SCRIPT_DIR/../../../third_party/quickjs" && pwd)"
BUILD_DIR="$(mktemp -d /tmp/selectBigInt-qjs.XXXXXX)"
OUTPUT_PREFIX="${OUTPUT_PREFIX:-$SCRIPT_DIR/opcode_timing}"

cleanup() {
  rm -rf "$BUILD_DIR"
}
trap cleanup EXIT

if ! [[ "$RUNS" =~ ^[1-9][0-9]*$ ]]; then
  echo "RUNS must be a positive integer" >&2
  exit 2
fi

TASKSET=()
if command -v taskset >/dev/null 2>&1; then
  if ! taskset -c "$PIN_CPU" true 2>/dev/null; then
    echo "CPU $PIN_CPU is unavailable; set PIN_CPU to an allowed CPU" >&2
    exit 2
  fi
  TASKSET=(taskset -c "$PIN_CPU")
fi

cp -a "$SOURCE_DIR/." "$BUILD_DIR/"
python3 "$SCRIPT_DIR/instrument_quickjs_opcode_timing.py" "$BUILD_DIR/quickjs.c"
sed -i '/^CFLAGS_OPT=/a CFLAGS_OPT+=-DOPCODE_TIMING' "$BUILD_DIR/Makefile"
make -C "$BUILD_DIR" clean >/dev/null
make -C "$BUILD_DIR" qjs >/dev/null

outputs=()
for ((run = 1; run <= RUNS; run++)); do
  printf -v run_number '%02d' "$run"
  output="${OUTPUT_PREFIX}_run${run_number}.csv"
  outputs+=("$output")
  QJS_OPCODE_TIMING_OUT="$output" \
    "${TASKSET[@]}" "$BUILD_DIR/qjs" \
    "$SCRIPT_DIR/selectBigInt_opcode_harness.mjs" "$SAMPLES" "$BITS"
done

python3 "$SCRIPT_DIR/analyze_opcode_timing.py" "${outputs[@]}"
