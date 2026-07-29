#!/usr/bin/env bash
set -euo pipefail

BITS="${1:-4095}"
ITERATIONS="${2:-1}"
PIN_CPU="${PIN_CPU:-5}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE_DIR="$(cd "$SCRIPT_DIR/../../../third_party/quickjs" && pwd)"
RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/pt_results}"
BUILD_DIR="$RESULTS_DIR/quickjs-build"
QJS_BIN="$BUILD_DIR/qjs"
PT_FILTER="${PT_FILTER:-}"
PERF_BIN="${PERF_BIN:-}"

if [ -z "$PERF_BIN" ]; then
	PERF_BIN="$(command -v perf 2>/dev/null || true)"
fi
if [ -z "$PERF_BIN" ] || [ ! -x "$PERF_BIN" ]; then
	echo "perf is required; install the Linux perf package matching your kernel" >&2
	exit 2
fi
if [ ! -d /sys/bus/event_source/devices/intel_pt ]; then
	echo "the kernel does not expose /sys/bus/event_source/devices/intel_pt" >&2
	echo "perf binary: $PERF_BIN" >&2
	exit 2
fi
if command -v taskset >/dev/null 2>&1 && ! taskset -c "$PIN_CPU" true 2>/dev/null; then
	echo "CPU $PIN_CPU is unavailable; set PIN_CPU to an allowed CPU" >&2
	exit 2
fi

mkdir -p "$RESULTS_DIR"

if [ ! -x "$QJS_BIN" ]; then
	mkdir -p "$BUILD_DIR"
	cp -a "$SOURCE_DIR/." "$BUILD_DIR/"
	# This modifies only the private build copy. Debug information and frame
	# pointers are needed for source/offset attribution after decoding.
	sed -i '/^CFLAGS_OPT=/a CFLAGS_OPT+=-g -fno-omit-frame-pointer' "$BUILD_DIR/Makefile"
	make -C "$BUILD_DIR" clean >/dev/null
	make -C "$BUILD_DIR" qjs >/dev/null
fi

task=("$QJS_BIN" "$SCRIPT_DIR/selectBigInt_pt_harness.mjs")
if command -v taskset >/dev/null 2>&1; then
	task=(taskset -c "$PIN_CPU" "${task[@]}")
fi

filter_args=()
if [ -n "$PT_FILTER" ]; then
	filter_args=(--filter "$PT_FILTER")
fi

for condition in false true; do
	data="$RESULTS_DIR/${condition}.data"
	trace="$RESULTS_DIR/${condition}.trace"
	"$PERF_BIN" record -q -e intel_pt//u "${filter_args[@]}" -o "$data" -- \
		"${task[@]}" "$condition" "$BITS" "$ITERATIONS"
	"$PERF_BIN" script -i "$data" --itrace=i1ibx \
		-F ip,sym,symoff,dso,insn > "$trace"
done

python3 "$SCRIPT_DIR/compare_intel_pt.py" \
	"$RESULTS_DIR/false.trace" "$RESULTS_DIR/true.trace" \
	> "$RESULTS_DIR/path_diff.txt"

echo "Intel PT outputs: $RESULTS_DIR"
echo "Focused path diff: $RESULTS_DIR/path_diff.txt"
