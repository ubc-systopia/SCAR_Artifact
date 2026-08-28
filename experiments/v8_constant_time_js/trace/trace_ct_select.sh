#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SRC="${ROOT}/experiments/v8_constant_time_js/trace"
D8="${D8:-${ROOT}/third_party/v8/out.gn/x64.release/d8}"
OUT="${OUT:-${ROOT}/build/output/ct_select}"

[ -x "$D8" ] || {
	echo "no d8 at $D8; build V8 first, or set D8=/path/to/d8" >&2
	exit 1
}
gdb -q -batch -ex run -ex quit --args /bin/true >/dev/null 2>&1 || {
	echo "gdb cannot ptrace here; needs kernel.yama.ptrace_scope <= 1" >&2
	exit 1
}

mkdir -p "$OUT"
cmds=$(mktemp)
trap 'rm -f "$cmds"' EXIT

cat > "$cmds" <<EOF
source ${SRC}/gdb_step_builtins.py
set pagination off
set confirm off
break v8::internal::Runtime_SystemBreak
run
sib ${OUT}/true.log
continue
continue
sib ${OUT}/false.log
quit
EOF

gdb -q -batch -x "$cmds" --args "$D8" \
	--allow-natives-syntax --single-threaded --no-concurrent-recompilation \
	--jitless "${SRC}/ct_select.js" 2>&1 | grep -E '^\[sib\] (stopped|program|error)'

for f in "$OUT/true.log" "$OUT/false.log"; do
	[ -s "$f" ] || { echo "no trace written to $f" >&2; exit 1; }
done

echo
printf '%-28s %8s %8s\n' handler true false
for h in ToBooleanHandler NegateHandler BitwiseAndSmiWideHandler; do
	printf '%-28s %8s %8s\n' "$h" \
		"$(grep -c "$h" "$OUT/true.log")" "$(grep -c "$h" "$OUT/false.log")"
done
echo
echo "traces in $OUT"
