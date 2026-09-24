#!/bin/bash
# Quality-gated capture for the QuickJS jpeg-js IDCT attack (run on leapx02).
#
# Eviction-set quality varies per launch AND per session, and a bad capture
# looks exactly like a decoder regression, so this keeps only launches that pass
# extract_jpeg_js.py --health. Per-capture SNR is low, so it collects several
# and extract_jpeg_js.py averages them (pass every kept trace with -f).
#
# Usage:
#   experiments/quickjs_jpeg/evaluation/capture.sh <victim_js> <tag> <n_good> \
#       [max_tries] [slot0] [slot1] [row_mark_line]
# Example:
#   experiments/quickjs_jpeg/evaluation/capture.sh \
#       experiments/quickjs_jpeg/js/jpeg_decode_emacs.js emacs 1
#
# Kept traces land in build/output/<tag>_1 .. <tag>_<n_good>.
set -u
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
if [ -n "${PY:-}" ]; then
	:
elif [ -n "${VIRTUAL_ENV:-}" ] && [ -x "$VIRTUAL_ENV/bin/python3" ]; then
	PY="$VIRTUAL_ENV/bin/python3"
elif [ -x "$ROOT/.venv/bin/python3" ]; then
	PY="$ROOT/.venv/bin/python3"
else
	PY="python3"
fi
EXTRACT="$ROOT/experiments/quickjs_jpeg/evaluation/extract_jpeg_js.py"
CORES="${CORES:-1,3,5,7,9,11,13,15}"
VJS="${1:?victim js path, relative to the repo root}"
TAG="${2:?output tag}"
NGOOD="${3:-6}"
TRIES="${4:-60}"
S0="${5:-mul+0}"
S1="${6:-sar+0}"
S3="${7:-0}"
ROWS="${ROWS:-strict}"

cd "$ROOT/build" || exit 2
good=0
for try in $(seq 1 "$TRIES"); do
	rm -rf output/quickjs_jpeg_js_r00001
	# A leftover attacker keeps Prime+Probe running and poisons every later
	# capture, so kill both sides by exact name (-f would also match the victim
	# path, which contains "quickjs_jpeg") and let them exit.
	pkill -9 -x quickjs_jpeg 2>/dev/null
	pkill -9 -x quickjs_rt 2>/dev/null
	sleep 2
	setsid bash -c "cd '$ROOT/build' && taskset -c $CORES \
		./src/runtime/quickjs/quickjs_rt '../$VJS' > /tmp/qj_victim_$TAG.log 2>&1" &
	sleep 3
	QJ_SLOT0="$S0" QJ_SLOT1="$S1" QJ_SLOT3="$S3" \
		QJ_MAX_CYCLES="${QJ_MAX_CYCLES:-8e8}" timeout 180 taskset -c "$CORES" \
		./experiments/quickjs_jpeg/quickjs_jpeg > "/tmp/qj_attacker_$TAG.log" 2>&1
	sleep 1
	pkill -9 -x quickjs_jpeg 2>/dev/null
	pkill -9 -x quickjs_rt 2>/dev/null
	if [ ! -f output/quickjs_jpeg_js_r00001/r0.out ]; then
		echo "try $try: no trace written"
		continue
	fi
	cand="output/${TAG}_cand"
	rm -rf "$cand"
	mv output/quickjs_jpeg_js_r00001 "$cand"
	report=$("$PY" "$EXTRACT" --rows "$ROWS" --health "$cand/r0.out" 2>/dev/null)
	if [ "${report:0:4}" = "PASS" ]; then
		good=$((good + 1))
		rm -rf "output/${TAG}_$good"
		mv "$cand" "output/${TAG}_$good"
		echo "try $try -> kept ${TAG}_$good ($good/$NGOOD): ${report#PASS }"
		[ "$good" -ge "$NGOOD" ] && break
	else
		echo "try $try: ${report:-health check failed}"
		rm -rf "$cand"
	fi
done
echo "kept $good good traces in $try tries -> build/output/${TAG}_1 .. ${TAG}_$good"
[ "$good" -gt 0 ] || exit 1
