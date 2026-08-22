#!/usr/bin/env bash
# Capture one P+P dataset: one capture per pool key, re-launched until healthy.
#
#   usage: run_pp_batch.sh [first] [last]
#          KEYS="0 5 9" RUNS=100 TAG=paper run_pp_batch.sh
#
# Env: RUNS (default 100), TAG (default paper), ATTEMPTS (default 8), plus
# anything run_ecdh_ct.sh takes. Roughly a third of launches build an unusable
# eviction set and decode at chance, so capture_health.py judges each one and a
# rejected launch is repeated. The lock is not optional: two captures at once
# ruin both.
set -u

exec 9>"${TMPDIR:-/tmp}/v8_ctjs_capture.lock"
flock -n 9 || { echo "another capture is running" >&2; exit 1; }

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RUNS=${RUNS:-100}
TAG=${TAG:-paper}
ATTEMPTS=${ATTEMPTS:-8}
BUILD=${BUILD:-$HERE/../../../build/experiments/v8_constant_time_js}

keys=${KEYS:-$(seq "${1:-0}" "${2:-99}")}
log=$BUILD/output/${TAG}_batch.log
mkdir -p "$BUILD/output"
: > "$log"

for k in $keys; do
  dst=$BUILD/output/pp_${TAG}_k${k}_r$(printf '%05d' "$RUNS")
  ok=0
  for a in $(seq 1 "$ATTEMPTS"); do
    out=$(RUNS=$RUNS TAG=$TAG "$HERE/run_ecdh_ct.sh" -pp "$k" 2>&1)
    if ! grep -q '(.* traces' <<<"$out"; then
      echo "key $k attempt $a: NO TRACES" | tee -a "$log"
      continue
    fi
    viol=$(sed -n 's|.*ERROR\] .*: \([0-9]*\)/[0-9]* captured run(s) exceeded.*|\1|p' \
             <<<"$out" | tail -1)
    health=$(python3 "$HERE/capture_health.py" "$dst")
    verdict=$?
    echo "key $k attempt $a: clock-ceiling viol ${viol:-0}/$RUNS | $health" | tee -a "$log"
    [ "$verdict" = 0 ] && { ok=1; break; }
  done
  [ "$ok" = 1 ] || echo "key $k: UNHEALTHY after $ATTEMPTS attempts" | tee -a "$log"
done
echo "batch done -> $BUILD/output (tag $TAG)" | tee -a "$log"
