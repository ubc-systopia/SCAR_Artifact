#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
VICTIM_CPUS="${DICT_VICTIM_CPUS:-1,3}"
ATTACK_CPUS="${DICT_ATTACK_CPUS:-5,7,9,11,13,15}"
ITERS=32
MAX_TRIES="${DICT_MAX_TRIES:-6}"
RUN_TIMEOUT="${DICT_TIMEOUT:-1800}"
TAG="${DICT_TAG:-dict}"
LOGDIR="${DICT_LOGDIR:-$ROOT/build/experiments/cpython_dictionary/logs}"

mkdir -p "$LOGDIR"

LOCKFILE="${DICT_LOCK:-/tmp/scar_cpython_dict.lock}"
exec 9>"$LOCKFILE"
if ! flock -n 9; then
    echo "ERROR: another cpython_dictionary run holds $LOCKFILE." >&2
    echo "Concurrent runs share one SysV barrier and corrupt each other." >&2
    exit 9
fi

drop_sync_segments() {
    local dev ino key
    dev=$(stat -c %d "$ROOT" 2>/dev/null) || { ipcrm -a >/dev/null 2>&1; return 0; }
    ino=$(stat -c %i "$ROOT" 2>/dev/null) || { ipcrm -a >/dev/null 2>&1; return 0; }
    for proj in 20000 20001 20002 20003; do
        key=$(printf '0x%08x' $(( ((proj & 255) << 24) | ((dev & 255) << 16) | (ino & 65535) )))
        ipcrm -M "$key" >/dev/null 2>&1
    done
    return 0
}

cleanup() {
    pkill -f '^\./cpython_dictionary' >/dev/null 2>&1
    pkill -f '^\./cpython_rt' >/dev/null 2>&1
    sleep 1
    local left
    left=$(ps -u "$USER" -o comm= | grep -cE '^cpython_dict|^cpython_rt')
    if [ "$left" -ne 0 ]; then
        ps -u "$USER" -o pid=,comm= \
            | awk '$2 ~ /^cpython_dict/ || $2 ~ /^cpython_rt/ {print $1}' \
            | xargs -r kill -9
        sleep 1
    fi
    drop_sync_segments
    return 0
}

trap cleanup EXIT

for try in $(seq 1 "$MAX_TRIES"); do
    cleanup
    sleep 1

    vlog="$LOGDIR/${TAG}_try${try}_victim.log"
    alog="$LOGDIR/${TAG}_try${try}_attacker.log"

    echo "=== try $try/$MAX_TRIES  tag=$TAG ==="

    ( cd "$ROOT/build/src/runtime/cpython" && \
      taskset -c "$VICTIM_CPUS" ./cpython_rt \
        "$ROOT/experiments/cpython_dictionary/python/cpython_dictionary.py" \
        "$ITERS" >"$vlog" 2>&1 ) &
    vpid=$!

    sleep 2

    ( cd "$ROOT/build/experiments/cpython_dictionary" && \
      timeout "$RUN_TIMEOUT" taskset -c "$ATTACK_CPUS" \
        ./cpython_dictionary >"$alog" 2>&1 )
    rc=$?

    kill "$vpid" 2>/dev/null
    wait "$vpid" 2>/dev/null

    echo "attacker rc=$rc"
    grep -E "candidate sets in band|fingerprint sets selected|cos self min|cos target threshold|FINGERPRINTS DO NOT SEPARATE|success rate|Replay data" "$alog" | sed 's/^/    /'

    if [ "$rc" -eq 0 ]; then
        echo "=== SUCCESS on try $try (logs: $alog) ==="
        exit 0
    fi

    case "$rc" in
        2) echo "    -> fingerprints did not separate, rebuilding evsets" ;;
        3) echo "    -> no usable cache sets, rebuilding evsets" ;;
        4) echo "    -> evset build failed" ;;
        124) echo "    -> timed out" ;;
        *) echo "    -> failed" ;;
    esac
done

echo "=== all $MAX_TRIES tries failed ==="
exit 1
