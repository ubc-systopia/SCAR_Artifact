#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${BUILD:-${ROOT}/build}"
SRC="${ROOT}/experiments/v8_ecdh"
BIN="${BUILD}/experiments/v8_ecdh/v8_ecdh_key_pool"
CPUS=${CPUS:-1,3,5,7}
KEYS=${KEYS:-100}
RUNS=${RUNS:-100}
ATTEMPTS=${ATTEMPTS:-5}
TAG=${TAG:-v8_ecdh_key_pool}
PYTHON=${PYTHON:-$ROOT/.venv/bin/python3}
[ -x "$PYTHON" ] || PYTHON=python3

[ -x "$BIN" ] || {
	echo "no binary at $BIN;" >&2
	exit 1
}

mkdir -p "$BUILD/output"
log=$BUILD/output/${TAG}.log

for attempt in $(seq 1 "$ATTEMPTS"); do
	rm -rf "${BUILD:?}/output/${TAG:?}"
	echo "capturing $KEYS keys x $RUNS traces (attempt $attempt/$ATTEMPTS)"
	(
		cd "$BUILD" || exit 1
		taskset -c "$CPUS" "$BIN" \
			"$SRC/js/elliptic_ecdh_eval.js" \
			"$SRC/js/elliptic_ecdh_repeat.js" \
			"$SRC/js/elliptic_ecdh_set_keypair_template.js" \
			-tag="$TAG" -keys="$KEYS" -runs="$RUNS" \
			--always-turbofan --single-threaded
	) >"$log" 2>&1

	captured=$(find "$BUILD/output/$TAG" -mindepth 1 -maxdepth 1 -type d -name '*_key*' 2>/dev/null | wc -l)
	[ "$captured" -eq "$KEYS" ] && break

	echo "  unusable eviction sets ($captured/$KEYS keys), retry"
	[ "$attempt" -eq "$ATTEMPTS" ] && {
		echo "failed after $ATTEMPTS attempts; see $log" >&2
		exit 1
	}
done

echo "traces in $BUILD/output/$TAG"
cd "$ROOT" || exit 1
exec "$PYTHON" "$SRC/evaluation/extract_ecdh.py" --all_keys "$BUILD/output/$TAG"
