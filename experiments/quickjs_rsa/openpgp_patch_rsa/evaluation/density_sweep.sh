#!/usr/bin/env bash
# Probe-density sweep: rerun the SELECT/modExp FR attack at successively lower
# WAITING_TIME and stash each run's traces for offline narrow-window analysis.
set -uo pipefail

ROOT=/home/ddinh02/SCAR_Artifact
BUILD=$ROOT/build
CPUS=1,3,5,7,9,11,13,15
RUNS=3
OUTBASE=/tmp/claude-1004/-home-ddinh02-SCAR-Artifact-experiments-quickjs-rsa/d08294d6-fd40-4d08-924b-7a3b24f6dd89/scratchpad/density
mkdir -p "$OUTBASE"

VICTIM=$BUILD/src/runtime/quickjs/quickjs_rt
ATT=$BUILD/experiments/quickjs_rsa/quickjs_select_rsa_fr
VJS=$ROOT/experiments/quickjs_rsa/openpgp_patch_rsa/js/openpgp_select_rsa.js
TRACE=$BUILD/output/quickjs_select_rsa_fr/quickjs_select_rsa_fr_key00000_r$(printf '%05d' $RUNS)

cd "$BUILD"
for WT in "$@"; do
	echo "===== WAITING_TIME=$WT ====="
	rm -rf "$TRACE"
	taskset -c "$CPUS" "$VICTIM" "$VJS" >/dev/null 2>&1 &
	VP=$!
	sleep 1
	VICTIM_RUNS=$RUNS WAITING_TIME=$WT ROUND_CYCLES=6000000000 KEY_ID=0 \
		taskset -c "$CPUS" "$ATT" $RUNS 2>&1 | grep -E "Round|warn|WARN" || true
	wait $VP 2>/dev/null || true
	kill $VP 2>/dev/null || true
	if [ -d "$TRACE" ]; then
		rm -rf "$OUTBASE/wt$WT"
		cp -r "$TRACE" "$OUTBASE/wt$WT"
		echo "  -> $OUTBASE/wt$WT"
	else
		echo "  !! no trace produced"
	fi
done
