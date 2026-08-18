#!/usr/bin/env bash
# Capture v8_ctjs_ecdh traces for one or more ECDH scalars and file each
# capture under its own directory.
#
#   usage: run_ecdh_ct.sh [-fr|-pp] [attacker-flags...] <key-name>...
#          run_ecdh_ct.sh -fr zeros ones alt 0 1 2
#          RUNS=40 run_ecdh_ct.sh -cl0=xw:0x240:0 7
#
# <key-name> is either an INDEX into the shared EC key pool
# (experiments/v8_ecdh/ec_key_pool/ec_key_<i>.json, the same {key1,key2} pairs
# the non-CT v8_ecdh case study draws from -- $POOL, regenerate/extend with
# v8_ecdh/gen_key_pool.py) or the suffix of a crafted raw-hex scalar,
# experiments/v8_constant_time_js/ec_key_<name>.hex, for the patterns a random
# pool has no reason to carry (zeros, ones, alt). Pool captures are filed under
# k<i> so a bare index never names a directory.
#
# The per-key directory is needed because dump_profiling_traces always writes to the same path
# (output/v8_ctjs_ecdh_r<runs>), so back-to-back captures would overwrite each
# other; each finished capture is moved to output/<prim>_<key>_r<runs>/ and the
# `channels` metadata the attacker wrote travels with it, which is what lets
# extract_v8_ct_ecdh.py configure itself per capture.
#
# Env: BIN, BUILD, CPUS (taskset list -- keep the victim and the attacker on
# the same socket, node1 odd CPUs on leapx02), RUNS, WARMUP, TAG (extra label
# in the capture directory name, e.g. TAG=w2k when sweeping -wait).
#
# RUNS defaults to 1000. The current leak site (BitwiseAndHandler +0x080) has a
# per-trace detection ceiling of 0.779, against 0.827 for the site this replaced,
# so the vote needs more traces to reach the same confidence -- at 200 no decoder
# setting reaches 0 wrong bits, at 1000 it does. A 1000-run capture takes ~7 s.
set -u

SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BUILD=${BUILD:-$SRC/../../build/experiments/v8_constant_time_js}
BIN=${BIN:-$BUILD/v8_ctjs_ecdh}
POOL=${POOL:-$SRC/../v8_ecdh/ec_key_pool}
CPUS=${CPUS:-9,11,13,15}
RUNS=${RUNS:-1000}
TAG=${TAG:-}
WARMUP=${WARMUP:-5}

prim=ps
flags=()
keys=()
for a in "$@"; do
  case $a in
    -fr) prim=fr; flags+=("$a") ;;
    -pp) prim=pp; flags+=("$a") ;;
    -*)  flags+=("$a") ;;
    *)   keys+=("$a") ;;
  esac
done

if [ ${#keys[@]} -eq 0 ]; then
  echo "usage: $0 [-fr|-pp] [attacker-flags...] <key-name>..." >&2
  exit 1
fi
[ -x "$BIN" ] || { echo "ERROR: no attacker binary at $BIN" >&2; exit 1; }

cd "$BUILD" || exit 1
raw="output/v8_ctjs_ecdh_r$(printf '%05d' "$RUNS")"

# One scratch file for every capture's stdout, removed however we exit. It is
# kept next to the captures rather than in /tmp because it holds the whole
# attacker stdout, including the -bits oracle stream derived from the private
# scalar (mktemp creates it 0600).
out=$(mktemp -p "$BUILD")

# BITS=1 captures the victim's OWN per-bit (tsc, bit) pairs alongside the trace,
# for extract_v8_ct_ecdh.py --oracle. This generated copy is the ONLY switch:
# the attacker reads `debug` out of whatever source it was handed and drains
# gt_ts/gt_bit to <raw>/victim_bits.txt when it is set. There is deliberately no
# attacker flag for it -- there used to be, and a flag that disagreed with the
# loaded source gave a capture that looked healthy and quietly had no oracle.
#
# The source flip is a GENERATED copy rather than a second checked-in .js: a
# hand-kept copy drifts, and a stale `let debug = 1;` in one is exactly the bug
# that once made a single derive emit 750-2226 trace lines instead of 246 and
# quietly corrupted every per-bit statistic computed from it. `debug` must stay
# `let` and stay on line 1 for the sed to bite -- see the comment on it there.
#
# It has to be the SAME run as the trace: --oracle uses those timestamps as the
# true slot boundaries against the attacker's samples, on the one rdtscp clock.
# Ground truth captured separately would only supply bit VALUES, which --key
# already knows.
SRC_JS=$SRC/js/ecdh_ct_eval.js
TMP_JS=                       # non-empty ONLY when we generated one to delete
if [ "${BITS:-0}" = 1 ]; then
  TMP_JS=$(mktemp -p "$BUILD" --suffix=.js)
  SRC_JS=$TMP_JS
  sed 's/^let debug = 0;/let debug = 1;/' "$SRC/js/ecdh_ct_eval.js" > "$SRC_JS"
  grep -q '^let debug = 1;' "$SRC_JS" ||
    { echo "ERROR: could not enable the victim oracle in $SRC_JS" >&2; exit 1; }
fi

trap 'rm -f "$out" ${TMP_JS:+"$TMP_JS"}' EXIT INT TERM

for k in "${keys[@]}"; do
  # A key name that is all digits is a pool index; anything else names a
  # crafted raw-hex scalar next to the victim sources. The attacker takes
  # either file and tells the two apart by extension.
  case $k in
    *[!0-9]*|'') key_file=$SRC/ec_key_$k.hex; label=$k ;;
    *)           key_file=$POOL/ec_key_$k.json; label=k$k ;;
  esac
  [ -f "$key_file" ] || { echo "ERROR: no key file $key_file" >&2; exit 1; }
  dst="output/${prim}${TAG:+_$TAG}_${label}_r$(printf '%05d' "$RUNS")"

  rm -rf "$raw" "$dst"
  echo "### $prim $k (runs=$RUNS, key $key_file)"
  # With BITS=1, $SRC_JS is the mktemp'd oracle copy the trap below deletes on
  # exit -- printing the command alone would hand back a path that is already
  # gone by the time anyone could paste it, so the regen line goes with it.
  if [ -n "$TMP_JS" ]; then
    printf "+ sed 's/^let debug = 0;/let debug = 1;/' %q > %q  # regenerates the oracle copy below; deleted on exit\n" \
      "$SRC/js/ecdh_ct_eval.js" "$SRC_JS"
  fi
  printf '+'
  printf ' %q' taskset -c "$CPUS" "$BIN" "${flags[@]}" -runs="$RUNS" -warmup="$WARMUP" \
    "$SRC_JS" "$SRC/js/ecdh_ct_repeat.js" "$key_file"
  echo
  taskset -c "$CPUS" "$BIN" "${flags[@]}" -runs="$RUNS" -warmup="$WARMUP" \
    "$SRC_JS" "$SRC/js/ecdh_ct_repeat.js" "$key_file" \
    > "$out" 2>&1
  # "qualified|rebuilding|never produced" are the attacker's pre-capture evset
  # fingerprint verdicts -- the one thing worth seeing BEFORE the run counts,
  # since a channel that needed three attempts is a channel to distrust.
  grep -aE "run 1/|run $RUNS/|cl[0-9] role|channel metadata|failed|ERROR\
|qualified|rebuilding|never produced" "$out" \
    | sed 's/\x1b\[[0-9;]*m//g'

  # -d "$raw" alone is not enough to call it a capture: the attacker creates
  # the directory for its `channels` metadata before it probes anything, so an
  # attacker that aborted -- a channel that never passed the pre-capture evset
  # fingerprint, say -- left a directory holding one file and no traces, and
  # this filed it under $dst as a real capture with "(0 traces)".
  if [ -d "$raw" ] && [ -n "$(ls "$raw"/*.out 2>/dev/null)" ]; then
    # victim_bits.txt -- the victim's own per-bit (tsc, bit) pairs, one block
    # per profiled derive, in run order -- is written by the attacker itself
    # when BITS=1 put `let debug = 1;` in the source above, straight from the
    # typed arrays. It used to be scraped out of stdout here; it no longer is,
    # because a log line from another thread could splice into a pair and
    # `grep '^[0-9]+,[01]$'` would drop it, shifting every later run's block
    # without a word. Absent (BITS unset) the file simply never appears.
    [ -s "$raw/victim_bits.txt" ] || rm -f "$raw/victim_bits.txt"
    mv "$raw" "$dst"
    echo "    -> $BUILD/$dst  ($(ls "$dst"/*.out 2>/dev/null | wc -l) traces$(
      [ -f "$dst/victim_bits.txt" ] && echo ", + oracle"))"
  else
    rm -rf "$raw"
    echo "    !! no traces produced" >&2
  fi
done
