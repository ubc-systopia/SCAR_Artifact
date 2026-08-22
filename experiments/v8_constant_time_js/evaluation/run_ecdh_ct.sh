#!/usr/bin/env bash
# Capture v8_ctjs_ecdh traces for one or more ECDH scalars, one directory per
# capture (the attacker always dumps to the same path, so back-to-back captures
# would otherwise overwrite each other).
#
#   usage: run_ecdh_ct.sh [-fr|-pp] [attacker-flags...] <key-name>...
#          run_ecdh_ct.sh -fr zeros ones alt 0 1 2
#          RUNS=40 run_ecdh_ct.sh -cl0=xw:0x240:0 7
#
# <key-name> is an index into the shared pool ($POOL/ec_key_<i>.json, filed
# under k<i>) or the suffix of a crafted scalar, ec_key_<name>.hex.
#
# Env: BIN, BUILD, CPUS (one socket -- node1 odd CPUs on leapx02), RUNS,
# WARMUP, TAG (extra label in the capture directory name).
set -u

SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BUILD=${BUILD:-$SRC/../../build/experiments/v8_constant_time_js}
BIN=${BIN:-$BUILD/v8_ctjs_ecdh}
POOL=${POOL:-$SRC/../v8_ecdh/ec_key_pool}
# Six of node1's eight cores, one socket. P+P starves below three runnable
# threads and measured best at six (median 0.875 over 8 reps against 0.866 at
# eight). F+R is insensitive to the count, so this costs it nothing.
CPUS=${CPUS:-5,7,9,11,13,15}
RUNS=${RUNS:-1000}
TAG=${TAG:-}
WARMUP=${WARMUP:-5}

prim=fr
flags=()
keys=()
for a in "$@"; do
  case $a in
    -fr)  prim=fr;  flags+=("$a") ;;
    -pp)  prim=pp;  flags+=("$a") ;;
    -csi) prim=csi; flags+=("$a") ;;
    -*)   flags+=("$a") ;;
    *)    keys+=("$a") ;;
  esac
done

# CSI drives its own probe keys, so <key-name> is optional there.
if [ ${#keys[@]} -eq 0 ] && [ "$prim" != csi ]; then
  echo "usage: $0 [-fr|-pp|-csi] [attacker-flags...] <key-name>..." >&2
  exit 1
fi
[ -x "$BIN" ] || { echo "ERROR: no attacker binary at $BIN" >&2; exit 1; }

cd "$BUILD" || exit 1
raw="output/v8_ctjs_ecdh_r$(printf '%05d' "$RUNS")"

# Holds the whole attacker stdout, oracle stream included, so it stays next to
# the captures rather than in /tmp (mktemp creates it 0600).
out=$(mktemp -p "$BUILD")

# BITS=1 generates a copy of the victim source with `let debug = 1;`, which
# makes the attacker drain the victim's own per-bit (tsc, bit) pairs to
# <raw>/victim_bits.txt for --oracle. The generated copy is the only switch --
# an attacker flag that disagreed with the loaded source used to give a capture
# that looked healthy and had no oracle. It must be the same run as the trace,
# since --oracle uses those timestamps as the true slot boundaries.
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

# CSI is its own capture shape: it writes one r<l3_set>.out per candidate L3
# set to output/v8_ctjs_ecdh, with the three csi_probe_keys as columns, and
# drives the victim through those keys itself rather than looping over
# <key-name>. BITS=1 adds csi_truth.txt and victim_bits.txt for offline
# scoring.
if [ "$prim" = csi ]; then
  csi_raw="output/v8_ctjs_ecdh"
  k=${keys[0]:-zeros}
  case $k in
    *[!0-9]*|'') key_file=$SRC/ec_key_$k.hex ;;
    *)           key_file=$POOL/ec_key_$k.json ;;
  esac
  [ -f "$key_file" ] || key_file=$SRC/ec_key_zeros.hex
  dst="output/csi${TAG:+_$TAG}"
  rm -rf "$csi_raw" "$dst"
  echo "### csi (key $key_file, BITS=${BITS:-0}, cpus $CPUS)"
  if [ -n "$TMP_JS" ]; then
    printf "+ sed 's/^let debug = 0;/let debug = 1;/' %q > %q  # oracle copy, deleted on exit\n" \
      "$SRC/js/ecdh_ct_eval.js" "$SRC_JS"
  fi
  printf '+'
  printf ' %q' taskset -c "$CPUS" "$BIN" "${flags[@]}" -warmup="$WARMUP" \
    "$SRC_JS" "$SRC/js/ecdh_ct_repeat.js" "$key_file"
  echo
  taskset -c "$CPUS" "$BIN" "${flags[@]}" -warmup="$WARMUP" \
    "$SRC_JS" "$SRC/js/ecdh_ct_repeat.js" "$key_file" \
    > "$out" 2>&1
  grep -aE "page slot|TRUE target set|CSI ground truth|samples|failed|ERROR" \
    "$out" | sed 's/\x1b\[[0-9;]*m//g'
  if [ -d "$csi_raw" ] && [ -n "$(ls "$csi_raw"/*.out 2>/dev/null)" ]; then
    [ -s "$csi_raw/victim_bits.txt" ] || rm -f "$csi_raw/victim_bits.txt"
    mv "$csi_raw" "$dst"
    echo "    -> $BUILD/$dst  ($(ls "$dst"/*.out 2>/dev/null | wc -l) candidate \
sets$([ -f "$dst/victim_bits.txt" ] && echo ', + oracle')$(
      [ -f "$dst/csi_truth.txt" ] && echo ', + truth'))"
  else
    rm -rf "$csi_raw"
    echo "    !! no candidate traces produced" >&2
  fi
  exit 0
fi

for k in "${keys[@]}"; do
  # All digits -> pool index, anything else -> crafted raw-hex scalar.
  case $k in
    *[!0-9]*|'') key_file=$SRC/ec_key_$k.hex; label=$k ;;
    *)           key_file=$POOL/ec_key_$k.json; label=k$k ;;
  esac
  [ -f "$key_file" ] || { echo "ERROR: no key file $key_file" >&2; exit 1; }
  dst="output/${prim}${TAG:+_$TAG}_${label}_r$(printf '%05d' "$RUNS")"

  rm -rf "$raw" "$dst"
  echo "### $prim $k (runs=$RUNS, key $key_file)"
  # $SRC_JS is deleted on exit under BITS=1, so print how to regenerate it.
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
  grep -aE "run 1/|run $RUNS/|cl[0-9] role|channel metadata|failed|ERROR" \
    "$out" | sed 's/\x1b\[[0-9;]*m//g'

  # -d "$raw" alone is not enough: the attacker creates the directory for its
  # `channels` metadata before it probes, so an aborted run leaves one behind.
  if [ -d "$raw" ] && [ -n "$(ls "$raw"/*.out 2>/dev/null)" ]; then
    # The attacker writes victim_bits.txt itself under BITS=1. Do not go back
    # to scraping it from stdout -- a log line from another thread splices into
    # a pair and shifts every later run's block silently.
    [ -s "$raw/victim_bits.txt" ] || rm -f "$raw/victim_bits.txt"
    mv "$raw" "$dst"
    echo "    -> $BUILD/$dst  ($(ls "$dst"/*.out 2>/dev/null | wc -l) traces$(
      [ -f "$dst/victim_bits.txt" ] && echo ", + oracle"))"
  else
    rm -rf "$raw"
    echo "    !! no traces produced" >&2
  fi
done
