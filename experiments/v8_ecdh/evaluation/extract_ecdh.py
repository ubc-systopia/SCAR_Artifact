#!/usr/bin/env python3
"""Recover ECDH secret scalars from a v8_ecdh Prime+Scope capture.

    python extract_ecdh.py --all_keys ./build/output/full_run

The capture directory holds one subdirectory per key, and one trace file per
run inside it. A trace is three channels wide -- clock, false arm, true arm
(see plot_ecdh_trace.py) -- and the decode reads the clock and the true-arm
marker only.
"""

import argparse
import json
import re

import numpy as np

from utils import Path, find_project_root, load_trace, trace_to_timestamp

# --- common+true nearest-tick decode ---------------------------------------
#
# The three-channel path above needs ch_0 (the FALSE arm) and ch_1 (the TRUE
# arm) in the same trace. That does not work on this target: FALSE is the
# branch's fall-through, so it is reached by sequential prefetch and fires on
# nearly every iteration whatever the bit was (measured: 215-256 hits against
# 121-144 zero-bits). Only two lines carry usable information --
#
#   slot 0, cl_offset[0] = 0xe00, the ladder loop header: one hit per
#           iteration, i.e. the CLOCK.
#   slot 2, cl_offset[2] = 0xfc0, inside the TRUE arm, which is a JUMP TARGET
#           so prefetch does not follow it: it fires once per 1-bit, and its
#           hit count equals the key's popcount (r = 0.999 over 10 keys).
#
# so a bit is decoded by asking which clock tick each marker event belongs to.
#
# The one subtlety is alignment. The densest clock segment usually holds a few
# more ticks than the key has bits (loop entry and exit, an extra sample), and
# which end the surplus sits on VARIES BETWEEN TRACES -- a fixed alignment
# scores 0.93 merged where a per-trace one scores 1.00. The shift cannot be
# chosen against the answer, so each trace offers one candidate per shift and
# they are resolved against each other: seed a consensus from one candidate,
# let every trace pick the candidate that agrees with it most, re-vote, repeat.
# The seed that ends with the highest agreement wins. No ground truth is used.

MAX_TICK_SHIFT = 10
SEGMENT_BREAK_CYCLES = 150000
MARKER_EDGE_TOLERANCE = 30000


def _densest_segment(ts, break_cycles=SEGMENT_BREAK_CYCLES):
    """The longest run of clock hits with no gap above `break_cycles`.

    The probe window is much longer than one derive, so the clock line also
    picks up idle and neighbouring derives; the ladder is the dense stretch.
    """
    if len(ts) < 2:
        return ts
    breaks = np.nonzero(np.diff(ts.astype(np.int64)) > break_cycles)[0]
    starts = np.concatenate(([0], breaks + 1))
    ends = np.concatenate((breaks + 1, [len(ts)]))
    best = np.argmax(ends - starts)
    return ts[starts[best]:ends[best]]


def _trace_candidates(clock, marker, key_length):
    """One bit vector per plausible tick/bit alignment of a single trace."""
    ticks = _densest_segment(clock)
    if len(ticks) < key_length:
        return []
    out = []
    span = min(len(ticks) - key_length, MAX_TICK_SHIFT)
    for shift in range(span + 1):
        t = ticks[shift:shift + key_length]
        idx = np.clip(np.searchsorted(t, marker), 1, key_length - 1)
        near = np.where(marker - t[idx - 1] <= t[idx] - marker, idx - 1, idx)
        near = near[(marker >= t[0] - MARKER_EDGE_TOLERANCE)
                    & (marker <= t[-1] + MARKER_EDGE_TOLERANCE)]
        bits = np.zeros(key_length, dtype=np.int8)
        bits[near] = 1
        out.append(bits)
    return out


MAX_CONSENSUS_SEEDS = 8


def _consensus(candidates, iters=6):
    """Resolve per-trace alignment against the other traces, then vote.

    Every candidate of every trace could seed the consensus, but the search
    is quadratic in the trace count and any trace that is not badly broken
    converges to the same answer, so only the first few traces are used as
    seeds. That is the difference between seconds and minutes on a capture
    with 100 traces per key.
    """
    best = None
    for cand_list in candidates[:MAX_CONSENSUS_SEEDS]:
        for seed in cand_list:
            cons = seed.copy()
            for _ in range(iters):
                chosen = [max(c, key=lambda b: (b == cons).sum())
                          for c in candidates]
                cons = (np.mean(chosen, axis=0) >= 0.5).astype(np.int8)
            score = float(np.mean([(b == cons).mean() for b in chosen]))
            if best is None or score > best[0]:
                best = (score, cons)
    return best


def _false_arm_health(clock, false_arm, key_length):
    """How many ladder ticks the FALSE arm lit, per trace.

    Slot 1 is read but never voted. Its hit count tracks the key's ZERO count
    closely, which makes it a good capture-health signal, but its per-tick
    PLACEMENT is not good enough to decode with: measured on pool keys,
    0xe80 lights ~200 of 246 ticks where there are 125 zeros (60% precision,
    96% recall) because its two events per zero straddle the tick boundary at
    phase ~0.00 and ~0.95. De-duped 0xec0 does better on count (124.7 against
    125) but still places only ~77% in the right tick.

    Fusing it with the marker was measured under ORACLE per-channel rates and
    changed nothing: the marker is a 17:1 likelihood-ratio channel (fire
    +2.83 nats, silent -2.69) while the false arm's silence is only 5.5:1
    (+1.71), so its term can never overturn the marker's on any bit. Over 92
    single traces the fused decode was bit-for-bit identical. It is kept for
    diagnostics, and because a marker with a poor eviction set is the one
    case where a weaker second channel would start to matter.
    """
    ticks = _densest_segment(clock)
    if len(ticks) < key_length or len(false_arm) == 0:
        return None
    t = ticks[:key_length]
    inside = false_arm[(false_arm >= t[0]) & (false_arm <= t[-1])]
    if len(inside) == 0:
        return None
    idx = np.clip(np.searchsorted(t, inside, side="right") - 1,
                  0, key_length - 1)
    return len(np.unique(idx))


def infer_key_nearest_tick(subdir, key_length):
    """Decode one key directory.

    -> (bits, self_consistency, n_traces, false_arm_ticks)
    """
    candidates = []
    false_ticks = []
    for filepath in sorted(Path(subdir).glob("*.out")):
        trace = load_trace(filepath)
        if trace.shape[1] < 3:
            continue
        clock = trace_to_timestamp(trace[0], "PS")
        marker = trace_to_timestamp(trace[2], "PS")
        false_arm = trace_to_timestamp(trace[1], "PS")
        cand = _trace_candidates(clock, marker, key_length)
        if cand:
            candidates.append(cand)
            lit = _false_arm_health(clock, false_arm, key_length)
            if lit is not None:
                false_ticks.append(lit)
    if not candidates:
        return None, 0.0, 0, None
    score, bits = _consensus(candidates)
    # An L-bit scalar has MSB 1 by definition, and the ladder's first
    # iteration produces no separately observable marker event.
    bits[0] = 1
    median_lit = float(np.median(false_ticks)) if false_ticks else None
    return bits, score, len(candidates), median_lit


def infer_all_keys_nearest_tick(all_keys_dir):
    dir_path = Path(all_keys_dir)
    pattern = r"v8_ecdh_key_pool_key(\d+)"
    total_wrong = total_bits = 0
    rows = []
    for subdir in sorted(dir_path.iterdir()):
        if not subdir.is_dir():
            continue
        matches = re.search(pattern, subdir.name)
        if not matches:
            continue
        key_id = int(matches.group(1))
        keypair = json.load(open(
            find_project_root()
            + f"/experiments/v8_ecdh/ec_key_pool/ec_key_{key_id}.json"))
        secret = int(keypair["key1"], 16)
        truth = np.array([int(c) for c in bin(secret)[2:]], dtype=np.int8)

        zeros = int((truth == 0).sum())
        bits, score, n, lit = infer_key_nearest_tick(subdir, len(truth))
        if bits is None:
            rows.append((key_id, len(truth), 0, 0.0, None, len(truth),
                         zeros, None))
            total_bits += len(truth)
            total_wrong += len(truth)
            continue
        wrong = int((bits != truth).sum())
        total_wrong += wrong
        total_bits += len(truth)
        rows.append((key_id, len(truth), n, score,
                     (bits == truth).mean(), wrong, zeros, lit))

    # false-arm columns are DIAGNOSTIC: slot 1 is read, never voted. "lit" is
    # how many ticks it fired in, against the key's zero count. Close to the
    # zero count means the line is alive and on the right target; far above it
    # means the eviction set is catching something else too.
    print(f"{'key':>4} {'bits':>5} {'traces':>7} {'consistency':>12} "
          f"{'accuracy':>9} {'wrong':>6} {'zeros':>6} {'cl1 lit':>8}")
    for key_id, length, n, score, acc, wrong, zeros, lit in rows:
        acc_s = "-" if acc is None else f"{acc * 100:.2f}%"
        lit_s = "-" if lit is None else f"{lit:.0f}"
        print(f"{key_id:>4} {length:>5} {n:>7} {score:>12.4f} "
              f"{acc_s:>9} {wrong:>6} {zeros:>6} {lit_s:>8}")
    if total_bits:
        print(f"\nTOTAL: {total_wrong} wrong / {total_bits} bits = "
              f"{(1 - total_wrong / total_bits) * 100:.3f}%")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Recover ECDH secret scalars from a v8_ecdh capture"
    )
    parser.add_argument(
        "--all_keys",
        required=True,
        help="capture directory, e.g. ./build/output/full_run",
    )
    args = parser.parse_args()

    infer_all_keys_nearest_tick(args.all_keys)
