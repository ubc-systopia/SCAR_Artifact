"""One trace per key: what a single-shot attacker gets.

evaluate_pool.py's headline numbers take the best of a key's 128 traces, which
answers "can this key be recovered?". This answers the other question -- draw
ONE trace per key at random and score it -- and reports mean / median / min /
max accuracy across the pool.

Does the whole thing in one pass: draw, decode, score. No intermediate
directory, no symlinks. The draw is seeded, so a run is reproducible; --seed
changes it, and the spread across seeds is itself informative.

    python3 one_trace_per_key.py [--pool DIR] [--seed N] [--csv OUT] [--jobs N]

Accuracy here is a plain per-bit rate over the bits the trace placed; there is
no voting band, because with one trace a vote is just the trace. Two things
are upper bounds and are reported rather than hidden:

  - the anchor is resolved against the known key (decoder.best_anchor), an
    oracle standing in for the 5 trial verifications a real attacker does;
  - coverage < 1 means the trace placed fewer bits than the exponent has. A
    key with low coverage has its accuracy computed over very few bits and is
    not comparable to the rest, so coverage is printed alongside.
"""
import os

# Before numpy, and before workers are forked: OpenBLAS otherwise spawns up to
# 64 threads per process and oversubscribes the pinned cores. There is no
# matrix work here -- the job is parsing trace files. (Same reason as
# evaluate_pool.py.)
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")

import argparse
import concurrent.futures as cf
import csv
import random
import re
import statistics as st
import sys
from pathlib import Path

import numpy as np

import decoder as D
import recover as R

DEFAULT_POOL = "/home/ddinh02/SCAR_Artifact/build/output/quickjs_select_rsa_ps"
DEFAULT_SEED = 20260821
KEY_DIR_RE = re.compile(r"quickjs_select_rsa_ps_key(\d+)_r(\d+)$")
ANCHOR_SPAN = 2
MIN_COVERAGE = 0.5   # below this, accuracy rests on too few bits to compare
BAND = (0.90, 0.95)  # evaluate_pool.py's band, applied here only to duplicates


def draw(pool, seed):
    """key_id -> one randomly chosen trace path. Draws from the directory with
    the most runs per key; ignores degenerate_backup_* and pilot leftovers."""
    best = {}
    for d in Path(pool).iterdir():
        m = KEY_DIR_RE.match(d.name) if d.is_dir() else None
        if m:
            key_id, runs = int(m.group(1)), int(m.group(2))
            if runs > best.get(key_id, (0, None))[0]:
                best[key_id] = (runs, d)

    rng = random.Random(seed)
    picks = {}
    for key_id in sorted(best):
        traces = sorted(best[key_id][1].glob("r*.out*"))
        if traces:
            picks[key_id] = rng.choice(traces)
    return picks


def collapse(idx, bit, n_bits, truth):
    """One prediction per exponent bit, then accuracy over the bits predicted.

    Two pairs can round to the same iteration index (seen: 255 pairs over 188
    distinct indices on a thin trace), so the raw per-pair rate would count
    some bits twice. Collapse duplicates the way evaluate_pool.py's vote does
    -- positive rate per bit against BAND, disagreements left unknown -- so
    the numbers here and there mean the same thing.

    Returns (n_known, accuracy) over the bits that came out known.
    """
    low, high = BAND
    ones = np.bincount(idx, weights=bit, minlength=n_bits)
    tot = np.bincount(idx, minlength=n_bits)
    observed = tot > 0
    ppr = np.full(n_bits, -1.0)
    ppr[observed] = ones[observed] / tot[observed]

    known = (ppr >= high) | ((ppr <= low) & observed)
    if not known.any():
        return 0, None
    pred = np.where(ppr >= high, 1, 0)
    return int(known.sum()), float((pred[known] == truth[known]).mean())


def score(item):
    """Worker: decode one trace, sweeping the anchor. Returns a result dict."""
    key_id, path = item
    lsb_first, _ = D.load_exponent(key_id)
    n_bits = len(lsb_first)
    ts = R.load(path)

    # The anchor is picked on the raw per-pair rate (decoder.best_anchor does
    # the same); duplicates are collapsed afterwards, on the winner only.
    best = None
    for anchor in range(-ANCHOR_SPAN, ANCHOR_SPAN + 1):
        idx, bit = R.recover(ts, n_bits, anchor=anchor)
        if not len(idx):
            continue
        raw = float((bit == lsb_first[idx]).mean())
        if best is None or raw > best[0]:
            best = (raw, anchor, idx, bit)

    if best is None:
        return {"key_id": key_id, "trace": path.name, "bits": 0,
                "coverage": 0.0, "accuracy": None, "anchor": None,
                "n_bits": n_bits}

    _, anchor, idx, bit = best
    bits, acc = collapse(idx, bit, n_bits, lsb_first)
    return {"key_id": key_id, "trace": path.name, "bits": bits,
            "coverage": bits / n_bits, "accuracy": acc, "anchor": anchor,
            "n_bits": n_bits}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", default=DEFAULT_POOL, help="key-pool output root")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--jobs", type=int, default=None)
    ap.add_argument("--csv", default=None, help="write per-key results here")
    args = ap.parse_args()

    if not Path(args.pool).is_dir():
        sys.exit(f"no such pool directory: {args.pool}")
    picks = draw(args.pool, args.seed)
    if not picks:
        sys.exit(f"no key directories found under {args.pool}")

    print(f"pool: {args.pool}")
    print(f"keys: {len(picks)}   one random trace each   seed: {args.seed}")

    with cf.ProcessPoolExecutor(max_workers=args.jobs) as ex:
        rows = list(ex.map(score, sorted(picks.items())))

    print(f"\n{'key':>5}{'trace':>14}{'bits':>7}{'coverage':>10}"
          f"{'anchor':>8}{'accuracy':>10}")
    for r in rows:
        acc = f"{r['accuracy']:.4f}" if r["accuracy"] is not None else "   n/a"
        anc = f"{r['anchor']:+d}" if r["anchor"] is not None else "  -"
        flag = "  (low coverage)" if r["coverage"] < MIN_COVERAGE else ""
        print(f"{r['key_id']:>5}{r['trace']:>14}{r['bits']:>7}"
              f"{r['coverage']:>10.4f}{anc:>8}{acc:>10}{flag}")

    accs = [r["accuracy"] for r in rows if r["accuracy"] is not None]
    if not accs:
        sys.exit("no key produced a usable trace")

    covs = [r["coverage"] for r in rows if r["accuracy"] is not None]
    lo = min(rows, key=lambda r: r["accuracy"] if r["accuracy"] is not None else 2)
    hi = max(rows, key=lambda r: r["accuracy"] if r["accuracy"] is not None else -1)
    clo = min(rows, key=lambda r: r["coverage"])
    chi = max(rows, key=lambda r: r["coverage"])

    print(f"\n{'=' * 68}\nOver {len(accs)} keys, one random trace each\n{'=' * 68}")
    print(f"  {'':<8}{'accuracy':>10}{'':>6}{'bit coverage':>14}")
    print(f"  {'mean':<8}{st.mean(accs):>10.4f}{'':>6}{st.mean(covs):>14.4f}")
    print(f"  {'median':<8}{st.median(accs):>10.4f}{'':>6}{st.median(covs):>14.4f}")
    print(f"  {'min':<8}{lo['accuracy']:>10.4f}{'':>6}{clo['coverage']:>14.4f}")
    print(f"  {'max':<8}{hi['accuracy']:>10.4f}{'':>6}{chi['coverage']:>14.4f}")
    print(f"  {'':<8}{'key ' + str(lo['key_id']) + ' / ' + str(hi['key_id']):>10}"
          f"{'':>6}{'key ' + str(clo['key_id']) + ' / ' + str(chi['key_id']):>14}"
          "   (min / max)")

    total_bits = sum(r["n_bits"] for r in rows)
    total_known = sum(r["bits"] for r in rows)
    total_right = sum(round(r["bits"] * r["accuracy"]) for r in rows
                      if r["accuracy"] is not None)
    print(f"\n  pool-wide: {total_known} of {total_bits} exponent bits predicted "
          f"({total_known / total_bits:.4f}),")
    print(f"             {total_right} of those correct "
          f"({total_right / total_known:.4f})")
    print( "  coverage < 1 is iterations the probe missed, plus pairs that rounded")
    print( "  onto the same index and disagreed; unpredicted bits are not guessed.")

    print(f"\n  >= 0.90        {sum(1 for a in accs if a >= 0.90):>3} / {len(accs)}")
    print(f"  >= 0.75        {sum(1 for a in accs if a >= 0.75):>3} / {len(accs)}")
    print(f"  ~chance <0.55  {sum(1 for a in accs if a < 0.55):>3} / {len(accs)}")

    thin = [r for r in rows if r["coverage"] < MIN_COVERAGE]
    if thin:
        print(f"\n  {len(thin)} key(s) below {MIN_COVERAGE:.0%} coverage -- accuracy there rests")
        print( "  on few bits and is not comparable: "
              + ", ".join(f"key {r['key_id']} ({r['coverage']:.3f})" for r in thin))

    print("\n  anchors resolved against the known key (decoder.best_anchor);")
    print("  a real attacker tries the 5 candidates against a known signature.")

    if args.csv:
        with open(args.csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        print(f"\nwrote {args.csv}")


if __name__ == "__main__":
    main()
