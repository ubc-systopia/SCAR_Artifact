"""Comprehensive key-pool evaluation for the SELECT-patch Prime+Scope attack.

Evaluates many keys and many runs per key, in the shape of the key-pool
result (evaluation/extract_openpgp_rsa.py): per-bit voting across repeated
runs with a confidence band, bits outside the band marked unknown, and
coverage / runs-required statistics reported as min/median/max across keys.

Two things differ from that reference on purpose, and are reported rather
than hidden:

  - the decoder needs one more piece of information per trace than section
    5.1's does: which loop iteration the first recovered pair belongs to (the
    "anchor", decoder.assign_indices). It is one integer per trace out of a
    handful of candidates, and it is resolved here against the known exponent
    (decoder.best_anchor). That stands in for the check a real attacker
    performs anyway -- trying each candidate key against a known signature --
    but it is an oracle, so every number below is an upper bound in that one
    specific respect.

  - the single-key analysis already finds that repeating the attack does not improve
    it on 5 traces of one key, because the errors are shared rather than
    independent. This script's per-key voting will most likely reproduce
    that finding at pool scale; §"voting vs best single trace" below checks
    it directly instead of assuming it.

Usage:
    python3 evaluate_pool.py --pool DIR [--runs N] [--band LOW HIGH]
                              [--jobs N] [--out CSV]

DIR is the quickjs_bigint_select_rsa output root, holding one subdirectory per
key: quickjs_bigint_select_rsa_key<NNNNN>_r<RRRRR>/r*.out[.gz].
"""
import os

# Must be set before numpy is imported (and before worker processes are
# forked, which inherit the environment): the work here is parsing trace
# files and taking medians, but OpenBLAS defaults to spawning up to 64
# threads per process regardless. With --jobs worker processes each doing
# that, the pinned cores are oversubscribed several times over and wall time
# roughly doubles for no benefit -- there's no matrix work here at all. One
# thread per process, --jobs processes, is the actual parallelism this
# script wants (the pool is I/O bound on trace parsing).
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")

import argparse
import concurrent.futures as cf
import csv
import random
import re
import sys
from pathlib import Path

import numpy as np

import decoder as D

DEFAULT_BAND = (0.90, 0.95)  # low -> predict 0, high -> predict 1; REPORT 5.1's band.
DEFAULT_TARGET_COVERAGE = 0.99
DEFAULT_RUNS_REPEATS = 5

KEY_DIR_RE = re.compile(r"quickjs_bigint_select_rsa_key(\d+)_r(\d+)$")


def find_key_dirs(pool_dir, runs=None):
    """Map key_id -> chosen trace directory under pool_dir.

    Multiple r-counts can exist for the same key (e.g. an earlier pilot run
    left key00000_r00004 alongside the full key00000_r00128). Prefer the
    directory matching --runs if given, else the one with the most runs.
    """
    candidates = {}
    for d in Path(pool_dir).iterdir():
        if not d.is_dir():
            continue
        m = KEY_DIR_RE.match(d.name)
        if not m:
            continue
        key_id, r = int(m.group(1)), int(m.group(2))
        candidates.setdefault(key_id, []).append((r, d))

    chosen = {}
    for key_id, opts in candidates.items():
        if runs is not None:
            match = [d for r, d in opts if r == runs]
            if match:
                chosen[key_id] = match[0]
                continue
        chosen[key_id] = max(opts, key=lambda x: x[0])[1]
    return chosen


def trace_files(key_dir):
    return sorted(key_dir.glob("r*.out*"))


# A handful of pool traces come back with almost no wide pairs at all (seen:
# runs of consecutive traces with 1, 8, 94, 171 pairs against a normal ~4000)
# -- some transient recording problem, not a slow trace. A period taken from
# a handful of spacings is meaningless and propagates silently into garbage
# indices and votes, so traces this thin are dropped before decoding.
MIN_WIDE_PAIRS = 100


def _process_trace(path):
    """Worker: parse one trace and split it into pairs. This is the expensive
    step (parsing ~700 KB of text per trace), so it's the unit of
    parallelism."""
    ts, _ = D.load_trace(path)
    start_t, wide_gap, _, alternation = D.wide_narrow(ts)
    return {
        "name": path.name.split(".")[0],
        "start_t": start_t,
        "wide_gap": wide_gap,
        "alternation": alternation,
        "degenerate": len(start_t) < MIN_WIDE_PAIRS,
    }


def process_key(key_id, paths, jobs, executor=None):
    """Decode every trace of one key. Returns (list of per-trace dicts; count
    of traces dropped as degenerate, see MIN_WIDE_PAIRS)."""
    lsb_first, _ = D.load_exponent(key_id)
    n_bits = len(lsb_first)

    if executor is not None:
        raw = list(executor.map(_process_trace, paths))
    else:
        raw = [_process_trace(p) for p in paths]

    n_degenerate = sum(1 for r in raw if r["degenerate"])
    raw = [r for r in raw if not r["degenerate"]]

    out = []
    for r in raw:
        start_t, wide_gap = r["start_t"], r["wide_gap"]
        pred_all = (wide_gap > np.median(wide_gap)).astype(int)
        anchor, _ = D.best_anchor(start_t, wide_gap, n_bits, lsb_first)
        idx, valid, _ = D.assign_indices(start_t, n_bits, anchor=anchor)
        out.append({
            "key_id": key_id,
            "name": r["name"],
            "n_bits": n_bits,
            "alternation": r["alternation"],
            "anchor": anchor,
            "bit_index": idx[valid],
            "pred": pred_all[valid],
            "truth": lsb_first,
        })
    return out, n_degenerate


def vote(traces, n_bits, band=DEFAULT_BAND, order=None):
    """Per-bit vote over a set of decoded traces (RSA_KEY.merge_inference /
    check_accuracy in evaluation/extract_openpgp_rsa.py, adapted to this
    decoder's index/gap representation).

    order: optional sequence of indices into `traces` controlling which/how
    many traces are folded in and in what order (used by runs_required).
    Returns a dict: known, unknown, wrong, obs (traces folded in), coverage,
    known_acc, ppr (per-bit positive rate), tot (per-bit observation count).
    """
    low, high = band
    ones = np.zeros(n_bits, dtype=np.int64)
    tot = np.zeros(n_bits, dtype=np.int64)
    seq = order if order is not None else range(len(traces))
    for i in seq:
        t = traces[i]
        np.add.at(ones, t["bit_index"], t["pred"])
        np.add.at(tot, t["bit_index"], 1)

    observed = tot > 0
    ppr = np.full(n_bits, -1.0)
    ppr[observed] = ones[observed] / tot[observed]

    is_one = ppr >= high
    is_zero = (ppr <= low) & observed
    known = is_one | is_zero
    pred_bit = np.where(is_one, 1, 0)

    truth = traces[0]["truth"] if traces else np.zeros(n_bits, dtype=np.int64)
    wrong = int((known & (pred_bit != truth)).sum())
    known_n = int(known.sum())

    return {
        "obs": len(list(seq)) if order is not None else len(traces),
        "known": known_n,
        "unknown": n_bits - known_n,
        "wrong": wrong,
        "known_acc": (known_n - wrong) / known_n if known_n else None,
        "coverage": known_n / n_bits,
        "ppr": ppr,
        "tot": tot,
    }


def runs_required(traces, n_bits, band=DEFAULT_BAND,
                   target=DEFAULT_TARGET_COVERAGE, repeats=DEFAULT_RUNS_REPEATS,
                   seed=0):
    """Smallest number of runs (shuffled order, repeated) whose vote reaches
    `target` coverage. Returns (values, reached) -- one value per repeat;
    `reached[i]` is False if all traces were used and target was still not
    met, in which case values[i] is len(traces) (a lower bound, not a hit).
    """
    rng = random.Random(seed)
    low, high = band
    n = len(traces)
    values, reached = [], []

    for rep in range(repeats):
        order = list(range(n))
        rng.shuffle(order)
        ones = np.zeros(n_bits, dtype=np.int64)
        tot = np.zeros(n_bits, dtype=np.int64)
        hit_at = None
        for k, i in enumerate(order, start=1):
            t = traces[i]
            np.add.at(ones, t["bit_index"], t["pred"])
            np.add.at(tot, t["bit_index"], 1)
            observed = tot > 0
            ppr = np.full(n_bits, -1.0)
            ppr[observed] = ones[observed] / tot[observed]
            known = (ppr >= high) | ((ppr <= low) & observed)
            if known.sum() / n_bits >= target:
                hit_at = k
                break
        if hit_at is None:
            values.append(n)
            reached.append(False)
        else:
            values.append(hit_at)
            reached.append(True)

    return values, reached


def best_single_trace_accuracy(traces):
    best = 0.0
    for t in traces:
        truth = t["truth"][t["bit_index"]]
        acc = float((t["pred"] == truth).mean()) if len(truth) else 0.0
        best = max(best, acc)
    return best


def rule(title):
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def summarize(label, values):
    a = np.asarray(values, dtype=float)
    print(f"  {label:<28}{'min':>10}{'median':>10}{'max':>10}")
    print(f"  {'':<28}{a.min():>10.4f}{np.median(a):>10.4f}{a.max():>10.4f}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", required=True, help="quickjs_bigint_select_rsa output root")
    ap.add_argument("--runs", type=int, default=None,
                     help="use the KNNN_r<runs> directory per key (default: most runs available)")
    ap.add_argument("--keys", type=int, default=None, help="cap on number of keys (default: all found)")
    ap.add_argument("--band", type=float, nargs=2, default=DEFAULT_BAND, metavar=("LOW", "HIGH"))
    ap.add_argument("--target-coverage", type=float, default=DEFAULT_TARGET_COVERAGE)
    ap.add_argument("--runs-repeats", type=int, default=DEFAULT_RUNS_REPEATS)
    ap.add_argument("--jobs", type=int, default=None)
    ap.add_argument("--out", default=None, help="write per-key CSV summary here")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    key_dirs = find_key_dirs(args.pool, runs=args.runs)
    if not key_dirs:
        print(f"No key directories found under {args.pool}", file=sys.stderr)
        return 1
    key_ids = sorted(key_dirs)
    if args.keys is not None:
        key_ids = key_ids[:args.keys]

    band = tuple(args.band)
    print(f"pool: {args.pool}")
    print(f"keys: {len(key_ids)}  band: [{band[0]}, {band[1]}]  "
          f"target coverage: {args.target_coverage}")

    per_key = {}
    degenerate_by_key = {}
    with cf.ProcessPoolExecutor(max_workers=args.jobs) as ex:
        for key_id in key_ids:
            paths = trace_files(key_dirs[key_id])
            if not paths:
                continue
            print(f"  decoding key {key_id:3d}: {len(paths)} traces ...", flush=True)
            traces, n_degenerate = process_key(key_id, paths, args.jobs, executor=ex)
            per_key[key_id] = traces
            degenerate_by_key[key_id] = n_degenerate
            if n_degenerate:
                print(f"    ({n_degenerate}/{len(paths)} traces dropped: "
                      f"< {MIN_WIDE_PAIRS} wide pairs)")

    total_degenerate = sum(degenerate_by_key.values())
    total_traces = sum(len(trace_files(key_dirs[k])) for k in key_ids)
    if total_degenerate:
        print(f"\ndropped {total_degenerate}/{total_traces} traces pool-wide as "
              f"degenerate (< {MIN_WIDE_PAIRS} wide pairs; see MIN_WIDE_PAIRS)")

    rule("Per-key voted accuracy")
    print("  each trace's anchor is resolved against the known key"
          " (decoder.best_anchor); see the header docstring")
    print(f"{'key':>5}{'traces':>8}{'bits':>7}{'coverage':>11}{'known acc':>11}"
          f"{'wrong':>8}")

    reports = []
    evaluated_key_ids = []
    for key_id in key_ids:
        traces = per_key.get(key_id)
        if not traces:
            continue
        n_bits = traces[0]["n_bits"]
        v = vote(traces, n_bits, band=band)
        reports.append(v)
        evaluated_key_ids.append(key_id)
        acc = f"{v['known_acc']:.4f}" if v["known_acc"] is not None else "  n/a "
        print(f"{key_id:>5}{len(traces):>8}{n_bits:>7}"
              f"{v['coverage']:>11.4f}{acc:>11}{v['wrong']:>8}")

    rule("Pool summary")
    if not reports:
        print("  (no keys decoded)")
    else:
        accs = [r["known_acc"] for r in reports if r["known_acc"] is not None]
        zero_err_keys = sum(1 for r in reports if r["wrong"] == 0)
        print(f"  keys evaluated       : {len(reports)}")
        print(f"  keys with 0 errors   : {zero_err_keys} / {len(reports)}")
        summarize("coverage", [r["coverage"] for r in reports])
        if accs:
            summarize("known-bit accuracy", accs)

    rule(f"Runs required to reach {args.target_coverage:.0%} coverage "
         f"({args.runs_repeats} shuffles/key)")
    print(f"{'key':>5}{'traces':>8}{'runs (min/med/max)':>24}")
    runs_all = []
    unreached = 0
    for key_id in evaluated_key_ids:
        traces = per_key[key_id]
        n_bits = traces[0]["n_bits"]
        values, reached = runs_required(
            traces, n_bits, band=band, target=args.target_coverage,
            repeats=args.runs_repeats, seed=args.seed + key_id)
        runs_all.extend(values)
        unreached += sum(1 for r in reached if not r)
        shown = f"{min(values)}/{int(np.median(values))}/{max(values)}"
        print(f"{key_id:>5}{len(traces):>8}{shown:>24}")

    if runs_all:
        rule("Runs-required summary across keys")
        print(f"  min {min(runs_all)}  median {int(np.median(runs_all))}"
              f"  max {max(runs_all)}"
              f"  ({unreached}/{len(runs_all)} shuffles never reached target"
              f" within the traces available)")

    rule("Voting vs best single trace (REPORT 5.2.5: repetition does not help)")
    print(f"{'key':>5}{'best single':>14}{'voted':>10}{'voted beats best?':>20}")
    beats = 0
    checked = 0
    for key_id in evaluated_key_ids:
        traces = per_key[key_id]
        n_bits = traces[0]["n_bits"]
        best = best_single_trace_accuracy(traces)
        v = vote(traces, n_bits, band=band)
        if v["known_acc"] is None:
            continue
        checked += 1
        wins = v["known_acc"] > best
        beats += int(wins)
        print(f"{key_id:>5}{best:>14.4f}{v['known_acc']:>10.4f}{str(wins):>20}")
    if checked:
        print(f"\n  voting beat the best single trace on {beats}/{checked} keys")

    if args.out:
        with open(args.out, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["key_id", "n_bits", "traces", "band_low", "band_high",
                        "coverage", "known_acc", "wrong"])
            for key_id, v in zip(evaluated_key_ids, reports):
                traces = per_key[key_id]
                w.writerow([key_id, traces[0]["n_bits"], len(traces),
                            band[0], band[1],
                            v["coverage"], v["known_acc"], v["wrong"]])
        print(f"\nwrote {args.out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
