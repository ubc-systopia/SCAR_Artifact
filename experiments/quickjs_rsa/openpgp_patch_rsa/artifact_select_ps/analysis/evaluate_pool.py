"""Comprehensive key-pool evaluation for the SELECT-patch Prime+Scope attack.

Extends the single-key, five-trace evaluation of reproduce.py/REPORT.md 5.2.5
to many keys and many runs per key, in the shape of the section 5.1 key-pool
result (evaluation/extract_openpgp_rsa.py): per-bit voting across repeated
runs with a confidence band, bits outside the band marked unknown, and
coverage / runs-required statistics reported as min/median/max across keys.

Two things differ from that reference on purpose, and are reported rather
than hidden:

  - the decoder needs one more piece of information per trace than section
    5.1's does: which loop iteration the first recovered pair belongs to (the
    "anchor", decoder.assign_indices). Cross-trace consensus recovers this
    correctly *up to one integer shared by the whole key* -- see
    decoder.blind_anchors. Every table below is reported once under that
    blind procedure (the honest, no-oracle number) and once under
    decoder.best_anchor, which resolves the anchor from the known exponent
    and is reported only as an upper bound on what a resolved anchor buys.

  - REPORT.md 5.2.5 already found that repeating the attack does not improve
    it on 5 traces of one key, because the errors are shared rather than
    independent. This script's per-key voting will most likely reproduce
    that finding at pool scale; §"voting vs best single trace" below checks
    it directly instead of assuming it.

Usage:
    python3 evaluate_pool.py --pool DIR [--runs N] [--band LOW HIGH]
                              [--jobs N] [--out CSV]

DIR is the quickjs_select_rsa_ps output root, holding one subdirectory per
key: quickjs_select_rsa_ps_key<NNNNN>_r<RRRRR>/r*.out[.gz].
"""
import os

# Must be set before numpy is imported (and before worker processes are
# forked, which inherit the environment): decoder.lock_period's period scan
# is single-threaded numpy work, but OpenBLAS defaults to spawning up to 64
# threads per process regardless. With --jobs worker processes each doing
# that, the pinned cores are oversubscribed several times over and wall time
# roughly doubles for no benefit -- there's no matrix work here big enough
# for BLAS threading to help. One thread per process, --jobs processes, is
# the actual parallelism this script wants.
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

KEY_DIR_RE = re.compile(r"quickjs_select_rsa_ps_key(\d+)_r(\d+)$")


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
# -- some transient recording problem, not a slow trace. lock_period's period
# scan (np.diff/np.linalg.lstsq on too few points) turns that into NaN rather
# than an error, which then propagates silently into garbage anchors/votes.
# Traces this thin can't support a period fit at all, so they're dropped
# before lock_period ever sees them.
MIN_WIDE_PAIRS = 100


def _process_trace(path):
    """Worker: everything about one trace that doesn't depend on other
    traces of the same key -- this is the expensive step (lock_period's
    period scan), so it's the unit of parallelism."""
    ts, _ = D.load_trace(path)
    start_t, wide_gap, narrow_gap, alternation = D.wide_narrow(ts)
    name = path.name.split(".")[0]
    if len(start_t) < MIN_WIDE_PAIRS:
        return {
            "name": name, "start_t": start_t, "wide_gap": wide_gap,
            "alternation": alternation, "period": float("nan"),
            "lock_magnitude": 0.0, "degenerate": True,
        }
    period, offset, lock_mag = D.lock_period(start_t)
    return {
        "name": name,
        "start_t": start_t,
        "wide_gap": wide_gap,
        "alternation": alternation,
        "period": period,
        "offset": offset,
        "lock_magnitude": lock_mag,
        "degenerate": False,
    }


def process_key(key_id, paths, jobs, executor=None):
    """Decode every trace of one key. Returns (list of per-trace dicts, each
    carrying both the blind (no-oracle) and oracle-anchor decodings; count of
    traces dropped as degenerate, see MIN_WIDE_PAIRS)."""
    lsb_first, _ = D.load_exponent(key_id)
    n_bits = len(lsb_first)

    if executor is not None:
        raw = list(executor.map(_process_trace, paths))
    else:
        raw = [_process_trace(p) for p in paths]

    n_degenerate = sum(1 for r in raw if r["degenerate"])
    raw = [r for r in raw if not r["degenerate"]]
    if not raw:
        return [], n_degenerate

    # lock_period's cache is keyed by the timestamp array's bytes, but that
    # cache lives in whichever process computed it -- the worker, not this
    # one. Without seeding it here, every call below that touches lock_period
    # (blind_anchors picking a reference, best_anchor's per-candidate scan)
    # would silently redo the ~13s period fit from scratch, serially, once
    # per trace: parallel decoding in the workers, then all of it thrown away
    # and repeated single-threaded in the parent.
    for r in raw:
        D._LOCK_CACHE[r["start_t"].tobytes()] = (
            r["period"], r["offset"], r["lock_magnitude"])

    triples = [(r["name"], r["start_t"], r["wide_gap"]) for r in raw]
    blind_anchor, blind_diag = D.blind_anchors(triples, n_bits)

    out = []
    for r in raw:
        name, start_t, wide_gap = r["name"], r["start_t"], r["wide_gap"]
        pred_all = (wide_gap > np.median(wide_gap)).astype(int)

        b_anchor = blind_anchor.get(name, 0)
        b_idx, b_valid, _ = D.assign_indices(start_t, n_bits, anchor=b_anchor)

        o_anchor, _ = D.best_anchor(start_t, wide_gap, n_bits, lsb_first)
        o_idx, o_valid, _ = D.assign_indices(start_t, n_bits, anchor=o_anchor)

        out.append({
            "key_id": key_id,
            "name": name,
            "n_bits": n_bits,
            "alternation": r["alternation"],
            "lock_magnitude": r["lock_magnitude"],
            "blind_anchor": b_anchor,
            "blind_agreement": blind_diag.get(name, (float("nan"), 0))[0],
            "blind_bit_index": b_idx[b_valid],
            "blind_pred": pred_all[b_valid],
            "oracle_anchor": o_anchor,
            "oracle_bit_index": o_idx[o_valid],
            "oracle_pred": pred_all[o_valid],
            "truth": lsb_first,
        })
    return out, n_degenerate


def vote(traces, n_bits, bit_index_key, pred_key, band=DEFAULT_BAND, order=None):
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
        idx = t[bit_index_key]
        pred = t[pred_key]
        np.add.at(ones, idx, pred)
        np.add.at(tot, idx, 1)

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


def runs_required(traces, n_bits, bit_index_key, pred_key, band=DEFAULT_BAND,
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
            np.add.at(ones, t[bit_index_key], t[pred_key])
            np.add.at(tot, t[bit_index_key], 1)
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


def resolve_group_shift(traces, n_bits, band=DEFAULT_BAND, span=2):
    """Search the one integer shared by every trace's blind anchor that the
    group itself cannot determine (decoder.blind_anchors: cross-trace
    agreement fixes every *relative* shift, not the group's shared absolute
    offset). A real attacker resolves this the way partial-key-exposure
    attacks always do: try the handful of candidate keys the shift implies
    against a known signature, an O(span) check per key rather than per
    trace. Here, without a signature to check against, ground truth stands
    in for that oracle -- this is a materially cheaper use of it than
    best_anchor's per-trace search, and the distinction is the point: it
    isolates the one bit of information blind consensus is missing.

    Shifting every trace's already-deduplicated blind_bit_index by a
    constant keeps each trace's indices unique (dedup was per-trace), so the
    shift can be applied directly without re-running assign_indices.

    Returns (delta, vote_result, shifted_traces). shifted_traces carries
    "shift_bit_index"/"shift_pred" per trace at the winning delta, for
    reuse by runs_required / best_single_trace_accuracy.
    """
    truth = traces[0]["truth"]

    def apply(delta):
        shifted = []
        for t in traces:
            idx = t["blind_bit_index"] + delta
            keep = (idx >= 0) & (idx < n_bits)
            shifted.append({
                "shift_bit_index": idx[keep],
                "shift_pred": t["blind_pred"][keep],
                "truth": truth,
            })
        return shifted

    best = None
    for delta in range(-span, span + 1):
        shifted = apply(delta)
        v = vote(shifted, n_bits, "shift_bit_index", "shift_pred", band=band)
        if v["known_acc"] is None:
            continue
        if best is None or v["known_acc"] > best[1]["known_acc"]:
            best = (delta, v, shifted)
    return best if best is not None else (0, vote(apply(0), n_bits,
                                                    "shift_bit_index", "shift_pred",
                                                    band=band), apply(0))


def best_single_trace_accuracy(traces, bit_index_key, pred_key):
    best = 0.0
    for t in traces:
        truth = t["truth"][t[bit_index_key]]
        acc = float((t[pred_key] == truth).mean()) if len(truth) else 0.0
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
    ap.add_argument("--pool", required=True, help="quickjs_select_rsa_ps output root")
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

    rule("Per-key voted accuracy: three anchor tiers (see header docstring)")
    print("  blind        = cross-trace consensus only, no oracle at all")
    print("  blind+shift  = blind, plus one shared integer resolved per key"
          " (stands in for a signature check)")
    print("  oracle       = every trace's anchor resolved individually against"
          " the known key -- upper bound")
    print(f"{'key':>5}{'traces':>8}{'bits':>7}"
          f"{'blind cov':>11}{'blind acc':>11}"
          f"{'+shift cov':>12}{'+shift acc':>12}"
          f"{'oracle cov':>12}{'oracle acc':>12}")

    blind_reports, shift_reports, oracle_reports = [], [], []
    shifted_traces_by_key = {}
    evaluated_key_ids = []
    for key_id in key_ids:
        traces = per_key.get(key_id)
        if not traces:
            continue
        n_bits = traces[0]["n_bits"]
        b = vote(traces, n_bits, "blind_bit_index", "blind_pred", band=band)
        _, s, shifted = resolve_group_shift(traces, n_bits, band=band)
        o = vote(traces, n_bits, "oracle_bit_index", "oracle_pred", band=band)
        blind_reports.append(b)
        shift_reports.append(s)
        oracle_reports.append(o)
        shifted_traces_by_key[key_id] = shifted
        evaluated_key_ids.append(key_id)
        bacc = f"{b['known_acc']:.4f}" if b["known_acc"] is not None else "  n/a "
        sacc = f"{s['known_acc']:.4f}" if s["known_acc"] is not None else "  n/a "
        oacc = f"{o['known_acc']:.4f}" if o["known_acc"] is not None else "  n/a "
        print(f"{key_id:>5}{len(traces):>8}{n_bits:>7}"
              f"{b['coverage']:>11.4f}{bacc:>11}"
              f"{s['coverage']:>12.4f}{sacc:>12}"
              f"{o['coverage']:>12.4f}{oacc:>12}")

    def report_tier(title, reports):
        rule(title)
        if not reports:
            print("  (no keys decoded)")
            return
        covs = [r["coverage"] for r in reports]
        accs = [r["known_acc"] for r in reports if r["known_acc"] is not None]
        zero_err_keys = sum(1 for r in reports if r["wrong"] == 0)
        print(f"  keys evaluated       : {len(reports)}")
        print(f"  keys with 0 errors   : {zero_err_keys} / {len(reports)}")
        summarize("coverage", covs)
        if accs:
            summarize("known-bit accuracy", accs)

    report_tier("Pool summary -- blind (no oracle at all)", blind_reports)
    report_tier("Pool summary -- blind + resolved group shift", shift_reports)
    report_tier("Pool summary -- oracle anchor (upper bound)", oracle_reports)

    # Pure blind (no oracle at all) is near chance -- see the pool summary
    # above -- because the group's shared absolute anchor offset is
    # unresolved, not because more votes help less. Neither runs-required
    # nor "does voting help" is informative measured against chance, so both
    # use the +shift tier (one resolved integer per key) and the oracle tier
    # (resolved per trace) instead.
    rule(f"Runs required to reach {args.target_coverage:.0%} coverage "
         f"({args.runs_repeats} shuffles/key) -- +shift and oracle tiers")
    print(f"{'key':>5}{'traces':>8}{'+shift runs (min/med/max)':>28}"
          f"{'oracle runs (min/med/max)':>28}")
    shift_runs_all, oracle_runs_all = [], []
    shift_unreached, oracle_unreached = 0, 0
    for key_id in key_ids:
        traces = per_key.get(key_id)
        shifted = shifted_traces_by_key.get(key_id)
        if not traces or not shifted:
            continue
        n_bits = traces[0]["n_bits"]
        sv, sr = runs_required(shifted, n_bits, "shift_bit_index", "shift_pred",
                                band=band, target=args.target_coverage,
                                repeats=args.runs_repeats, seed=args.seed + key_id)
        ov, orr = runs_required(traces, n_bits, "oracle_bit_index", "oracle_pred",
                                 band=band, target=args.target_coverage,
                                 repeats=args.runs_repeats, seed=args.seed + key_id)
        shift_runs_all.extend(sv)
        oracle_runs_all.extend(ov)
        shift_unreached += sum(1 for r in sr if not r)
        oracle_unreached += sum(1 for r in orr if not r)
        sstr = f"{min(sv)}/{int(np.median(sv))}/{max(sv)}"
        ostr = f"{min(ov)}/{int(np.median(ov))}/{max(ov)}"
        print(f"{key_id:>5}{len(traces):>8}{sstr:>28}{ostr:>28}")

    if shift_runs_all:
        rule("Runs-required summary across keys")
        print(f"  +shift: min {min(shift_runs_all)}  median {int(np.median(shift_runs_all))}"
              f"  max {max(shift_runs_all)}"
              f"  ({shift_unreached}/{len(shift_runs_all)} shuffles never reached target"
              f" within the traces available)")
        print(f"  oracle: min {min(oracle_runs_all)}  median {int(np.median(oracle_runs_all))}"
              f"  max {max(oracle_runs_all)}"
              f"  ({oracle_unreached}/{len(oracle_runs_all)} shuffles never reached target"
              f" within the traces available)")

    rule("Voting vs best single trace (REPORT 5.2.5: repetition does not help) -- +shift tier")
    print(f"{'key':>5}{'best single (+shift)':>22}{'voted (+shift)':>16}{'voted beats best?':>20}")
    beats = 0
    checked = 0
    for key_id in key_ids:
        shifted = shifted_traces_by_key.get(key_id)
        if not shifted:
            continue
        n_bits = per_key[key_id][0]["n_bits"]
        best = best_single_trace_accuracy(shifted, "shift_bit_index", "shift_pred")
        s = vote(shifted, n_bits, "shift_bit_index", "shift_pred", band=band)
        if s["known_acc"] is None:
            continue
        checked += 1
        wins = s["known_acc"] > best
        beats += int(wins)
        print(f"{key_id:>5}{best:>22.4f}{s['known_acc']:>16.4f}{str(wins):>20}")
    if checked:
        print(f"\n  voting beat the best single trace on {beats}/{checked} keys")

    if args.out:
        with open(args.out, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["key_id", "n_bits", "traces", "band_low", "band_high",
                        "blind_coverage", "blind_known_acc", "blind_wrong",
                        "shift_coverage", "shift_known_acc", "shift_wrong",
                        "oracle_coverage", "oracle_known_acc", "oracle_wrong"])
            for key_id, b, s, o in zip(evaluated_key_ids, blind_reports,
                                        shift_reports, oracle_reports):
                traces = per_key[key_id]
                w.writerow([key_id, traces[0]["n_bits"], len(traces), band[0], band[1],
                            b["coverage"], b["known_acc"], b["wrong"],
                            s["coverage"], s["known_acc"], s["wrong"],
                            o["coverage"], o["known_acc"], o["wrong"]])
        print(f"\nwrote {args.out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
