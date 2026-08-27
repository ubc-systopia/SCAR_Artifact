"""Why the attack watches bf_logic_or's line and not bf_logic_and's.

The bf_logic_and line is the more appealing target on paper: nothing else
lives on it, so a trace is exactly the three bf_logic_and calls each modExp
iteration makes (`exp & 1n`, then SELECT's two `&`), against the bf_logic_or
line's mixture of bf_logic_or and bf_rint.

It does not survive the measurement. The A2->A3 gap -- inside SELECT, between
its two `&` calls, the interval closest to the cond-dependent mask arithmetic
-- comes back flat (0.52, chance) on every trace, and its median sits at
~11,800 cycles against a measured floor of ~10,900. That floor is Prime+Scope's
own re-arm time: after a detection the probe must rebuild its eviction set
before it can see anything again. A2->A3 reading at the floor means the two
accesses are actually closer together than the probe can resolve, so what the
trace records there is recovery time, not victim work -- which is why it
carries no bit here. The bit is only visible in intervals that also span a full
modular multiplication, where ~2,200 cycles of signal sit under 3x more jitter.

That gap is not empty, though: it holds `mask - _1n + cond`, and instrumented
QuickJS plus Intel PT put ~+1,523 cycles of bit-dependent cost there -- the
largest single contribution in the iteration. `cond` of 0n has BigInt length 0,
so bf_add_internal takes the zero-operand shortcut (libbf.c:908) and copies;
1n runs bf_resize plus the full limb loop. See EXPLANATION_AND.md §4.1.

(An earlier version of this file cited a specific instrumented-victim figure
for the A2->A3 gap. That measurement came from an LD_PRELOAD interposer whose
own per-call overhead is larger than the effect it was measuring, so the number
is not trustworthy and has been removed; the +1,523 above comes from the
bytecode-handler timing in openpgp_patch/, not from that interposer.)

Run from this directory:  python3 and_line.py
Traces: ../data/traces_and_line (PROBE_LINE=and), ../data/traces (default).
Ground truth is the key's `d`; the exponent is not blinded (OpenPGP.js blinds
the message), so every signature runs the same bit sequence.
"""
import numpy as np

import decoder as D

AND_DIR = D.ROOT / "data" / "traces_and_line"
# Same split as decoder.PAIR_SPLIT_CYCLES: within an iteration the AND accesses
# are ~12k apart, between them lie the two ~300k modular multiplications.
LONG_GAP = D.PAIR_SPLIT_CYCLES


def and_iterations(path):
    """Return (A1, A2, A3, A1_next) timestamps for each complete iteration.

    One iteration touches the line three times:

        A1  bf_logic_and   exp & 1n
        A2  bf_logic_and   SELECT's first &     <- the bit is between
        A3  bf_logic_and   SELECT's second &    <- these two
        A1' next iteration

    A1 is separated from A2 by `exp >>= 1n` and `r*x % n`, and A3 from A1' by
    the `|` and `x*x % n`, so grouping on long gaps yields an alternating
    singleton / pair pattern. Iterations where that pattern is broken (a
    missed or doubled detection) are dropped.
    """
    ts, _ = D.load_trace(path, slot=0)
    lo, hi = D.signing_window(ts)
    ts = ts[(ts >= lo) & (ts <= hi)]

    gaps = np.diff(ts)
    starts = np.concatenate(([0], np.where(gaps >= LONG_GAP)[0] + 1))
    ends = np.concatenate((starts[1:] - 1, [len(ts) - 1]))
    size = ends - starts + 1

    rows = [(ts[starts[k]], ts[starts[k + 1]], ts[ends[k + 1]], ts[starts[k + 2]])
            for k in range(len(size) - 2)
            if size[k] == 1 and size[k + 1] == 2 and size[k + 2] == 1]
    return map(np.array, zip(*rows))


def separability(t, value, bits):
    """Best median-threshold accuracy of `value` against the exponent bits.

    Indices come from the same locked-period model the main decoder uses; the
    anchor (which iteration the first sample belongs to) is scanned, as in
    decoder.best_anchor. This is an upper bound -- the anchor is resolved
    against ground truth -- which is the point: even given the anchor for
    free, the AND intervals do not separate.
    """
    period, offset, _ = D.lock_period(t.astype(float))
    idx = np.round((t - offset) / period).astype(int)
    idx -= idx.min()

    # A trace can span more indices than the exponent has bits (spurious
    # detections stretch idx), so the scan has to allow negative anchors too.
    slack = len(bits) - idx.max()
    best = None
    for anchor in range(min(-20, slack - 20), max(20, slack + 20)):
        i = idx + anchor
        ok = (i >= 0) & (i < len(bits))
        if ok.sum() < 2500:
            continue
        b, x = bits[i[ok]], value[ok]
        acc = (x > np.median(x)).astype(int).__eq__(b).mean()
        acc = max(acc, 1 - acc)
        if best is None or acc > best[0]:
            best = (acc, anchor, ok.sum())

    acc, anchor, n = best
    i = idx + anchor
    ok = (i >= 0) & (i < len(bits))
    b, x = bits[i[ok]], value[ok]
    spread = lambda z: np.percentile(z, 75) - np.percentile(z, 25)

    # Per-bit prediction under this anchor, -1 where the trace has no sample.
    # Orientation (which side of the threshold means 1) is fixed the same way
    # the accuracy is: whichever way round scores better.
    pred = np.full(len(bits), -1, dtype=int)
    call = (x > np.median(x)).astype(int)
    if (call == b).mean() < 0.5:
        call = 1 - call
    pred[i[ok]] = call

    return {
        "acc": acc, "n": n, "pred": pred,
        "med0": np.median(x[b == 0]), "med1": np.median(x[b == 1]),
        "iqr0": spread(x[b == 0]), "iqr1": spread(x[b == 1]),
    }


def report(label, r):
    print(f"  {label:24s} n={r['n']:5d}  acc={r['acc']:.3f}"
          f"  median 0/1 = {r['med0']:>9,.0f} / {r['med1']:>9,.0f}"
          f"  (delta {r['med1'] - r['med0']:+,.0f}, IQR ~{max(r['iqr0'], r['iqr1']):,.0f})")


def main():
    bits, _ = D.load_exponent()

    floor = min(np.diff(D.load_trace(p, slot=0)[0]).min()
                for p in sorted(AND_DIR.glob("*.out")))
    floor = min(floor, min(np.diff(D.load_trace(p)[0]).min()
                           for p in sorted(D.TRACE_DIR.glob("*.out"))))
    print(f"Prime+Scope resolution floor: {floor:,} cycles "
          f"(smallest gap in any trace, either line)")
    print("A2->A3 medians below sit just above that floor: the interval is\n"
          "unresolvable, so the trace records probe recovery, not victim work.\n")

    print("== bf_logic_and line (PROBE_LINE=and) ==")
    preds, accs = [], []
    for path in sorted(AND_DIR.glob("*.out")):
        a1, a2, a3, a1n = and_iterations(path)
        print(f"{path.stem}: {len(a1):,} complete iterations")
        report("A2->A3  inside SELECT", separability(a2, (a3 - a2).astype(float), bits))
        report("A2->A1' SELECT+square", separability(a2, (a1n - a2).astype(float), bits))
        best = separability(a2, (a1n - a1).astype(float), bits)
        report("A1->A1' whole iteration", best)
        preds.append(best["pred"])
        accs.append(best["acc"])

    # Unlike the or line -- where a single trace is already ~99% and voting only
    # dilutes it -- the and line's best interval is ~80%, so there is headroom.
    # This asks whether the errors are independent enough for repetition to buy
    # anything back. Anchors are resolved per trace against ground truth, so
    # this is an upper bound on what a real attacker could vote.
    P = np.array(preds)
    votes = np.where(P < 0, np.nan, P)
    with np.errstate(invalid="ignore"):
        mean_vote = np.nanmean(votes, axis=0)
    covered = ~np.isnan(mean_vote)
    voted = (mean_vote[covered] > 0.5).astype(int)
    vote_acc = (voted == bits[covered]).mean()
    print(f"\n{len(preds)}-trace majority vote on A1->A1':"
          f"  acc={vote_acc:.3f}  coverage={covered.mean():.3f}"
          f"   (best single trace {max(accs):.3f})")

    print("\n== bf_logic_or line (default), for comparison ==")
    for path in sorted(D.TRACE_DIR.glob("*.out")):
        ts, _ = D.load_trace(path)
        start_t, wide_gap, _, alternation = D.wide_narrow(ts)
        print(f"{path.stem}: {len(wide_gap):,} wide pairs, alternation {alternation:.3f}")
        report("wide pair = SELECT", separability(start_t.astype(np.int64), wide_gap, bits))


if __name__ == "__main__":
    main()
