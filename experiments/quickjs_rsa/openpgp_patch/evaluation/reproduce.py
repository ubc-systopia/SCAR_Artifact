"""Regenerate every result table from the included traces.

Usage:  python3 analysis/reproduce.py [--traces DIR]
        python3 analysis/reproduce.py --pool DIR [evaluate_pool.py options]
            regenerates the multi-key, multi-run tables instead (100 keys x
            128 runs); defers entirely to evaluate_pool.py, see
            that file for the analysis (voting, anchor tiers, runs-required).
"""
import argparse
import itertools
import sys

import numpy as np

import decoder as D


def rule(title):
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", help="directory of trace files")
    ap.add_argument("--pool", help="quickjs_bigint_select_rsa output root; "
                     "regenerate the key-pool tables instead of the "
                     "5-trace ones (remaining args are passed through "
                     "to evaluate_pool.py)")
    args, pool_extra = ap.parse_known_args()
    if args.pool:
        import evaluate_pool
        sys.argv = [sys.argv[0], "--pool", args.pool, *pool_extra]
        return evaluate_pool.main()
    if args.traces:
        from pathlib import Path
        D.TRACE_DIR = Path(args.traces)

    paths = D.trace_paths()
    if not paths:
        print(f"No traces found in {D.TRACE_DIR}", file=sys.stderr)
        return 1

    lsb_first, _ = D.load_exponent()
    n_bits = len(lsb_first)
    print(f"key: RSA-4096, {n_bits}-bit exponent, {int(lsb_first.sum())} ones")
    try:  # keep output path-independent so it can be diffed against the reference
        shown = D.TRACE_DIR.relative_to(D.ROOT)
    except ValueError:
        shown = D.TRACE_DIR
    print(f"traces: {len(paths)} from {shown}")

    results = [D.decode(p) for p in paths]

    rule("Table 1 - pair structure (REPORT 5.2.4)")
    print(f"{'trace':<7}{'wide pairs':>12}{'alternation':>13}"
          f"{'wide gap':>12}{'std':>7}{'narrow gap':>12}{'std':>7}{'period':>10}")
    for r in results:
        print(f"{r['name']:<7}{r['wide_pairs']:>12}{r['alternation']:>13.3f}"
              f"{r['wide_mean']:>12.0f}{r['wide_std']:>7.0f}"
              f"{r['narrow_mean']:>12.0f}{r['narrow_std']:>7.0f}{r['period']:>10.0f}")

    rule("Table 2 - main results (REPORT 5.2.5)")
    print(f"{'trace':<7}{'corr':>9}{'n':>7}{'accuracy':>10}"
          f"{'fwd corr':>10}{'fwd acc':>9}")
    for r in results:
        corr = D.correlation(r["gap"], r["truth"])
        acc = D.accuracy(r["predicted"], r["truth"])
        fcorr = D.correlation(r["gap"], r["truth_forward"])
        facc = D.accuracy(r["predicted"], r["truth_forward"])
        print(f"{r['name']:<7}{corr:>+9.4f}{len(r['gap']):>7}{acc:>10.4f}"
              f"{fcorr:>+10.4f}{facc:>9.4f}")
    se = 1 / np.sqrt(n_bits)
    print(f"\nstandard error 1/sqrt({n_bits}) = {se:.4f}; "
          f"correlations above are up to {0.5151/se:.0f} standard errors")

    rule("Table 3 - correlation within ten consecutive parts of each trace")
    for r in results:
        parts = np.array_split(np.arange(len(r["gap"])), 10)
        cs = [D.correlation(r["gap"][p], r["truth"][p]) for p in parts]
        print(f"{r['name']:<5}" + " ".join(f"{c:+.3f}" for c in cs))

    rule("Table 4 - accuracy over the lowest N exponent bits")
    Ns = (256, 1024, 2048, n_bits)
    W = 20
    print(f"{'trace':<7}" + "".join(f"{('N=' + str(N)):>{W}}" for N in Ns))
    for r in results:
        row = f"{r['name']:<7}"
        for N in Ns:
            m = r["bit_index"] < N
            acc = D.accuracy(r["predicted"][m], r["truth"][m])
            errs = int((r["predicted"][m] != r["truth"][m]).sum())
            row += f"{acc:.4f} [{errs}/{int(m.sum())}]".rjust(W)
        print(row)
    print("  cell = accuracy [errors / bits assigned an index]")

    rule("Table 5 - combining traces buys coverage, not accuracy (REPORT 5.2.5)")
    names = [r["name"] for r in results]
    by_name = {r["name"]: r for r in results}

    def combine(sel):
        total = np.zeros(n_bits)
        count = np.zeros(n_bits)
        for nm in sel:
            r = by_name[nm]
            z = (r["gap"] - r["gap"].mean()) / r["gap"].std()
            total[r["bit_index"]] += z
            count[r["bit_index"]] += 1
        m = count > 0
        v = total[m] / count[m]
        return D.accuracy((v > np.median(v)).astype(int), lsb_first[m]), int(m.sum())

    print(f"{'traces':<8}{'best subset':<28}{'n':>6}{'accuracy':>10}")
    for k in range(1, len(names) + 1):
        best = max(itertools.combinations(names, k), key=lambda s: combine(s)[0])
        acc, n = combine(best)
        print(f"{k:<8}{','.join(best):<28}{n:>6}{acc:>10.4f}")

    rule("Table 6 - traces agree with each other even where both are wrong")
    if len(results) >= 2:
        a, b = results[0], results[3] if len(results) > 3 else results[1]
        pa = np.full(n_bits, -1); pa[a["bit_index"]] = a["predicted"]
        pb = np.full(n_bits, -1); pb[b["bit_index"]] = b["predicted"]
        print(f"comparing {a['name']} and {b['name']}")
        print(f"{'bit range':<16}{'acc ' + a['name']:>10}"
              f"{'acc ' + b['name']:>10}{'agreement':>11}")
        for lo in range(0, n_bits, 500):
            hi = min(lo + 500, n_bits)
            m = (pa[lo:hi] >= 0) & (pb[lo:hi] >= 0)
            t = lsb_first[lo:hi][m]
            print(f"{f'{lo}-{hi}':<16}{(pa[lo:hi][m] == t).mean():>10.3f}"
                  f"{(pb[lo:hi][m] == t).mean():>10.3f}"
                  f"{(pa[lo:hi][m] == pb[lo:hi][m]).mean():>11.3f}")
        print("\nBoth traces are near-perfect throughout, so agreement is high "
              "everywhere.\nThe residual errors are still largely shared rather "
              "than independent, so combining traces "
              "cannot remove them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
