"""Check the decoder against the numbers published in REPORT.md.

Exits non-zero if any published value is not reproduced. Correlations and
accuracies must match to within 0.001; counts must match exactly.

Usage:  python3 analysis/verify.py
"""
import sys

import numpy as np

import decoder as D

# (trace, wide_pairs, alternation, correlation, n, accuracy)
EXPECTED = [
    ("r0", 4023, 0.982, +0.4994, 3989, 0.7766),
    ("r1", 3988, 0.979, +0.4242, 3967, 0.7373),
    ("r2", 3987, 0.975, +0.0746, 3960, 0.5566),
    ("r3", 4008, 0.977, +0.5151, 3967, 0.7751),
    ("r4", 4024, 0.979, +0.0417, 3988, 0.5238),
]

# Errors among the lowest 2048 exponent bits, and bits assigned an index.
EXPECTED_LOW = {"r0": (16, 1995), "r1": (65, 1972), "r3": (21, 1985)}

TOL = 1e-3
failures = []


def check(label, got, want, tol=TOL):
    ok = abs(got - want) <= tol if tol else got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label:<34} got {got!r:<10} want {want!r}")
    if not ok:
        failures.append(label)


def main():
    paths = D.trace_paths()
    print(f"traces: {len(paths)} in {D.TRACE_DIR}")
    if len(paths) != len(EXPECTED):
        print(f"FAIL: expected {len(EXPECTED)} traces, found {len(paths)}")
        return 1

    lsb_first = D.load_exponent()
    print(f"exponent: {len(lsb_first)} bits, {int(lsb_first.sum())} ones")
    if len(lsb_first) != 4094:
        print("FAIL: exponent is not 4094 bits")
        return 1

    results = {}
    for path, exp in zip(paths, EXPECTED):
        name, pairs, alt, corr, n, acc = exp
        r = D.decode(path)
        results[name] = r
        print(f"\n{name}:")
        check(f"{name} wide pairs", r["wide_pairs"], pairs, tol=0)
        check(f"{name} alternation", r["alternation"], alt, tol=5e-4)
        check(f"{name} correlation", D.correlation(r["gap"], r["truth"]), corr)
        check(f"{name} bits assigned", len(r["gap"]), n, tol=0)
        check(f"{name} accuracy", D.accuracy(r["predicted"], r["truth"]), acc)

        fcorr = D.correlation(r["gap"], r["truth_forward"])
        facc = D.accuracy(r["predicted"], r["truth_forward"])
        ok = abs(fcorr) < 0.05 and 0.45 < facc < 0.55
        print(f"  {'PASS' if ok else 'FAIL'}  {name} forward-order control       "
              f"corr {fcorr:+.4f}, acc {facc:.4f} (must be chance)")
        if not ok:
            failures.append(f"{name} forward control")

    print("\nlowest 2048 exponent bits:")
    for name, (errs, bits) in EXPECTED_LOW.items():
        r = results[name]
        m = r["bit_index"] < 2048
        check(f"{name} errors in low 2048",
              int((r["predicted"][m] != r["truth"][m]).sum()), errs, tol=0)
        check(f"{name} bits in low 2048", int(m.sum()), bits, tol=0)

    print("\nnarrow group carries less variance than wide (control):")
    for name, r in results.items():
        ok = r["narrow_std"] < r["wide_std"]
        print(f"  {'PASS' if ok else 'FAIL'}  {name} narrow std {r['narrow_std']:.0f}"
              f" < wide std {r['wide_std']:.0f}")
        if not ok:
            failures.append(f"{name} narrow/wide variance")

    print("\ncombining traces does not beat the best single trace:")
    best_single = max(D.accuracy(r["predicted"], r["truth"]) for r in results.values())
    total = np.zeros(4094); count = np.zeros(4094)
    for r in results.values():
        z = (r["gap"] - r["gap"].mean()) / r["gap"].std()
        total[r["bit_index"]] += z
        count[r["bit_index"]] += 1
    m = count > 0
    v = total[m] / count[m]
    vote = D.accuracy((v > np.median(v)).astype(int), lsb_first[m])
    ok = vote <= best_single
    print(f"  {'PASS' if ok else 'FAIL'}  5-trace vote {vote:.4f} <= "
          f"best single {best_single:.4f}")
    if not ok:
        failures.append("vote does not beat single")

    print("\n" + "=" * 60)
    if failures:
        print(f"FAILED: {len(failures)} check(s): {', '.join(failures)}")
        return 1
    print("All checks passed. REPORT.md numbers reproduced.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
