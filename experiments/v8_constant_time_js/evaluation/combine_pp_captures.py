#!/usr/bin/env python3
"""Combine several independent captures of the same key into one decode.

A key whose single capture lands near chance cannot be spotted from that
capture alone (coverage correlates with accuracy at r=0.36, the fitted
response amplitude at r=-0.19). Repeating the capture does spot it: a capture
decoding noise disagrees with the others almost everywhere, so keeping only
the bits they agree on sends its errors to unknown instead of out wrong.

Rules, applied to the captures that classified a given bit:
  agree     all of them say the same thing
  majority  strictly more than half do
Both need --min-votes captures to have classified it at all.

  usage: combine_pp_captures.py [--tags T,T,T] [--rule agree|majority]
                                [--min-votes N] [--runs N] [--keys N]
                                [--jobs N] [--csv PATH] [extract flags...]
"""
import argparse
import collections
import concurrent.futures
import csv
import os
import re
import statistics
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
EXTRACT = os.path.join(HERE, "extract_v8_ct_ecdh.py")
POOL = os.path.join(ROOT, "experiments", "v8_ecdh", "ec_key_pool")
OUT = os.path.join(ROOT, "build", "experiments", "v8_constant_time_js", "output")

# print_key_comparison pads "real :" to line up with "infer:".
ROW_RE = re.compile(r"^\s*\[\s*\d+\] (real|infer)\s*: ([01u]+)\s*$")


def decode_bits(key, capture, python, extra):
    """(true bits, predicted bits over {0,1,u}), or (None, None) if no decode."""
    p = subprocess.run(
        [python, EXTRACT, "-d", capture,
         "--key", os.path.join(POOL, f"ec_key_{key}.json"), *extra],
        capture_output=True, text=True)
    true_bits, pred = [], []
    for line in p.stdout.splitlines():
        m = ROW_RE.match(line)
        if m:
            (true_bits if m.group(1) == "real" else pred).append(m.group(2))
    # A fixed-band fallback is near-constant, so it agrees with whatever the
    # others say on one of the two values. Treat it as no decode.
    if not pred or "fixed band" in p.stdout:
        return None, None
    return "".join(true_bits), "".join(pred)


def merge(preds, rule, min_votes):
    out = []
    for votes in zip(*preds):
        cast = [v for v in votes if v != "u"]
        if len(cast) < min_votes:
            out.append("u")
            continue
        top, n = collections.Counter(cast).most_common(1)[0]
        ok = n == len(cast) if rule == "agree" else n * 2 > len(cast)
        out.append(top if ok else "u")
    return "".join(out)


def score(true_bits, pred):
    known = sum(1 for b in pred if b != "u")
    wrong = sum(1 for t, b in zip(true_bits, pred) if b != "u" and b != t)
    return {"known": known, "wrong": wrong, "nbits": len(pred),
            "coverage": 100.0 * known / len(pred),
            "acc": None if not known else (known - wrong) / known}


def one_key(key, python, tags, runs, extra, rule, min_votes):
    caps = [os.path.join(OUT, f"{t}_k{key}_r{runs:05d}") for t in tags]
    if not all(os.path.isdir(c) for c in caps):
        return {"key": key, "ok": False}
    decoded = [decode_bits(key, c, python, extra) for c in caps]
    usable = [(t, p) for t, p in decoded if p is not None]
    if len(usable) < min_votes:
        return {"key": key, "ok": False}
    if len({t for t, _ in usable}) != 1 or len({len(p) for _, p in usable}) != 1:
        return {"key": key, "ok": False}
    true_bits = usable[0][0]
    preds = [p for _, p in usable]
    # Padded back to one entry per tag so the CSV columns match --tags.
    it = iter(preds)
    each = [score(true_bits, next(it)) if p is not None else None
            for _, p in decoded]
    return {"key": key, "ok": True, "each": each,
            "both": score(true_bits, merge(preds, rule, min_votes))}


def summarise(label, stats):
    good = [s for s in stats if s["acc"] is not None]
    if not good:
        print(f"  {label}: no key classified a bit")
        return
    acc = sorted(100 * s["acc"] for s in good)
    cov = sorted(s["coverage"] for s in good)
    print(f"  {label}: {len(good)} keys | accuracy min {acc[0]:.1f}% "
          f"median {statistics.median(acc):.1f}% max {acc[-1]:.1f}% "
          f"| coverage min {cov[0]:.1f}% median {statistics.median(cov):.1f}% "
          f"max {cov[-1]:.1f}%")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tags", default="pp_paper,pp_paper2")
    ap.add_argument("--rule", choices=("agree", "majority"), default="agree")
    ap.add_argument("--min-votes", type=int, default=2)
    ap.add_argument("--runs", type=int, default=100)
    ap.add_argument("--keys", type=int, default=100)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--csv", default=os.path.join(OUT, "pp_combined_results.csv"))
    ap.add_argument("extra", nargs="*")
    args = ap.parse_args()

    tags = [t for t in args.tags.split(",") if t]
    results = []
    with concurrent.futures.ProcessPoolExecutor(args.jobs) as pool:
        futs = [pool.submit(one_key, k, args.python, tags, args.runs,
                            tuple(args.extra), args.rule, args.min_votes)
                for k in range(args.keys)]
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            results.append(r)
            if r["ok"]:
                s = r["both"]
                a = "  none" if s["acc"] is None else f"{100 * s['acc']:5.1f}%"
                print(f"key {r['key']:>3}: kept {s['known']:>3}/{s['nbits']} "
                      f"({s['coverage']:5.1f}%) wrong {s['wrong']:>3} acc {a}",
                      flush=True)
            else:
                print(f"key {r['key']:>3}: skipped", flush=True)
    results.sort(key=lambda r: r["key"])

    os.makedirs(os.path.dirname(os.path.abspath(args.csv)), exist_ok=True)
    with open(args.csv, "w", newline="") as fp:
        w = csv.writer(fp)
        head = ["key"]
        for t in tags + ["combined"]:
            head += [f"{t}_known", f"{t}_wrong", f"{t}_cov", f"{t}_acc"]
        w.writerow(head)
        for r in results:
            if not r["ok"]:
                w.writerow([r["key"]] + [""] * (4 * (len(tags) + 1)))
                continue
            row = [r["key"]]
            for s in r["each"] + [r["both"]]:
                if s is None:
                    row += ["", "", "", ""]
                else:
                    row += [s["known"], s["wrong"], f"{s['coverage']:.2f}",
                            "" if s["acc"] is None else f"{s['acc']:.5f}"]
            w.writerow(row)

    ok = [r for r in results if r["ok"]]
    print(f"\n{len(ok)}/{len(results)} keys have every capture  ->  {args.csv}")
    for i, t in enumerate(tags):
        summarise(f"capture {t}", [r["each"][i] for r in ok if r["each"][i]])
    summarise(f"combined ({args.rule}, min {args.min_votes})",
              [r["both"] for r in ok])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
