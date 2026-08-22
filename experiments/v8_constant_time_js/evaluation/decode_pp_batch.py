#!/usr/bin/env python3
"""Decode a whole run_pp_batch.sh dataset and reduce it to per-key statistics.

Runs extract_v8_ct_ecdh.py once per key, parses its vote line, and reports the
minimum, median and maximum accuracy of the classified bits with the coverage
of those same decodes. One capture takes ~2 min to decode and is
single-threaded, hence the process pool.

  usage: decode_pp_batch.py [--tag T] [--runs N] [--keys N] [--jobs N]
                            [--csv PATH] [-- extract flags...]
"""
import argparse
import concurrent.futures
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

VOTE_RE = re.compile(
    r"known\s+(\d+)\s+\(\s*([\d.]+)%\)\s*\|\s*unknown\s+(\d+)\s+\(\s*([\d.]+)%\)"
    r"\s*\|\s*wrong\s+(\d+)\s*\|\s*known-acc\s+(None|[\d.]+)\s*\|\s*(\d+) traces")


def decode(key, capture, python, extra=()):
    p = subprocess.run(
        [python, EXTRACT, "-d", capture,
         "--key", os.path.join(POOL, f"ec_key_{key}.json"), *extra],
        capture_output=True, text=True)
    m = VOTE_RE.search(p.stdout)
    if not m:
        why = "no traces decoded" if "No traces decoded" in p.stdout else "no vote line"
        return {"key": key, "ok": False, "why": why}
    known, known_pct, unknown, _, wrong, acc, traces = m.groups()
    return {"key": key, "ok": True, "known": int(known), "unknown": int(unknown),
            "wrong": int(wrong), "traces": int(traces),
            # A vote that could not fit its model falls back to the fixed band
            # and labels every bit: a failed decode, not a weak one.
            "fallback": "fixed band" in p.stdout,
            "coverage": float(known_pct),
            "known_acc": None if acc == "None" else float(acc)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output-dir", default=OUT)
    ap.add_argument("--tag", default="pp_paper")
    ap.add_argument("--runs", type=int, default=100)
    ap.add_argument("--keys", type=int, default=100)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--csv", default=os.path.join(OUT, "pp_batch_results.csv"))
    ap.add_argument("extra", nargs="*", help="flags passed to extract_v8_ct_ecdh.py")
    args = ap.parse_args()

    todo = []
    for k in range(args.keys):
        d = os.path.join(args.output_dir, f"{args.tag}_k{k}_r{args.runs:05d}")
        if os.path.isdir(d):
            todo.append((k, d))
        else:
            print(f"key {k}: no capture at {d}", file=sys.stderr)

    results = []
    with concurrent.futures.ProcessPoolExecutor(args.jobs) as pool:
        futs = [pool.submit(decode, k, d, args.python, tuple(args.extra))
                for k, d in todo]
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            results.append(r)
            if r["ok"]:
                acc = "  none" if r["known_acc"] is None else f"{r['known_acc']:.5f}"
                print(f"key {r['key']:>3}: known {r['known']:>3} "
                      f"({r['coverage']:6.2f}%) wrong {r['wrong']:>3} "
                      f"known-acc {acc}"
                      f"{'  [band fallback]' if r['fallback'] else ''}", flush=True)
            else:
                print(f"key {r['key']:>3}: FAILED ({r['why']})", flush=True)
    results.sort(key=lambda r: r["key"])

    os.makedirs(os.path.dirname(os.path.abspath(args.csv)), exist_ok=True)
    with open(args.csv, "w") as fp:
        fp.write("key,ok,known,unknown,wrong,coverage_pct,known_acc,traces,fallback\n")
        for r in results:
            if not r["ok"]:
                fp.write(f"{r['key']},0,,,,,,,\n")
                continue
            acc = "" if r["known_acc"] is None else f"{r['known_acc']:.5f}"
            fp.write(f"{r['key']},1,{r['known']},{r['unknown']},{r['wrong']},"
                     f"{r['coverage']:.2f},{acc},{r['traces']},{int(r['fallback'])}\n")

    good = [r for r in results if r["ok"] and r["known_acc"] is not None]
    if not good:
        print("\nno key decoded", file=sys.stderr)
        return 1
    acc = sorted(r["known_acc"] for r in good)
    cov = sorted(r["coverage"] for r in good)
    print(f"\n{len(good)}/{len(results)} keys decoded  ->  {args.csv}")
    print(f"  known-bit accuracy  min {100 * acc[0]:.1f}%  "
          f"median {100 * statistics.median(acc):.1f}%  max {100 * acc[-1]:.1f}%")
    print(f"  coverage of all bits min {cov[0]:.1f}%  "
          f"median {statistics.median(cov):.1f}%  max {cov[-1]:.1f}%")
    # The paper pairs each accuracy with the coverage of the SAME key.
    by_acc = sorted(good, key=lambda r: r["known_acc"])
    med = by_acc[len(by_acc) // 2]
    print(f"  paired (acc, coverage): min key {by_acc[0]['key']} "
          f"({100 * by_acc[0]['known_acc']:.1f}%, {by_acc[0]['coverage']:.1f}%)  "
          f"median key {med['key']} "
          f"({100 * med['known_acc']:.1f}%, {med['coverage']:.1f}%)  "
          f"max key {by_acc[-1]['key']} "
          f"({100 * by_acc[-1]['known_acc']:.1f}%, {by_acc[-1]['coverage']:.1f}%)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
