"""Build a one-trace-per-key pool from a full key-pool collection.

The pool run records 128 traces per key. evaluate_pool.py's headline numbers
take the best of those 128 per key, which answers "can the attack recover this
key?". This builds the other dataset: one trace per key, chosen uniformly at
random, which answers "what does a single-shot attacker get?".

Output is a directory of symlinks in evaluate_pool.py's expected layout
(quickjs_select_rsa_ps_key<NNNNN>_r00001/), plus MANIFEST.txt recording the
seed and which trace each key drew, so a run is reproducible.

    python3 make_one_trace_pool.py --pool SRC --out DST [--seed N]
"""
import argparse
import os
import random
import re
import shutil
from pathlib import Path

KEY_DIR_RE = re.compile(r"quickjs_select_rsa_ps_key(\d+)_r(\d+)$")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", required=True, help="quickjs_select_rsa_ps output root")
    ap.add_argument("--out", required=True, help="directory to create (overwritten)")
    ap.add_argument("--seed", type=int, default=20260821)
    args = ap.parse_args()

    # Several r-counts can exist per key (pilot runs alongside the full one);
    # draw from the largest, and ignore the degenerate_backup_* directories.
    best = {}
    for d in Path(args.pool).iterdir():
        m = KEY_DIR_RE.match(d.name) if d.is_dir() else None
        if m:
            key_id, runs = int(m.group(1)), int(m.group(2))
            if runs > best.get(key_id, (0, None))[0]:
                best[key_id] = (runs, d)

    out = Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    rng = random.Random(args.seed)
    lines = [f"seed={args.seed}", f"source={Path(args.pool).resolve()}"]
    for key_id in sorted(best):
        traces = sorted(best[key_id][1].glob("r*.out*"))
        if not traces:
            continue
        pick = rng.choice(traces)
        dst = out / f"quickjs_select_rsa_ps_key{key_id:05d}_r00001"
        dst.mkdir()
        os.symlink(pick.resolve(), dst / pick.name)
        lines.append(f"{key_id:05d} {pick.name}")

    (out / "MANIFEST.txt").write_text("\n".join(lines) + "\n")
    print(f"{len(lines) - 2} keys, one trace each -> {out}")


if __name__ == "__main__":
    main()
