#!/usr/bin/env python3
"""Accept or reject a v8_ctjs_ecdh capture from its two channels' hit counts.

Usable eviction sets are decided per LAUNCH, and a launch whose set shares a
cache set with a hot line decodes at chance. Expected rates per derive: clock
(NegateHandler, once per select_ints, 4 per scalar bit) ~4x246, marker
(BitwiseAndHandler slow path) ~390. Bands below were measured against captures
whose decode accuracy is known -- inside them a capture can still decode
poorly, outside them it never decodes at all.

  usage: capture_health.py <capture-dir>   (exit 0 if healthy)
"""
import argparse
import glob
import os
import statistics
import sys


def channel_counts(path):
    marker = clock = 0
    with open(path) as fp:
        for line in fp:
            for i, cell in enumerate(line.rstrip("\n").split("\t")[:2]):
                ts, _, lat = cell.partition(":")
                if lat and ts.isdigit() and ts != "0":  # 0:0 is padding
                    if i == 0:
                        marker += 1
                    else:
                        clock += 1
    return marker, clock


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("directory")
    ap.add_argument("--marker-lo", type=int, default=250)
    ap.add_argument("--marker-hi", type=int, default=650)
    ap.add_argument("--clock-lo", type=int, default=300)
    ap.add_argument("--clock-hi", type=int, default=1300)
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.directory, "r*.out")))
    if not files:
        print(f"{args.directory}: no traces")
        return 1
    counts = [channel_counts(f) for f in files]
    marker = statistics.median(c[0] for c in counts)
    clock = statistics.median(c[1] for c in counts)
    why = []
    if not args.marker_lo <= marker <= args.marker_hi:
        why.append(f"marker {marker:.0f} outside [{args.marker_lo},{args.marker_hi}]")
    if not args.clock_lo <= clock <= args.clock_hi:
        why.append(f"clock {clock:.0f} outside [{args.clock_lo},{args.clock_hi}]")
    print(f"marker {marker:.0f} clock {clock:.0f} n {len(files)} "
          f"-> {'ok' if not why else 'BAD: ' + ', '.join(why)}")
    return 1 if why else 0


if __name__ == "__main__":
    sys.exit(main())
