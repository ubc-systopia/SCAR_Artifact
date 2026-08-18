import os
from pathlib import Path

import numpy as np
import pandas as pd
from bokeh import palettes
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

cpu_freq = 2800000000
PS_sample_interval = 10000
PS_fs = cpu_freq // PS_sample_interval

progress = Progress(
    TextColumn("[progress.description]{task.description}"),
    # TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
    BarColumn(),
    MofNCompleteColumn(),
    TextColumn("•"),
    TimeRemainingColumn(),
    TextColumn("•"),
    TimeElapsedColumn(),
    speed_estimate_period=600,
)

palette = [
    palettes.Colorblind8[0],  # 0 #0072B2
    palettes.Colorblind8[1],  # 1 #E69F00
    palettes.Bokeh8[4],  # 2 #20B254
    palettes.Bokeh8[0],  # 3 #EC1557
    palettes.Paired12[9],  # 4 #6A3D9A
    palettes.Category20_20[1],  # 5 #AEC7E8
    palettes.Colorblind8[0],  # 0 #0072B2
    palettes.Colorblind8[1],  # 1 #E69F00
    palettes.Bokeh8[4],  # 2 #20B254
    palettes.Bokeh8[0],  # 3 #EC1557
    palettes.Paired12[9],  # 4 #6A3D9A
    palettes.Category20_20[1],  # 5 #AEC7E8
]

from enum import Enum


class CacheLevel(Enum):
    L1 = 1
    L2 = 2
    L3 = 3
    RML2 = 4
    DRAM = 5
    PAGE = 6
    UND = 7


def clevel_to_hit(clevel, attack="FR"):
    if attack == "FR":
        return clevel.value < CacheLevel.DRAM.value
    elif attack == "PS":
        return clevel.value > CacheLevel.L2.value
    print("Unknown attack type")
    return None


def lat_to_clevel(lat):
    if lat == 0:
        return CacheLevel.UND
    elif lat < 70:
        return CacheLevel.L1
    elif lat < 90:
        return CacheLevel.L2
    elif lat < 140:
        return CacheLevel.L3
    elif lat < 240:
        return CacheLevel.RML2
    elif lat < 460:
        return CacheLevel.DRAM
    else:
        return CacheLevel.PAGE


def lat_to_hit(lat, attack="FR"):
    if attack == "FR":
        return clevel_to_hit(lat_to_clevel(lat), attack)
    else:
        return lat > 0


def trace_to_timestamp(trace, at="FR"):
    return np.array([x[0] for x in trace[trace.apply(lambda x: lat_to_hit(x[1], at))]])


def trace_hit_count(trace, att):
    pos = []
    all_pos = trace.apply(lambda x: False, axis=1)
    for i in range(trace.shape[1]):
        pos.append(trace.apply(lambda x: lat_to_hit(x[i][1], att), axis=1))
        all_pos |= pos[i]

    trace = trace[all_pos]

    hit_counts = [len(trace[i][pos[i]]) for i in range(trace.shape[1])]
    return hit_counts


def load_trace(filepath):
    f = open(filepath)
    lines = f.readlines()
    lines = list(filter(lambda x: x, lines))
    lines = list(
        map(
            lambda l: list(
                map(
                    lambda p: [
                        int(p.split(":")[0]),
                        int(p.split(":")[1]),
                    ],
                    l.strip().split(),
                )
            ),
            lines,
        )
    )
    df = pd.DataFrame(lines)
    return df


def load_ground_truth(fp=None):
    if not fp:
        fp = Path(__file__).resolve().parent / Path(
            "../output/quickjs_ground_truth.out"
        )
    f = open(fp)
    lines = f.readlines()
    gt = list(map(lambda l: l.strip().split(":"), lines))
    gt = pd.DataFrame(gt).astype(int)
    gt = gt.groupby(1)[0].apply(list)

    return gt


def aligned_timestamps(target_ts, reference_ts, delta=3000):
    aligned_ts = []
    i, j = 0, 0
    len_target, len_ref = len(target_ts), len(reference_ts)

    while i < len_target and j < len_ref:
        ts, ts_ref = target_ts[i], reference_ts[j]

        if ts_ref < ts - delta:
            j += 1
        elif ts_ref > ts + delta:
            i += 1
        else:
            aligned_ts.append(ts)
            i += 1

    return aligned_ts


def find_project_root(start_path=None, marker=".project"):
    if start_path is None:
        start_path = os.getcwd()

    current = os.path.abspath(start_path)

    while True:
        candidate = os.path.join(current, marker)
        if os.path.isfile(candidate):
            return current

        parent = os.path.dirname(current)
        if parent == current:
            return None

        current = parent
