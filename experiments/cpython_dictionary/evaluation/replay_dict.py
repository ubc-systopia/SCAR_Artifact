#!/usr/bin/env python3
"""Re-score a saved cpython_dictionary capture without touching the hardware.

The attacker binary writes a replay directory under
    build/experiments/cpython_dictionary/output/cpython_dict_<tag>/
containing meta.txt, targets.txt, select_sets.txt, fingerprints.txt,
calibration.txt and attack.txt. This script recomputes the paper's three
numbers from those files and can sweep the cosine-similarity threshold.
"""

import argparse
import math
import os
import shutil
import subprocess
import sys


def read_kv(path):
    out = {}
    with open(path) as fp:
        for line in fp:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 2:
                out[parts[0]] = parts[1]
    return out


def read_fingerprints(path):
    fps = {}
    with open(path) as fp:
        for line in fp:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 2:
                continue
            fps[int(parts[0])] = [float(x) for x in parts[1:]]
    return fps


def read_attack(path):
    rows = []
    with open(path) as fp:
        header = fp.readline()
        if not header.startswith("iter"):
            fp.seek(0)
        for line in fp:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 5:
                continue
            rows.append(
                {
                    "iter": int(parts[0]),
                    "kind": parts[1],
                    "dict_index": int(parts[2]),
                    "gt": int(parts[3]),
                    "vec": [float(x) for x in parts[4:]],
                }
            )
    return rows


def cosine(a, b):
    dot = nx = ny = 0.0
    for x, y in zip(a, b):
        dot += x * y
        nx += x * x
        ny += y * y
    denom = math.sqrt(nx) * math.sqrt(ny)
    if denom == 0.0:
        return 0.0
    return dot / denom


def score(rows, fps, threshold):
    target_success = target_access = access_success = 0
    n_target = n_nontarget = 0

    for row in rows:
        best_sim = 0.0
        choice = -1
        for tid in sorted(fps):
            sim = cosine(row["vec"], fps[tid])
            if sim > best_sim:
                best_sim = sim
                choice = tid
        decision = choice if best_sim > threshold else -1

        if row["kind"] == "target":
            n_target += 1
            if decision != -1:
                target_access += 1
            if decision == row["gt"]:
                target_success += 1
        else:
            n_nontarget += 1
            if decision == -1:
                access_success += 1

    return {
        "n_target": n_target,
        "n_nontarget": n_nontarget,
        "target_success": target_success / n_target if n_target else 0.0,
        "target_access": target_access / n_target if n_target else 0.0,
        "nontarget_reject": access_success / n_nontarget if n_nontarget else 0.0,
    }



PALETTE = {
    "surface": "#fcfcfb",
    "ink": "#0b0b0b",
    "ink_soft": "#52514e",
    "grid": "#dcdbd6",
    "target": "#2a78d6",
    "nontarget": "#eb6834",
    "ramp": ["#cde2fb", "#b7d3f6", "#9ec5f4", "#86b6ef", "#6da7ec", "#5598e7",
             "#3987e5", "#2a78d6", "#256abf", "#1c5cab", "#184f95", "#104281",
             "#0d366b"],
}

GRAY = {
    "surface": "#ffffff",
    "ink": "#0b0b0b",
    "ink_soft": "#52514e",
    "grid": "#d8d8d8",
    "target": "#1a1a1a",
    "nontarget": "#8a8a8a",
    "ramp": ["#f2f2f2", "#e2e2e2", "#d0d0d0", "#bcbcbc", "#a6a6a6", "#909090",
             "#7a7a7a", "#646464", "#4e4e4e", "#3a3a3a", "#282828", "#181818",
             "#0b0b0b"],
}


def html_to_pdf(html_path, pdf_path):
    """Print a saved bokeh page to a vector PDF with headless Chrome."""
    chrome = None
    for name in ("google-chrome-stable", "google-chrome", "chromium",
                 "chromium-browser"):
        chrome = shutil.which(name)
        if chrome:
            break
    if not chrome:
        print("  no chrome/chromium found, skipping PDF")
        return False

    with open(html_path) as fp:
        page = fp.read()
    style = ("<style>@page { size: 1000px 812px; margin: 0 } "
             "html, body { margin: 0; padding: 0; width: 1000px } "
             "@media print { .bk-Column, .bk-Figure { break-inside: avoid } }"
             "</style>")
    if style not in page:
        page = page.replace("</head>", style + "</head>", 1)
        with open(html_path, "w") as fp:
            fp.write(page)

    cmd = [chrome, "--headless", "--disable-gpu", "--no-sandbox",
           "--no-pdf-header-footer", "--virtual-time-budget=10000",
           "--print-to-pdf=" + os.path.abspath(pdf_path),
           "file://" + os.path.abspath(html_path)]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired):
        print("  chrome failed, skipping PDF")
        return False
    return os.path.exists(pdf_path)


def make_plot(path, meta, fps, rows, threshold, grayscale=False):
    try:
        from bokeh.layouts import column
        from bokeh.models import (ColorBar, ColumnDataSource, HoverTool,
                                  LinearColorMapper, Span)
        from bokeh.plotting import figure, save
        from bokeh.resources import INLINE
    except ImportError:
        sys.exit("bokeh is required for --plot "
                 "(use the project venv, .venv/bin/python)")

    c = GRAY if grayscale else PALETTE
    tids = sorted(fps)
    nsets = len(fps[tids[0]])
    band_hi = float(meta.get("band_high", 42))
    iters = meta.get("dict_iterations", "32")

    example_t = next((r for r in rows if r["kind"] == "target"), None)
    example_n = next((r for r in rows if r["kind"] == "nontarget"), None)

    grid, labels = [], []
    for t in tids:
        grid.append(fps[t])
        labels.append("profiled target %d" % t)
    if example_t:
        grid.append(example_t["vec"])
        labels.append("observed (target %d)" % example_t["gt"])
    if example_n:
        grid.append(example_n["vec"])
        labels.append("observed (non-target)")

    hx, hy, hv = [], [], []
    for r, lab in enumerate(labels):
        for i in range(nsets):
            hx.append(i)
            hy.append(lab)
            hv.append(grid[r][i])

    mapper = LinearColorMapper(palette=c["ramp"], low=0, high=band_hi)
    src1 = ColumnDataSource(dict(x=hx, y=hy, v=hv))

    p1 = figure(height=48 * len(labels) + 120, width=980,
                sizing_mode="fixed",
                y_range=list(reversed(labels)),
                x_range=(-0.5, nsets - 0.5),
                title="LLC hit vectors: each dictionary entry has its own "
                      "signature",
                x_axis_label="selected LLC cache set",
                toolbar_location="above",
                tools="pan,box_zoom,reset,save")
    p1.rect(x="x", y="y", width=0.94, height=0.88, source=src1,
            fill_color={"field": "v", "transform": mapper},
            line_color=c["surface"], line_width=1)
    p1.add_tools(HoverTool(tooltips=[("row", "@y"),
                                     ("cache set", "@x"),
                                     ("hits / %s accesses" % iters, "@v")]))
    p1.add_layout(ColorBar(color_mapper=mapper, width=12,
                           title="hits / %s accesses" % iters,
                           background_fill_color=c["surface"]), "right")

    xs_t, ys_t, gt_t, xs_n, ys_n, idx_n = [], [], [], [], [], []
    for r in rows:
        best, choice = 0.0, -1
        for t in tids:
            sim = cosine(r["vec"], fps[t])
            if sim > best:
                best, choice = sim, t
        if r["kind"] == "target":
            xs_t.append(r["iter"])
            ys_t.append(best)
            gt_t.append(r["gt"])
        else:
            xs_n.append(r["iter"])
            ys_n.append(best)
            idx_n.append(r["dict_index"])

    p2 = figure(height=360, width=980, y_range=(-0.05, 1.38),
                sizing_mode="fixed",
                title="Decision: target accesses separate cleanly from "
                      "non-targets",
                x_axis_label="attack access",
                y_axis_label="best cosine similarity",
                toolbar_location="above",
                tools="pan,box_zoom,reset,save")
    rt = p2.scatter(x="x", y="y", marker="circle", size=8,
                    fill_color=c["target"], line_color=c["surface"],
                    line_width=1, legend_label="access to a target entry",
                    source=ColumnDataSource(dict(x=xs_t, y=ys_t, gt=gt_t)))
    rn = p2.scatter(x="x", y="y", marker="triangle", size=9,
                    fill_color=c["nontarget"], line_color=c["surface"],
                    line_width=1, legend_label="access to any other entry",
                    source=ColumnDataSource(dict(x=xs_n, y=ys_n, di=idx_n)))
    p2.add_tools(HoverTool(renderers=[rt], tooltips=[
        ("access", "@x"), ("true target", "@gt"), ("similarity", "@y{0.000}")]))
    p2.add_tools(HoverTool(renderers=[rn], tooltips=[
        ("access", "@x"), ("dict index", "@di"),
        ("similarity", "@y{0.000}")]))
    p2.add_layout(Span(location=threshold, dimension="width",
                       line_color=c["ink_soft"], line_width=2,
                       line_dash="dashed"))
    p2.legend.location = "top_left"
    p2.legend.orientation = "horizontal"
    p2.legend.background_fill_color = c["surface"]
    p2.legend.background_fill_alpha = 1.0
    p2.legend.border_line_color = None
    p2.legend.label_text_color = c["ink"]

    for p in (p1, p2):
        p.output_backend = "svg"
        p.background_fill_color = c["surface"]
        p.border_fill_color = c["surface"]
        p.outline_line_color = None
        p.grid.grid_line_color = c["grid"]
        p.grid.grid_line_width = 1
        p.axis.axis_line_color = c["ink_soft"]
        p.axis.major_tick_line_color = c["ink_soft"]
        p.axis.minor_tick_line_color = None
        p.axis.major_label_text_color = c["ink_soft"]
        p.axis.axis_label_text_color = c["ink"]
        p.title.text_color = c["ink"]
        p.title.text_font_size = "13px"
    p1.xgrid.grid_line_color = None
    p1.ygrid.grid_line_color = None
    p2.xgrid.grid_line_color = None

    save(column(p1, p2, sizing_mode="fixed"), filename=path,
         resources=INLINE,
         title="CPython dictionary cache attack, threshold %.3f" % threshold)
    print("  plot written to %s" % path)

    pdf_path = os.path.splitext(path)[0] + ".pdf"
    if html_to_pdf(path, pdf_path):
        print("  plot written to %s" % pdf_path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("replay_dir", help="output/cpython_dict_<tag> directory")
    ap.add_argument("--threshold", type=float, default=None,
                    help="cosine threshold (default: the captured one)")
    ap.add_argument("--sweep", action="store_true",
                    help="sweep the threshold and print the best")
    ap.add_argument("--plot", metavar="FILE",
                    help="write the figure as .html, plus a .pdf beside it")
    ap.add_argument("--gray", action="store_true",
                    help="render the plot in grayscale")
    args = ap.parse_args()

    d = args.replay_dir
    for name in ("meta.txt", "fingerprints.txt", "attack.txt"):
        if not os.path.exists(os.path.join(d, name)):
            sys.exit("missing %s in %s" % (name, d))

    meta = read_kv(os.path.join(d, "meta.txt"))
    cal_path = os.path.join(d, "calibration.txt")
    cal = read_kv(cal_path) if os.path.exists(cal_path) else {}
    fps = read_fingerprints(os.path.join(d, "fingerprints.txt"))
    rows = read_attack(os.path.join(d, "attack.txt"))

    if not rows:
        sys.exit("attack.txt has no rows")

    print("capture: %s" % d)
    print("  targets=%s iters=%s band=[%s,%s] fingerprint sets=%d" % (
        meta.get("target_entries"), meta.get("dict_iterations"),
        meta.get("band_low"), meta.get("band_high"), len(next(iter(fps.values())))))
    if cal:
        print("  calibration: self_min=%s cross_max=%s captured_thres=%s" % (
            cal.get("cos_self_min"), cal.get("cos_cross_max"),
            cal.get("cos_target_thres")))

    thres = args.threshold
    if thres is None:
        thres = float(cal.get("cos_target_thres", 0.9))

    res = score(rows, fps, thres)
    print()
    print("  threshold %.4f  ->  target ID %.2f  target detected %.2f  "
          "non-target reject %.2f  (n=%d/%d)" % (
              thres, res["target_success"], res["target_access"],
              res["nontarget_reject"], res["n_target"], res["n_nontarget"]))
    print("  paper §5.5: target ID 0.96, non-target reject 0.95")

    if args.plot:
        make_plot(args.plot, meta, fps, rows, thres, grayscale=args.gray)

    if args.sweep:
        print()
        print("  threshold sweep (balanced = target ID + non-target reject):")
        best = None
        t = 0.50
        while t <= 0.9995:
            r = score(rows, fps, t)
            bal = r["target_success"] + r["nontarget_reject"]
            if best is None or bal > best[1]:
                best = (t, bal, r)
            print("    %.4f  target ID %.2f  reject %.2f  balanced %.3f" % (
                t, r["target_success"], r["nontarget_reject"], bal))
            t += 0.05 if t < 0.95 else 0.005
        print()
        print("  best threshold %.4f -> target ID %.2f, non-target reject %.2f"
              % (best[0], best[2]["target_success"], best[2]["nontarget_reject"]))


if __name__ == "__main__":
    main()
