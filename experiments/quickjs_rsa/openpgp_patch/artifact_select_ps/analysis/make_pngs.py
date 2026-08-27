"""Render each Bokeh figure to its own PNG, for embedding in EXPLANATION.md.

The interactive versions live in results/figures_<trace>.html; these are the
static copies the markdown shows inline. Needs bokeh, numpy and playwright:

    pip install bokeh playwright && python3 -m playwright install chromium
    python3 make_pngs.py [--trace r0]
"""
import argparse
import tempfile
from pathlib import Path

from bokeh.layouts import column
from bokeh.plotting import output_file, save
from playwright.sync_api import sync_playwright

import decoder as D
import plot_figures as P
from figures import enrich

WIDTH = 1180


def figures(path, res):
    """(filename stem, bokeh figure) for every panel, in report order."""
    sep_a, sep_b = P.fig_separation(res)
    return [
        ("fig1_raster", P.fig_raster(path, res)),
        ("fig2_gap_scales", P.fig_gap_scales(path)),
        ("fig3_per_bit", P.fig_per_bit(res)),
        ("fig4a_separation_low", sep_a),
        ("fig4b_separation_all", sep_b),
        ("fig5_along_trace", P.fig_along_trace(res)),
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trace", default="r0")
    args = ap.parse_args()

    path = next(p for p in D.trace_paths() if p.name.startswith(args.trace))
    out_dir = Path(__file__).resolve().parents[1] / "results" / "figures"
    out_dir.mkdir(parents=True, exist_ok=True)
    res = enrich(path)

    with tempfile.TemporaryDirectory() as tmp, sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(viewport={"width": WIDTH, "height": 600},
                                device_scale_factor=2)
        for stem, fig in figures(path, res):
            fig.sizing_mode = "fixed"
            fig.width = WIDTH
            fig.toolbar_location = None      # no zoom controls in a static image
            html = Path(tmp) / f"{stem}.html"
            output_file(html, title=stem, mode="inline")
            save(column(fig))
            page.goto(html.as_uri())
            page.wait_for_timeout(1200)
            png = out_dir / f"{stem}.png"
            page.locator(".bk-Figure").first.screenshot(path=png)
            print(f"wrote {png.relative_to(out_dir.parents[1])}")
        browser.close()


if __name__ == "__main__":
    main()
