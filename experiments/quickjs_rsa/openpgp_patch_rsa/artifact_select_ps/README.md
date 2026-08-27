# Prime+Scope against OpenPGP.js's branchless RSA exponent selection

Self-contained copy of the attack behind **paper §4.2**'s patch analysis, with
Prime+Scope traces included so the decode can be checked without the
measurement hardware. On the included single-signature trace the decoder
recovers 3976 of the 4094 exponent bits with 30 errors.

The full 100-key evaluation the paper reports lives one directory up; see
[`../Readme.md`](../Readme.md).

## What is here

```
analysis/decoder.py          decoder; needs only numpy
analysis/reproduce.py        regenerates every table
analysis/verify.py           checks the output against the published numbers
analysis/figures.py          the figures as text; needs only numpy
analysis/plot_figures.py     the figures as interactive HTML; needs bokeh
analysis/make_pngs.py        renders each figure to PNG; needs bokeh + playwright
results/figures_r0.html      interactive figures (pan, zoom, hover)
results/expected_output.txt  reference output of reproduce.py
data/traces/r{0..4}.out      five Prime+Scope traces of the bf_logic_or line,
                             one signature each
data/traces_and_line/        three traces of the bf_logic_and line, for the
                             line-attribution check
victim/openpgp_select_rsa.js       victim entry point
victim/openpgp_select_patched.js   OpenPGP.js 5.11.2 with the patch applied
victim/selectBigInt.mjs            the proposed constant-time selection
victim/rsa_key_0.json              RSA-4096 key; `d` is the ground truth
attack/quickjs_select_rsa_ps.c     the attacker
attack/run_select_rsa_ps.sh        victim + attacker driver
run.sh                             runs the check below
```

## Reproduce from the included traces

Runs anywhere: no special hardware, no build, about ten seconds. Requires
Python 3.8+ and numpy, and nothing from the surrounding repository.

```bash
python3 -m venv .venv && .venv/bin/pip install numpy
./run.sh
```

or directly:

```bash
cd analysis
python3 reproduce.py     # prints the result tables
python3 verify.py        # checks them; exits non-zero on any mismatch
```

`verify.py` asserts 42 values: pair counts, alternation rates, correlations,
bit counts, accuracies, the error counts over the lowest 2048 bits, that the
forward-order control returns chance, that the narrow group has lower variance
than the wide group, and that combining traces does not beat the best single
trace. `results/expected_output.txt` holds the full reference output for
diffing.

### Figures

```bash
cd analysis
python3 figures.py          # text versions, numpy only
python3 plot_figures.py     # -> ../results/figures_r0.html
python3 make_pngs.py        # -> ../results/figures/*.png
```

The last two need `bokeh` (and `playwright` plus `python3 -m playwright install
chromium` for the PNGs). Nothing in the verification path depends on them. Pass
`--trace r1` to plot any of the five traces.

## Collecting new traces

Use the build and the run scripts one directory up, which are already wired
into the repository's CMake build. New traces can be analysed here with:

```bash
python3 analysis/reproduce.py --traces /path/to/trace/directory
```

`verify.py` will not pass on new traces: it checks the exact values obtained
from the traces shipped here. Expect the pair structure to hold, correlations
to vary between traces, and accuracy over the lowest 2048 bits to be far above
accuracy over all 4094.
