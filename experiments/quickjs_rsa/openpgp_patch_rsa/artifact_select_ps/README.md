# Prime+Scope against OpenPGP.js's branchless RSA exponent selection

Artifact for REPORT.md (section 5.2). OpenPGP.js's proposed constant-time patch
replaces the secret-dependent ternary in `modExp` with a masked selection over
BigInts. This removes the bytecode branch but leaves the amount of work done by
QuickJS's big-integer library dependent on the key bit. A Prime+Scope attack on
one signature recovers 1995 of the lowest 2048 exponent bits with 16 errors.

## What is here

```
REPORT.md                    the writeup (section 5.2)
EXPLANATION.md               plain-language walkthrough of the attack, with figures
analysis/decoder.py          decoder; needs only numpy
analysis/reproduce.py        regenerates every table in the report
analysis/verify.py           checks the output against the published numbers
analysis/figures.py          the figures as text; needs only numpy
analysis/plot_figures.py     the figures as interactive HTML; needs bokeh
analysis/make_pngs.py        renders each figure to PNG; needs bokeh + playwright
results/figures_r0.html      interactive figures (pan, zoom, hover)
results/figures/*.png        static figures, as embedded in EXPLANATION.md
data/traces/r{0..4}.out.gz   five Prime+Scope traces, one signature each
victim/openpgp_select_rsa.js   victim entry point
victim/openpgp_select_patched.js   OpenPGP.js 5.11.2 with the patch applied
victim/selectBigInt.mjs      the proposed constant-time selection
victim/rsa_key_0.json        RSA-4096 key; `d` is the ground truth
attack/quickjs_select_rsa_ps.c   the attacker
attack/run_select_rsa_ps.sh  victim + attacker driver
results/expected_output.txt  reference output of reproduce.py
run.sh                       runs path A below
```

## Path A: reproduce the results from the included traces

Runs anywhere. No special hardware, no build, about ten seconds.

Requires Python 3.8+ and numpy. Nothing else — not pandas, and not the
surrounding SCAR repository.

```bash
python3 -m venv .venv && .venv/bin/pip install numpy
./run.sh
```

or directly:

```bash
cd analysis
python3 reproduce.py     # prints Tables 1-6 of the report
python3 verify.py        # checks them; exits non-zero on any mismatch
```

`verify.py` asserts 42 published values: pair counts, alternation rates,
correlations, bit counts, accuracies, the error counts over the lowest 2048
bits, that the forward-order control returns chance, that the narrow group has
lower variance than the wide group, and that combining traces does not beat the
best single trace.

Expected final line:

```
All checks passed. REPORT.md numbers reproduced.
```

`results/expected_output.txt` holds the full reference output for diffing.

### Figures

`EXPLANATION.md` is a plain-language walkthrough of the whole attack; its figures are
generated from the same traces and are regenerated with:

```bash
cd analysis
python3 figures.py                            # text versions, numpy only
python3 plot_figures.py                       # -> ../results/figures_r0.html
python3 make_pngs.py                          # -> ../results/figures/*.png
```

The last two need `pip install bokeh` (and `playwright` plus
`python3 -m playwright install chromium` for the PNGs). Nothing in the verification
path depends on them. Pass `--trace r1` (etc.) to plot any of the five traces.

## Path B: collect new traces

This needs the measurement setup, and results are meaningless without it.

Preconditions:

- Intel CPU with an inclusive last-level cache, at least 16 logical cores.
- CPU frequency pinned to 2.4 GHz and address space layout randomisation
  disabled. The repository's `setup.sh` does both and needs `sudo`.
- QuickJS built as a shared library, so victim and attacker map the same
  `libquickjs.so` pages.
- The surrounding SCAR repository, which supplies the shared libraries
  `utils`, `prime_probe` and `quickjs_runtime`.

Copy `attack/quickjs_select_rsa_ps.c` to `experiments/quickjs_rsa/openpgp_patch_rsa/`
and `victim/*.js` to `experiments/quickjs_rsa/openpgp_patch_rsa/js/`, then add to
`experiments/quickjs_rsa/CMakeLists.txt`:

```cmake
add_executable(quickjs_select_rsa_ps openpgp_patch_rsa/quickjs_select_rsa_ps.c)
target_link_libraries(quickjs_select_rsa_ps PRIVATE utils prime_probe quickjs_runtime)
```

A new target needs a full reconfigure, not just a rebuild:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --target quickjs_select_rsa_ps -j"$(nproc)"
VICTIM_RUNS=5 bash experiments/quickjs_rsa/openpgp_patch_rsa/run_select_rsa_ps.sh
```

Traces land in
`build/output/quickjs_select_rsa_ps/quickjs_select_rsa_ps_key00000_r00005/`.
Analyse them with:

```bash
python3 analysis/reproduce.py --traces /path/to/that/directory
```

Do not expect `verify.py` to pass on new traces: it checks the exact values
obtained from the traces shipped here. Expect the pair structure of Table 1 to
hold, correlations to vary between traces as they do in Table 2, and accuracy
over the lowest 2048 bits to be far above accuracy over all 4094.

### Two constants are specific to the QuickJS build

`quickjs_select_rsa_ps.c` locates its target by adding fixed file offsets to
the load address of `libquickjs.so`:

```c
static const uintptr_t bf_logic_or_file_offset = 0xb1220;
static const uintptr_t js_std_eval_file_offset = 0x18da0;
```

These are valid only for the QuickJS commit and compiler flags used here.
Recompute them with `nm` and `addr2line` against your own `libquickjs.so` if
either changes; wrong offsets produce traces with no structure rather than an
obvious error.

## Reading the trace files

One line per probe record. Columns are whitespace separated, each `tsc:latency`.
The attacker probes one cache line, `bf_logic_or`, so traces have a single
column. The traces in `data/traces` predate that and carry a second probe,
`bf_add_internal`, in column 0; it was dropped as redundant (see
"Why only one probe" below), and the signal is the last column either way.
A timestamp of 0 means no record. `analysis/decoder.py:load_trace` parses this
in 20 lines if you want to write your own analysis.

## Why only one probe

An earlier version watched `bf_add_internal` alongside the signal as a control,
on the grounds that it is reached from `bf_mul`/`bf_divrem` on every loop
iteration whatever the key bit, and so should not leak. It doesn't (correlation
0.036), but that fact is redundant: the decoder's forward-order score is a
permutation test over the real signal, and already rules out the pair-splitting
and index fit manufacturing correlation from trace structure. A probe in a
different LLC set also says nothing about what may be co-resident in
`bf_logic_or`'s set, which is the only exposure Prime+Scope adds over
Flush+Reload. Removing it leaves the result unchanged and the attack one thread
and one eviction set smaller.

## Limitations

Stated in full at the end of REPORT.md. In short: one key and five traces; two
of the five (r2, r4) are close to chance over the whole exponent; the mapping
from the 4.1 recorded accesses per call to SELECT's three calls into
`bf_logic_op` is not established; and the lattice step that would turn the
recovered low half of `d` into the full key is cited, not run.
