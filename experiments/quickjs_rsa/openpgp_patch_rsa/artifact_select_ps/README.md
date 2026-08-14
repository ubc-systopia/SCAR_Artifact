# Prime+Scope against OpenPGP.js's branchless RSA exponent selection

Artifact for REPORT.md (section 5.2). OpenPGP.js's proposed constant-time patch
replaces the secret-dependent ternary in `modExp` with a masked selection over
BigInts. This removes the bytecode branch but leaves the amount of work done by
QuickJS's big-integer library dependent on the key bit. A Prime+Scope attack on
one signature recovers 3976 of the 4094 exponent bits with 30 errors.

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
data/traces/r{0..4}.out      five Prime+Scope traces of the bf_logic_or line, one
                            signature each
data/traces_and_line/       three traces of the bf_logic_and line (PROBE_LINE=and),
                            for the line-attribution check in the README
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

### The target is resolved by symbol, not by offset

`quickjs_select_rsa_ps.c` used to locate its target by adding hard-coded file
offsets (`0xb1220`, `0x18da0`) to the load address of `libquickjs.so`. It now
includes `quickjs/libbf.h` and takes the addresses straight from the linker:

```c
target_bf_logic_and = (uintptr_t)&bf_logic_and & CACHE_LINE_MASK;
target_bf_logic_or = (uintptr_t)&bf_logic_or & CACHE_LINE_MASK;
```

`bf_logic_or`/`bf_logic_and`/`bf_rint` are exported by `libquickjs.so`, and the
attacker links against the same shared object the victim executes from, so these
are the real loaded addresses and nothing needs recomputing when the QuickJS
build changes. (`third_party/CMakeLists.txt` copies `libbf.h` into the QuickJS
install tree; upstream's `install` target ships only three headers.)

What *does* depend on the build is which functions share the target's cache
line — see below.

### The watched line is not exclusive to `|`

In the current build the libbf logic thunks and `bf_rint` land like this:

```
0xb1210 bf_rint      \
0xb1220 bf_logic_or   >  one 64-byte line, base 0xb1200
0xb1230 bf_logic_xor /
0xb1240 bf_logic_and     the next line, base 0xb1240
```

So the "`bf_logic_or` line" also holds `bf_rint`, which `bf_divrem`/`bf_rem`
call, i.e. every `%` in the modExp loop touches it. Interposing the PLT over one
RSA-4096 signature of the patched victim counts, per signature:

| symbol | calls | per modExp iteration |
| --- | --- | --- |
| `bf_logic_or` | 4,094 | 1 (`SELECT`'s `\|`) |
| `bf_logic_and` | 12,282 | 3 (`exp & 1n`, `SELECT`'s two `&`) |
| `bf_logic_xor` | 0 | – |
| `bf_rint` | 13,305 | ~3.25 (from the `%` operations) |

`bf_rint` + `bf_logic_or` = 17,399, and that is what the ~17,000-record traces
are: the ~4.1 records per `SELECT` call are ~1 `bf_logic_or` plus ~3.25
`bf_rint`, not four accesses to `bf_logic_or`. They are *not* `bf_logic_and`
traces — a probe cannot record more events (17,074 in `r0`) than there are calls
(12,282) — and `bf_logic_and` cannot bleed into them either: its line differs in
address bit 6, which is part of the LLC set index, so it is a different set.

Measured confirmation, three fresh runs each (`VICTIM_RUNS=3`):

| `PROBE_LINE` | records/trace | expected calls | ratio |
| --- | --- | --- | --- |
| `or` (default) | 16,970 / 17,302 / 16,473 | 17,399 | 0.95–0.99 |
| `and` | 12,596 / 12,450 / 12,458 | 12,282 | 1.01–1.03 |

### Which of the four accesses per iteration is which

Timestamping the victim's own `bf_rint`/`bf_logic_and`/`bf_logic_or` calls shows an
invariant 7-call loop body, `and(exp&1n) rint(shift) rint(r*x%n) and and or
rint(x*x%n)`. Four of those are on the watched line, giving the observed two
pairs per iteration separated by the two ~278k-cycle modular multiplications:

| pair | endpoints | gap, bit=0 | gap, bit=1 | 1-threshold accuracy |
| --- | --- | --- | --- | --- |
| wide | `rint(r*x%n)` -> `or` (all of `SELECT`) | 29,608 | 32,164 | 0.993 |
| narrow | `rint(x*x%n)` -> next `rint(shift)` (the exponent shift) | 25,282 | 25,374 | 0.585 |
| (inside wide) | `SELECT`'s first `&` -> second `&` | 3,430 | 4,759 | 0.998 |

So the decoder's median split isolates the `SELECT` pair. The leak within it is
*not* `SELECT`'s two `bf_logic_and` calls: per-handler timing on an instrumented
QuickJS (`openpgp_patch/run_opcode_timing.sh`, 10 runs at `maxBitLength=4096`)
puts the `and` pair at +16 cycles and the `or` at -36, against **+1,422 for the
`add`** in `mask - _1n + cond`. `cond = 0n` is a BigInt of length 0, which
`bf_add_internal` short-circuits at `libbf.c:908`; `cond = 1n` runs the full
64-limb add and carries out the top, forcing a second `bf_resize`. Intel PT
localizes the divergence to that one branch (`bf_add_internal+0x26a`). The `+`
sits between `SELECT`'s two `&` calls, which is why the interval above separates.
See `EXPLANATION.md` §4 and `EXPLANATION_AND.md` §4.1. (The absolute figures in
the last row come from an LD_PRELOAD interposer whose per-call overhead is
comparable to that short interval; the delta agrees with the handler timing, the
endpoints are inflated.)

The gaps above are measured inside the victim, but the Prime+Scope trace
reproduces the same four intervals from the outside (`python3 analysis/figures.py`,
figure 0, r0):

| interval | measured in the trace | instrumented victim | delta |
| --- | --- | --- | --- |
| `rint(shift)` -> `rint(r*x%n)` (multiply) | 277,590 | 277,734 | -144 |
| `rint(r*x%n)` -> `or` (**wide pair**) | 29,620 | 30,726 | -1,106 |
| `or` -> `rint(x*x%n)` (square) | 278,664 | 278,880 | -216 |
| `rint(x*x%n)` -> next `rint(shift)` (**narrow pair**) | 25,564 | 25,326 | +238 |
| loop period | 611,438 | 612,666 | -1,228 |

Even the ~1,100-cycle asymmetry between the multiply and the square survives, so
which pair follows which multiplication is fixed by the trace itself rather than
assumed from the source order.

`PROBE_LINE=both` probes both lines at once, but the two Prime+Scope threads
contend badly — one starves the other per round (12,246 vs 667 in one round,
342 vs 9,690 in the next) — so compare the lines across two single-probe runs.

## Reading the trace files

One line per probe record. Columns are whitespace separated, each `tsc:latency`.
By default the attacker probes one cache line, so traces have a single column.
Older traces in `data/traces` carry a dropped `bf_add_internal` probe in column
0, and `decoder.py` therefore takes the *last* column. Note the exception:
under `PROBE_LINE=both` the last column is `bf_logic_and`, so pass
`load_trace(path, slot=0)` explicitly to decode the `bf_logic_or` signal.
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
of the five (r2, r4) are close to chance over the whole exponent; the ~700-cycle
gap between the instrumented cost of the leak (~+1,450) and what the traces show
(~+2,200) is unexplained; and the lattice step that would turn the
recovered low half of `d` into the full key is cited, not run.
