# Progress: integrating the SELECT FR attack into a real modExp loop

Status as of 2026-08-05. Picks up from `openpgp_patch/quickjs_select_fr.c` +
`openpgp_patch/js/select_probe.js`, which showed 100% single-shot classification
of SELECT's secret `cond` bit — but only in an **isolated microbenchmark**
(SELECT called directly in a loop, no other BigInt arithmetic running).
This sub-experiment (`openpgp_patch_rsa/`) tries to reproduce that against
**real RSA-4096 signing** with SELECT patched into `BigInteger.modExp`.
See the approved plan at
`/home/ddinh02/.claude/plans/glimmering-tickling-nova.md` (top section) for
the original design; this file is the up-to-date status/résumé, the plan file
is the original design doc (now partially superseded by what's below).

## What's built and working

- `js/openpgp_select_patched.js` — copy of `../js/openpgp.js` with
  `BigInteger.modExp`'s `r = lsb ? rx : r` replaced by
  `r = SELECT(lsb, rx, r, bits)` (imports `SELECT` from
  `../../openpgp_patch/js/selectBigInt.mjs`). **Verified correct**: byte-identical
  signatures vs. unpatched `openpgp.js` for the same key+message (`/tmp/verify_patched.js`
  vs `/tmp/verify_unpatched.js` — both scratch files, not checked in).
- `js/openpgp_select_rsa.js` — victim entry point, same shape as
  `../js/openpgp_rsa.js` (KEY_ID env → `rsa_key_pool/rsa_key_<id>.json` →
  `crypto.publicKey.rsa.sign(...)`), just importing the patched module.
- `quickjs_select_rsa_fr.c` — FR attacker. Reuses `quickjs_select_fr.c`'s
  `get_bf_add_internal_target()` (same cache line, same build-derived offset)
  combined with a real per-key round loop (`KEY_ID` via `sync_ctx.data`,
  barrier protocol identical to `quickjs_rsa_fr.c`). Builds and runs cleanly.
  **Important fix already applied**: the probe loop now breaks early once the
  victim signals `SYNC_CTX_PAUSE` (checked every 4096 iterations) instead of
  always probing for the full `ROUND_CYCLES` budget — without this, a round's
  trace was ~90% post-signing idle noise since signing (~900ms/sign) finishes
  long before a generously-sized cycle budget (6e9) elapses.
- `evaluation/extract_select_rsa.py` — windowed hit-count decoder (splits one
  round's continuous trace into `secret_key_bits` equal-duration windows,
  classifies each by hit-rate threshold). Runs end-to-end without crashing,
  reuses `RSA_KEY`/`lat_to_hit`/scoring from `../../evaluation/extract_openpgp_rsa.py`
  and `../../evaluation/utils.py` unchanged.
- `run_select_rsa_eval.sh` — driver script, modeled on `../run_fr_eval.sh`.
- `CMakeLists.txt` wiring for `quickjs_select_rsa_fr` (in `../CMakeLists.txt`).

All of the above compiles, runs without deadlocks, and the full pipeline
(victim → attacker → trace files → decoder) executes end to end.

## The blocking finding: bit classification is at chance (~50%)

Windowed decoding gives ~50.7% accuracy (chance) against real signing traces,
even after fixing the idle-time dilution bug above. Root-caused via a targeted
experiment, not guessed:

1. First hypothesis (wrong, ruled out): suspected QuickJS re-parsing the
   44K-line bundled `openpgp_select_patched.js` every round was diluting the
   signal. Benchmarked a single `sign()` call in isolation
   (`/tmp/bench_sign_loop.js`, N=20 loop, not checked in): **~900ms/sign**,
   which is almost the entire round duration — parsing is only ~10% of a
   round. Ruled out.

2. Second hypothesis (confirmed): **`bf_add_internal` is not SELECT-exclusive**
   inside a real modExp loop. Every iteration also does
   `(r*x) % n.value` and `(x*x) % n.value` — regardless of the secret bit —
   and BigInt multiply/mod-reduce internally call the same shared
   `bf_add_internal` as an implementation detail, unrelated to which branch
   SELECT takes.

   **Verified directly**: wrote `../openpgp_patch/js/mulmod_probe.js` — a
   victim doing *only* the unconditional `(r*x)%n` / `(x*x)%n` work, no
   `SELECT()` call at all — and ran it through the exact same FR attacker/window
   (`quickjs_select_fr`, `iters=50`, `ROUND_CYCLES=20e6`) used for the earlier
   100%-accuracy synthetic result. Result: **~1.1–1.3% hit rate on every
   round**, on par with or above the original SELECT-only `cond=1` rate
   (~1.2–1.5%), while the original isolated `cond=0` rate was only ~0.6–0.7%.

   Conclusion: the unconditional mul/mod traffic that runs on *every* modExp
   iteration touches the target cache line at a rate comparable to or
   exceeding SELECT's own branch-taken signal, so once mixed into a real
   modExp loop there is no way for a hit-count threshold to separate
   "SELECT took the full-arithmetic path" from "surrounding mul/mod also
   touched this same shared function" — they're literally the same cache line.

**Implication**: the earlier 100%-accuracy result is real, but demonstrates
that SELECT leaks *in isolation*, not that `bf_add_internal` leaks the secret
bit *during actual RSA signing*. Those are meaningfully different claims.

## Option (a) closed definitively via disassembly (not just deprioritized)

User asked to still attempt re-localizing a SELECT-exclusive target (option
(a) from the original two choices). Did **real disassembly work**, not more
guessing, against `build/quickjs/lib/quickjs/libquickjs.so`:

```bash
objdump -d "$LIB" > /tmp/qjs_disasm.txt
grep -B2 "affa0 <bf_add_internal>" /tmp/qjs_disasm.txt | grep -E "call|jmp"
```

**Result: `bf_add_internal` has exactly two callers in the entire library**
(`__bf_add` at `b0770`, `__bf_sub` at `b0780`), both bare tail-jumps into the
identical shared code at `affa0`. There is only ever one compiled copy of this
function. `bf_add`/`bf_sub` (the public entry points routing into it) are in
turn called from dozens of sites throughout the library, including directly
inside `bf_mul`'s address range (`b77f0`–`b8xxx`) and `bf_divrem`'s
(`bd9c0` neighborhood) — i.e. multiplication and modulo-reduction (exactly
what `(r*x)%n` / `(x*x)%n` execute every iteration) call the *same*
addition/subtraction machinery SELECT calls, byte-for-byte identical
instructions. **A cache-line probe cannot distinguish "who called this
shared function"** — that information isn't present in the executing code,
only on the (address-invisible) call stack. Option (a) as originally
conceived is not merely hard, it is proven impossible for this target.

## A viable variant of (a): `bf_logic_or` as an exclusive marker channel

Before fully closing the door, found and started pursuing a different angle:
QuickJS's single BigInt-binary-op dispatcher (`js_binary_arith_bigint`,
`third_party/quickjs/quickjs.c:13162`) routes `OP_and`/`OP_or` to
`bf_logic_and`/`bf_logic_or` — **separate functions from `bf_add`/`bf_sub`**,
never called by `bf_mul`/`bf_divrem` (arithmetic algorithms don't need
bitwise AND/OR). Checked call sites the same way:

```bash
grep -n "bf_logic_and@plt\|bf_logic_or@plt" /tmp/qjs_disasm.txt
```

**`bf_logic_or` has exactly ONE caller in the whole binary**:
`js_binary_arith_bigint`'s `OP_or` case (quickjs.c:13297). SELECT's
implementation (`(a & (mask - cond)) | (b & (mask - 1n + cond))`) has exactly
one `|` — so a hit on `bf_logic_or`'s cache line can only mean SELECT's own
combine step just ran. (`bf_logic_and` has a second, unrelated caller —
`js_bigint_asUintN`, but confirmed via grep that `openpgp_select_patched.js`
never calls `BigInt.asUintN`, so in practice it'd also be exclusive here.)

**Idea**: use `bf_logic_or` hits as a per-SELECT-call temporal anchor. SELECT
computes its two subtraction/addition steps (which *do* touch the ambiguous
`bf_add_internal` line) immediately before combining with `|` — all within
one JS statement, a handful of instructions apart. `bf_add_internal` hits
that land in a short cycle-window just before a `bf_logic_or` hit are very
likely SELECT's own; the much larger population of `bf_add_internal` hits
scattered across the rest of the (much longer, ~115µs/iteration) mul/mod-
dominated loop body are not.

### What's implemented

`quickjs_select_rsa_fr.c` now probes **two channels**
(`cache_line_count = 2`): slot 0 = `bf_add_internal` (existing), slot 1 =
`bf_logic_or` (new, file offset `0xb1220`, same load-bias derivation as the
existing target). Builds and runs cleanly; `dump_profiling_traces` now
produces 2-column trace files. Confirmed the marker channel behaves
completely differently from the noisy `bf_add_internal` channel — sparse
(~1.7–1.9% hit rate vs the dense, flat ~4%+ from before) — consistent with it
firing on discrete events rather than constant background traffic, as
predicted.

### Open problem: ~1.9x too many marker events, not yet root-caused

The real modExp loop runs exactly `secret_key_bits` = **4094** iterations
(verified unambiguously — `bnSign` in `openpgp_select_patched.js:12696` does
one plain `m.modExp(d, n)` call, **not** CRT/`p`,`q`,`u` decomposition, so
there's no ambiguity about iteration count from that angle). SELECT's source
has exactly one `|` per call, so 4094 `bf_logic_or` touches are expected.

Measured (5-round smoke test, `output/quickjs_select_rsa_fr/..._key00000_r00005/r0.out`):
raw hit count ~12,364 per round (~3x expected); after clustering
temporally-adjacent hits (merge threshold 50,000 cycles) into single
per-touch anchors, **7,736 clusters** — still **~1.9x** the expected 4094.
Root cause not yet found. Candidates, none yet checked:
- A dedup/clustering-threshold artifact in the analysis (not the underlying
  data) — try different merge windows, or histogram raw inter-hit spacing to
  see if there's a natural bimodal split.
- A genuine double-touch per iteration from the calling convention itself
  (e.g. the interpreter's slow-path dispatch touching the handler's cache
  line twice — once for a type-check/dispatch step, once for the real call).
- Something else in the runtime executing a second, unrelated `|` per
  modExp iteration not yet identified (checked: `openpgp_select_patched.js`
  doesn't call `asUintN`; haven't checked whether other steps in the loop
  body, e.g. `BigInteger` wrapper methods, secretly do bitwise ops).

### Root cause found: `bf_logic_or` was never actually exclusive — false sharing at the cache-line level

Resolved by disassembling the exact bytes on the target line, not by tracing.
`nm -S` shows the four functions living in and around the probed cache line
(`0xb1200`–`0xb123f`, since `0xb1220 & ~0x3f == 0xb1200`):

```
000000000000b1220  b  T bf_logic_or     <- probed entry stub (11 bytes)
000000000000b1230  e  T bf_logic_xor    <- adjacent entry stub, SAME line (starts b1230, still < b1240)
000000000000b1240  e  T bf_logic_and    <- next line, NOT included (starts exactly at the line boundary)
000000000000b0c60 5b0 t bf_logic_op     <- shared body ends inside this line too
```

`objdump -d --start-address=0xb1200 --stop-address=0xb1250` confirms it
directly: the line opens with the **tail end of `bf_logic_op`'s epilogue**
(labeled `<bf_logic_op+0x5a0>`, the stack-canary check + return shared by
*every* call regardless of which of AND/OR/XOR was requested), then
`bf_logic_or`'s stub, then `bf_logic_xor`'s stub — all inside the same 64-byte
line. `bf_logic_and`'s stub is the one thing that happens to land just past
the boundary (`0xb1240`), which is why the earlier single-caller check on
`bf_logic_or`/`bf_logic_xor`'s *entry stubs* was true but irrelevant: the
question that matters for a cache-line probe isn't "who calls this stub" but
"what else touches this line," and the shared epilogue answers that
differently.

Confirmed via the PLT call sites (these are exported `T` symbols, so even
intra-library calls route through `<name>@plt>`, `grep -n
"bf_logic_and@plt\|bf_logic_or@plt\|bf_logic_xor@plt" /tmp/qjs_disasm_full.txt`):
`bf_logic_and`, `bf_logic_or`, and `bf_logic_xor` each have exactly one call
site and all three sit inside `js_binary_arith_bigint`, exactly as expected —
but all three also route through the *same* `bf_logic_op` body, whose
epilogue lands on the probed line. SELECT's own combine step
(`(a & ...) | (b & ...)`) issues **three** `bf_logic_op` calls per invocation
(two `&`, one `|`), not one — every one of them touches the probed line via
the shared epilogue, only one of them (the final `|`) also touches it via the
`bf_logic_or`-specific entry stub. That inflates the "marker" count to
somewhere between 1x and 3x the naive one-hit-per-SELECT-call expectation
depending on FR's flush/reload timing resolution relative to how close
together the three sub-calls execute — squares with the observed ~1.9x
(7736/4094) sitting between those two bounds, and needs no invocation of any
mysterious unrelated code path (no XOR calls anywhere in the real signing
trace need to be posited).

**This closes the `bf_logic_or`-as-marker idea for the same structural reason
`bf_add_internal` was closed**: at 64-byte cache-line granularity, QuickJS's
BigInt logic-op dispatch shares one epilogue across AND/OR/XOR, and SELECT's
own unconditional AND calls collide with the line meant to exclusively mark
its OR call. There is no cache-line-aligned boundary inside this function
family that isolates "OR happened" from "any bf_logic_op call happened" —
`bf_logic_or`'s 11-byte stub is too small, and too close to both the shared
epilogue and `bf_logic_xor`'s stub, to occupy a line by itself. No amount of
instruction-level tracing changes this: the collision is a static layout
fact, not a runtime ambiguity — confirmed by reading the bytes, not by
inference from hit counts.

**Not done, and now moot for this specific approach**: no correlated
bit-decoder was built — `evaluation/extract_select_rsa.py` still only
implements the old (confound-broken) single-channel windowed decoder.

## Where this stands

Both candidate FR targets for the real-modExp SELECT attack are now closed,
each for a disassembly-proven structural reason:

- `bf_add_internal`: single shared implementation, called by `bf_mul`/`bf_divrem`
  (the unconditional per-iteration mul/mod work) as well as by SELECT's own
  subtract/add steps — no address-level way to attribute a hit to SELECT vs.
  the surrounding arithmetic.
- `bf_logic_or`: shares its cache line with `bf_logic_op`'s common epilogue
  (hit by every AND/OR/XOR call, including SELECT's own unconditional ANDs)
  and with `bf_logic_xor`'s entry stub — no address-level way to isolate "OR
  happened" from "any logic op happened."

Both closures came from reading the actual compiled bytes (`objdump`/`nm`),
not from accuracy numbers or speculation — they're solid regardless of any
further tracing. The natural next moves, not yet started, would require a
different kind of target entirely rather than more analysis of these two:
rebuilding QuickJS/libbf with `-ffunction-sections` (or manual padding/
`__attribute__((aligned(64)))`) so `bf_logic_or` gets its own cache line,
which is a build-system change big enough to be treated as a new "should we
do this" decision rather than a continuation of this investigation as scoped.
Absent that, the honest documented result for this sub-experiment is a
**negative result**: SELECT's leak, real and 100%-reproducible in isolation
(`../openpgp_patch/quickjs_select_fr.c`), does not have a known cache-line-
granularity FR target that survives being embedded in a real RSA-4096
`modExp` loop.

### Checked: can the ~1.9x be recovered by better clustering? Yes — a coarse first sweep missed it.

First pass swept the merge-window threshold in coarse 50k-cycle steps and
concluded (wrongly — see below) that no threshold recovers ~4094:

```
thresh= 50000: clusters= 7736  ratio=1.890
thresh=250000: clusters= 7730  ratio=1.888
thresh=300000: clusters= 3473  ratio=0.848
```

The 250k→300k step is a 50k-cycle jump, and it turns out the correct
threshold lives inside that gap. Re-swept at 250-cycle resolution and found a
**steep but real crossing to ratio 1.0** right around **280,500-281,000
cycles**:

```
thresh=278500: clusters=4864  ratio=1.1881
thresh=279500: clusters=4659  ratio=1.1380
thresh=280500: clusters=4350  ratio=1.0625
thresh=280750: clusters=4214  ratio=1.0293
thresh=281000: clusters=3972  ratio=0.9702
thresh=281500: clusters=3785  ratio=0.9245
```

This isn't a fluke of one trace: checked the same crossing point across all 5
independent rounds in the 5-round smoke test, using "first threshold where
cluster count drops to ≤4094":

```
round 0: crossing_thresh=281000
round 1: crossing_thresh=280500
round 2: crossing_thresh=280500
round 3: crossing_thresh=280500
round 4: crossing_thresh=280750
```

Spread of only 500 cycles across independent rounds — this is the actual mean
modExp-loop-iteration duration showing up as the natural boundary between
"multiple sub-touches of the same iteration" and "next iteration," not
threshold-tuning noise. Using a **fixed** threshold of 280,750 cycles (chosen
from round 0, not re-tuned per round) against all 5 rounds:

```
round 0: clusters=4214  (+2.93%)
round 1: clusters=3988  (-2.59%)
round 2: clusters=3980  (-2.78%)
round 3: clusters=3960  (-3.27%)
round 4: clusters=4023  (-1.73%)
```

All within **±3.3%** of the true 4094 iteration count, with one fixed
threshold, out-of-sample across rounds. This recovers a usable per-iteration
anchor from the `bf_logic_or` marker channel — the earlier "definitively
closed, no threshold works" conclusion in this section was wrong; it was
based on a sweep with too coarse a step size that stepped over the real
(narrow) crossing region.

**Status now**: the marker-channel approach is back open. Implemented and
tested `marker_windowed_inference` in `evaluation/extract_select_rsa.py`
(`--marker` flag): instead of trusting one fixed threshold, it binary-searches
*each round's own* trace for the merge threshold giving exactly
`secret_key_bits` clusters (`_find_exact_cluster_threshold`, monotonic step
function over `_cluster_count`) — justified by the round-to-round crossing
point being stable to within 500 cycles, so per-round self-calibration isn't
overfitting, it's exploiting a real invariant. Rejects (returns `""`) any
round where no exact-match threshold exists in range, rather than guessing at
a misaligned window boundary.

**Result against the 5-round smoke trace**: 3/5 rounds hit an exact
4094-cluster threshold (mechanically confirms the earlier per-round crossing
analysis). But end-to-end accuracy on those 3 usable rounds is **50.7%
(chance)** — `python3 extract_select_rsa.py -d <dir> --id 0 --marker`.

This is the expected outcome given the earlier disassembly finding, not a
new mystery: fixing the marker channel only fixes *window boundaries* — the
signal being classified within each window is still `bf_add_internal`'s hit
rate, and that channel was already proven (via `mulmod_probe.js` and the
disassembly showing `bf_add_internal`'s only two callers, `__bf_add`/
`__bf_sub`, being invoked from inside `bf_mul`/`bf_divrem` too) to be
dominated by the unconditional `(r*x)%n`/`(x*x)%n` work every iteration does
regardless of the secret bit. Correct window boundaries don't help if the
thing being counted inside each window isn't SELECT-exclusive.

**Bottom line, now checked end-to-end rather than left open**: the marker-
clustering problem (this section's original subject) is solved — 500-cycle-
stable per-round thresholds reliably recover the true iteration count. The
*decoding* problem is not.

### Checked: does a SHORT pre-marker window help? No — and not for the reason first assumed

The first write-up of the negative result above said the full-iteration window
failed because `bf_add_internal` isn't SELECT-exclusive. True, but it skipped
the thing `quickjs_select_rsa_fr.c`'s own header comment proposes: score only a
*short* window immediately around the `bf_logic_or` marker, where SELECT's own
subtractions live, rather than the whole ~280k-cycle iteration (which is what
`marker_windowed_inference` actually did). That was never tested.

Tested now. For each cluster anchor (both the cluster's first and last OR hit),
`bf_add_internal` hit rate was computed over windows of 1k–50k cycles and
scored by point-biserial correlation against the true bits of `d`
(`rsa_key_pool/rsa_key_0.json`, 4094 bits, 2017 ones):

| WAITING_TIME | probe period | probes/iteration | best \|corr\| across rounds |
|---|---|---|---|
| 2000 | 3710 | ~75 | 0.016 – 0.018 |
| 1000 | 2702 | ~104 | 0.006 – 0.037 |
| 400  | 2072 | ~135 | 0.023 – 0.036 |
| 100  | 1778 | ~158 | 0.016 – 0.034 |

(probes/iteration = 280k-cycle iteration ÷ probe period. Note the raw trace span
is ~2.5e9 cycles while the marker-clustered region is only ~1.15e9 — an RSA sign
does two CRT modExps plus setup, so span/n_bits *overestimates* per-iteration
time by ~2x. Use the cluster threshold, not the span.)

All correlations are ~0.02–0.04 **with inconsistent sign across rounds of the
same key** — noise, not weak signal. Narrow windows do not rescue the decoder.

### The probe-density tradeoff (why lowering WAITING_TIME can't fix this)

The sweep above was run at four `WAITING_TIME` values to test whether the
limitation was simply sampling resolution (SELECT's whole execution is on the
order of one probe period at the default `waiting_time = 2000`). Attacker-side
counters, 3 rounds each:

| WAITING_TIME | samples/round | bf_add hits | bf_logic_or hits |
|---|---|---|---|
| 2000 | 725k  | 11,920 | 12,426 |
| 1000 | 999k  |  9,663 | 10,544 |
| 400  | 1,257k |  7,258 |  8,386 |
| 100  | 1,487k |  3,742 |  7,742 |

Sampling rate roughly doubles but observed hits fall ~3x. Each probe only
detects an access landing between its flush and its reload, so shrinking
`FR_wait` shrinks the detection window in near-proportion: faster probing buys
resolution and loses sensitivity. At `WAITING_TIME=100` the `bf_add` channel
also goes visibly unreliable (raw hit counts jump to ~50k in the Python-side
`lat < 460` classification vs ~3.7k under the C-side `lat < 300` rule — the line
is no longer being reliably flushed between probes). Marker clustering also
degrades: only 3 of 4 low-`WAITING_TIME` rounds still admit an exact
4094-cluster threshold.

So probe density is **not** the binding constraint in the range `WAITING_TIME`
can reach. Reproduce with the scratch scripts noted below.

**Conclusion for the real-modExp target**: the `bf_add_internal` channel does
not carry a recoverable per-bit signal inside a real RSA-4096 modExp, at any
window width or probe density tried. This stands in contrast to the synthetic
`select_probe.js` harness (100% single-shot accuracy), where each round batched
50 SELECT calls at a fixed `cond` with no mul/mod work in between — that
amplification is what made the leak measurable there, and it does not exist in
the real loop. A working decoder would need a genuinely SELECT-exclusive
*arithmetic* signal, not just an exclusive marker/clock; none has been
identified.

## Files touched this session (all new except CMakeLists.txt)

- `openpgp_patch_rsa/js/openpgp_select_patched.js` (new)
- `openpgp_patch_rsa/js/openpgp_select_rsa.js` (new)
- `openpgp_patch_rsa/quickjs_select_rsa_fr.c` (new; now 2-channel, see above)
- `openpgp_patch_rsa/evaluation/extract_select_rsa.py` (new; still single-channel,
  not yet updated for the marker-correlation idea)
- `openpgp_patch_rsa/run_select_rsa_eval.sh` (new)
- `openpgp_patch_rsa/evaluation/density_sweep.sh` (new — reruns the attack at a
  list of `WAITING_TIME` values, stashing each run's traces)
- `openpgp_patch_rsa/evaluation/density_analyze.py` (new — per-trace probe
  period, marker cluster threshold, and narrow-window-vs-true-`d` correlation;
  produces the two tables in the density-tradeoff section above)
- `openpgp_patch_rsa/PROGRESS.md` (this file)
- `openpgp_patch/js/mulmod_probe.js` (new — confound-check script, kept since
  it's a reusable diagnostic, not scratch)
- `../CMakeLists.txt` (added `quickjs_select_rsa_fr` target)

Scratch files used for verification, NOT checked in (recreate if needed):
`/tmp/verify_patched.js`, `/tmp/verify_unpatched.js`, `/tmp/bench_sign_loop.js`,
`/tmp/qjs_disasm.txt` (full `objdump -d` of libquickjs.so, ~187K lines,
regenerate with the command in the disassembly section above if needed again).

## How to reproduce the key results

Correctness check (patch doesn't change signatures) — recreate the two
`/tmp/verify_*.js` scripts described above (see git history of this message
or just diff `js/openpgp_select_patched.js` against `../js/openpgp.js` for the
one-line change) and run both with `build/quickjs/bin/qjs --std`.

Confound-check (the key `bf_add_internal`-alone negative result):
```bash
cd build
CPUS="1,3,5,7,9,11,13,15"
taskset -c "$CPUS" ./src/runtime/quickjs/quickjs_rt ../experiments/quickjs_rsa/openpgp_patch/js/mulmod_probe.js &
sleep 1
NUM_ROUNDS=20 ROUND_CYCLES=20000000 taskset -c "$CPUS" ./experiments/quickjs_rsa/quickjs_select_fr 20
```
Compare against the original SELECT-only run (same command, `select_probe.js`
as victim instead) to see the hit-rate overlap.

Disassembly evidence for the "only two callers" finding:
```bash
LIB=build/quickjs/lib/quickjs/libquickjs.so
objdump -d "$LIB" > /tmp/qjs_disasm.txt
grep -B2 "affa0 <bf_add_internal>" /tmp/qjs_disasm.txt | grep -E "call|jmp"
grep -n "bf_logic_and@plt\|bf_logic_or@plt" /tmp/qjs_disasm.txt
```

Two-channel real-signing pipeline (marker channel wired up, decoder not yet
updated to use it — currently still produces chance-level results via the old
single-channel windowed decoder):
```bash
./experiments/quickjs_rsa/openpgp_patch_rsa/run_select_rsa_eval.sh
```

Marker-clustering diagnostic (reproduces the "7736 vs 4094" finding):
```bash
cd experiments/quickjs_rsa/openpgp_patch_rsa/evaluation
python3 -c "
import sys; sys.path.insert(0, '../../evaluation')
import numpy as np
from utils import load_trace
trace = load_trace('../../../../build/output/quickjs_select_rsa_fr/quickjs_select_rsa_fr_key00000_r00005/r0.out')
or_pairs = np.array(trace[1].tolist(), dtype=np.int64)
or_hit = np.sort(or_pairs[(or_pairs[:,1] > 0) & (or_pairs[:,1] < 300)][:,0])
clusters = []
cur = [or_hit[0]]
for t in or_hit[1:]:
    if t - cur[-1] < 50000:
        cur.append(t)
    else:
        clusters.append(cur)
        cur = [t]
clusters.append(cur)
print('clusters:', len(clusters), 'vs expected 4094')
"
```

Probe-density sweep + narrow-window correlation (the two tables above):
```bash
cd build
bash ../experiments/quickjs_rsa/openpgp_patch_rsa/evaluation/density_sweep.sh 2000 1000 400 100
../.venv/bin/python3 ../experiments/quickjs_rsa/openpgp_patch_rsa/evaluation/density_analyze.py
```
`density_analyze.py` takes ~3 min (it binary-searches a cluster threshold per
trace over ~1M-sample arrays). Both scripts hardcode the scratch trace-stash
path at the top; edit if reproducing elsewhere.

## Prime+Scope port (`quickjs_select_rsa_ps.c`)

Built and working. Same victim, same two target lines as the FR attacker
(slot 0 = `bf_add_internal`, slot 1 = `bf_logic_or`, so the trace format and
slot order match and the same evaluation code applies).

Rationale: the FR probe period bottoms out at ~1778 cycles because each probe
only detects an access landing between its flush and its reload, so shrinking
`FR_wait` trades sensitivity for resolution roughly 1:1 (see the density table
above). `PS_profile_once` (`src/attack/prime_probe.c:35-63`) is *event-driven*
instead: it spins on a single timed access to the scope line and records a
`(tsc, latency)` pair only when an eviction actually occurs. (`PS_sample_interval
= 10000` in `evaluation/utils.py` is an FFT post-processing constant, NOT the
probe cadence — easy to misread as a resolution limit.)

No `identify_quickjs_target_sets` needed: both targets are exact addresses
derived from the load bias (ASLR off), so `prepare_evset()` (`src/attack/LLCF.c:106`)
builds an eviction set for the known address directly. Measured at run time:
**PS Resolution: 154 cycles**, vs FR's 1778-cycle floor — 11.5x finer.

### What improved

`bf_logic_or` events per SELECT call went from 1.9-3.0 (FR) to **4.11-4.13**
(P+S), consistently across all 5 rounds. The signing region is cleanly visible
as a flat-density window (~0.2e9 to ~2.75e9 of the 4e9 budget) with idle either
side, so it isolates without guesswork.

### What this corrected

**The ~280,750-cycle figure earlier in this document is a cluster-merge
threshold, not the loop-iteration duration.** Actual mean per-iteration time is
~615-623k cycles (2.55e9-cycle signing window / 4094 iterations), which matches
the `duration mean0/mean1` values in the marker-timing table. Anywhere above
that reads 280,750 as "mean per-iteration loop duration ≈ 117µs", that
interpretation is wrong; the number is still the right *threshold*, it just
isn't a period.

### What did not improve, and the new blocker

Correlations against the true bits of `d` are still ~0.02-0.036 — the same
magnitude as FR, not the improvement more dynamic range predicted:

| feature | mean corr | rounds | same sign |
|---|---|---|---|
| OR events per cluster | +0.0224 | 2 | yes |
| OR cluster span (duration proxy) | +0.0170 | 2 | yes |
| mean probe latency | -0.0092 | 2 | yes |
| max probe latency | +0.0071 | 2 | no |
| `bf_add_internal` count (control) | +0.0198 | 2 | yes |

Caveat: only **2 of 5 rounds** scored, because the FR clustering assumption
does not transfer. In FR, iteration boundaries were the large gaps and a
threshold of ~280k cleanly yielded 4094 clusters. In P+S the extra events fill
those gaps in, and the gap distribution becomes bimodal with a cliff:

```
thresh   5000 -> 16809 clusters
thresh  50000 ->  8310
thresh 200000 ->  8143   <- plateau, ~2 per iteration
thresh 500000 ->     19   <- cliff
```

Three of five rounds have no threshold giving exactly 4094 at all. The stable
plateau is ~8100-8350 — roughly **two groups per iteration** where FR resolved
one. That is the resolution gain showing up structurally, and it is the most
interesting unexploited result here: SELECT issues 2 `&` and 1 `|`, all routed
through `bf_logic_op`'s shared body whose epilogue shares the probed line, so
two resolvable groups per call is consistent with the AND-pair and the OR
separating. If they can be told apart, the OR group alone is isolatable — and
the OR's duration is precisely the cond-dependent quantity.

That is the next concrete step and it is NOT done: re-segment at the ~8100-
cluster plateau instead of forcing 4094, assign sub-groups within each
iteration, and score the OR sub-group's span alone. The current
`ps_analyze.py` forces exactly 4094 clusters, which is why it rejects 3 of 5
rounds — that rejection is an artifact of the wrong segmentation, not a
property of the data.

Files: `quickjs_select_rsa_ps.c`, `run_select_rsa_ps.sh`,
`evaluation/ps_analyze.py`, `evaluation/marker_amplitude.py`, plus the
`quickjs_select_rsa_ps` target in `../CMakeLists.txt` (needs a full
`cmake -S . -B build` reconfigure, not just `--build`).

```bash
VICTIM_RUNS=5 bash experiments/quickjs_rsa/openpgp_patch_rsa/run_select_rsa_ps.sh
.venv/bin/python3 experiments/quickjs_rsa/openpgp_patch_rsa/evaluation/ps_analyze.py
```

## Re-segmentation: the patch leaks. corr +0.50, 77.7% single-trace accuracy

The re-segmentation flagged above is now done, and it works. Decoder:
`evaluation/ps_select_leak.py` (supersedes `ps_analyze.py`, which forced 4094
clusters and was measuring the wrong thing).

### The actual structure

The ~8100 plateau was real but the interpretation above was wrong. `bf_logic_or`
events come in **pairs**: two events ~25-32k cycles apart, then ~278k to the next
pair. The gap histogram is bimodal with nothing at all between ~35k and ~270k, so
splitting pairs at 100k is not a tuned knob.

Pairs alternate strictly — 97.5-98.2% of consecutive pairs swap class — between:

| population | intra-pair gap | std   |
|------------|----------------|-------|
| WIDE       | ~30,050        | ~1400 |
| NARROW     | ~25,650        | ~ 600 |

Two pairs per iteration (2 x ~306k ~= the ~612k iteration period, matching the
least-squares period 612,038-613,417 across rounds). So the "two groups per
iteration" reading was right; what it missed is that the discriminator is the
*intra-pair gap*, not the group's event count or its position.

The WIDE member carries 2-3x the variance of the NARROW one, and that variance is
the secret. This is exactly SELECT's mechanism: `mask - cond` and
`mask - 1n + cond` differ in limb count with the bit, `bf_logic_op` runs for a
different duration, and the interval between its two probed accesses stretches or
shrinks. The NARROW member is a built-in control — same code, non-varying
operands, half the spread, no correlation with the key.

### Results (key 0, 4094 bits, 5 rounds)

| round | wide groups | alternation | LSB-first corr | acc    | forward (control) |
|-------|-------------|-------------|----------------|--------|-------------------|
| r0    | 4023        | 0.982       | **+0.4994**    | 0.7766 | -0.018 / 0.4896   |
| r1    | 3988        | 0.979       | **+0.4242**    | 0.7373 | -0.017 / 0.4878   |
| r2    | 3987        | 0.975       | +0.0746        | 0.5566 | -0.019 / 0.4869   |
| r3    | 4008        | 0.977       | **+0.5151**    | 0.7751 | -0.031 / 0.4895   |
| r4    | 4024        | 0.979       | +0.0417        | 0.5238 | -0.014 / 0.4902   |

Forward-order scoring returns chance in every round — square-and-multiply
consumes `d` LSB-first, so this is the negative control and it behaves.

Per-chunk correlation is the important number: **it reaches +0.94 to +0.96**
wherever the index alignment holds, e.g. r0 `+0.938 +0.685 +0.864 +0.897 +0.959`
before decaying, r3 similarly. The signal is near-total per bit. Whole-trace
accuracy is limited by alignment, not by SNR.

### Alignment is now the bottleneck (and repetition does not fix it)

~100 of 4094 iterations produce no clean pair, so the wide series is ~3990 long
and cannot be sliced positionally. Three aligners tried:

| aligner                      | result                                       |
|------------------------------|----------------------------------------------|
| global least-squares         | **best** — 0.777 / 0.775 / 0.737 on r0/r3/r1 |
| sequential step counting     | destroys signal (corr ~0.02): one missed group shifts every later bit |
| alternation counting (W's)   | same failure, 3993 W's vs 4094 bits          |
| block-anchored (640 blocks)  | 0.717 vote acc — better than naive, still below global |

Anything that accumulates index shift fails catastrophically. The global fit is
anchored so errors do not accumulate, but per-point residual jitter is ~0.25P, so
individual points slip and correlation decays along the trace.

The 5-round vote gives corr +0.3914, acc 0.7289 — *below* the best single round.
That is expected and not a contradiction: the rounds are misaligned differently,
so averaging them mixes bit positions. Repetition only helps once alignment is
fixed.

Next step: a drop-aware aligner. The information to do it is present — a dropped
iteration should be visible as a wide-gap of ~2P — so this is an engineering fix,
not a new measurement.

### Bottom line

The OpenPGP.js team's branchless `selectBigInt` does **not** stop the leak in a
real RSA-4096 `modExp`. The source-level constant-time property does not survive
lowering: QuickJS's arbitrary-precision BigInt makes `bf_logic_op`'s *duration*
depend on the secret bit through operand limb counts, and that duration is
directly observable via Prime+Scope as the interval between two accesses to a
single cache line. No branch is required for the leak.

```bash
.venv/bin/python3 experiments/quickjs_rsa/openpgp_patch_rsa/evaluation/ps_select_leak.py
```
