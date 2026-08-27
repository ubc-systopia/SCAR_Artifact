# Attacking `bf_logic_and` directly

This is a self-contained explanation of the `PROBE_LINE=and` variant of the
attack: what it watches, what it recovers, and why it recovers less than the
default `bf_logic_or` variant. It doesn't assume you've read `EXPLANATION.md`
(the `or`-line writeup) — the two attacks watch different cache lines and the
reasoning is independent, though they end up sharing a punch line.

## 1. What `SELECT` does, and where `&` comes in

OpenPGP.js's constant-time replacement for `r = lsb ? rx : r` is
(`victim/selectBigInt.mjs`):

```js
export function SELECT(cond, a, b, maxBitLength) {
	const _1n = 1n;
	const mask = _1n << maxBitLength;
	return (a & (mask - cond)) | (b & (mask - _1n + cond));
}
```

Every call does exactly two BigInt `&` operations — one per operand — followed
by one `|` to combine them. `cond` is the secret bit; `mask - cond` and
`mask - 1n + cond` are the two masks it selects between, and each one is a
few-thousand-bit-wide all-ones-or-all-zeros(-ish) value in either the top or
bottom half of a `maxBitLength`-wide range.

QuickJS's `libbf` lowers BigInt `&` to `bf_logic_and`, and `|` to
`bf_logic_or`. So each `SELECT` call is `and`, `and`, `or` — but this document
only looks at the `and`s.

QuickJS has neither WebCrypto nor Node crypto, so OpenPGP.js's `sign()` falls
through past `webSign` and `nodeSign` to the pure-JS `bnSign`, which does a
single `m.modExp(d, n)` — **no CRT**. The exponent is the full `d` (4,094 bits
for the key in `victim/`) and the modulus is the full 4096-bit `n`, so
`maxBitLength` is **4096** and the loop runs 4,094 iterations. (The CRT code
in `openpgp_select_patched.js` is the *decryption* path and is never reached
when signing. The traces confirm this directly: decoded bits match `d` at
99.2% and match `dp`, `dq`, or either concatenation at chance.)

4,094 iterations means 4,094 `SELECT` calls, i.e. **8,188 `bf_logic_and` calls
from `SELECT` alone**, plus one more `and` per iteration for the loop's own
`exp & 1n` test that produces `cond`. 4,094 + 8,188 = **12,282 `bf_logic_and`
calls per signature** — the number this whole document is trying to extract
bits from.

## 2. Why `bf_logic_and`'s cache line looks like a clean target

`libbf`'s three bitwise ops are tiny 5-instruction thunks that tail-jump into
a shared `bf_logic_op`:

```
00000000000b1210 <bf_rint>       (unrelated function, not a thunk)
00000000000b1220 <bf_logic_or>
00000000000b1230 <bf_logic_xor>
00000000000b1240 <bf_logic_and>
   b1240: endbr64
   b1244: mov $0x2,%ecx
   b1249: jmp b0c60 <bf_logic_op>
00000000000b1250 <bf_get_float64>  (unrelated, never called during modExp)
```

Cache lines are 64 bytes (`CACHE_LINE_MASK = ~0x3f`), and `0xb1240` is itself
64-byte aligned, so `bf_logic_and`'s line runs `0xb1240`–`0xb127f` and holds
*only* `bf_logic_and` plus the unused tail of `bf_get_float64`. That's the
whole appeal over the default target: the `or` line (`0xb1220`–`0xb125f`)
also holds `bf_rint`, which is called from unrelated code (`%` and shift
opcodes) and has to be reasoned about and subtracted out. The `and` line has
no such co-tenant — every record in a `PROBE_LINE=and` trace is a real
`bf_logic_and` call, full stop.

The attacker resolves the target by symbol rather than hard-coded offset
(`get_select_targets()` in `quickjs_select_rsa_ps.c`, using `libbf.h`), so
switching between lines is just `PROBE_LINE=and` vs `PROBE_LINE=or`:

```bash
PROBE_LINE=and ./run_select_rsa_ps.sh
```

## 3. What a trace looks like

One iteration of the modExp loop touches the `and` line exactly three times,
in a fixed order:

```
A1   bf_logic_and    exp & 1n            (computing cond for this iteration)
                       <- exp >>= 1n, r * x % n (bf_rint calls, not on this line) ->
A2   bf_logic_and    SELECT's first &     (a & (mask - cond))
A3   bf_logic_and    SELECT's second &    (b & (mask - 1n + cond))
                       <- x * x % n (bf_rint, not on this line) ->
A1'  bf_logic_and    exp & 1n, next iteration
```

A2 and A3 are close together (nothing but a `|` and the mask arithmetic sit
between them). A1 and A2 are far apart (a shift and a full modular
multiplication sit between them), and so are A3 and A1' (a `|` and another
full modular multiplication). So a raw trace, split on long gaps, alternates
**singleton, pair, singleton, pair, …** — one hit alone, then two hits close
together, repeating every iteration.

Measured on a real trace (`data/traces_and_line/r0.out`, `PROBE_LINE=and`,
one signature): 11,632 records recovered in the signing window against 12,282
expected — matching the layout in §2, with a few hundred detections lost to
probe noise and no unexplained excess. Grouping on a 100,000-cycle split gives
3,171 clean pairs and 4,922 clean singletons out of 4,094 iterations (a
fraction of iterations lose or gain a detection — same failure mode as the `or`
line, see `EXPLANATION.md` §7; a dropped pair member turns one pair into two
singletons, which is why singletons run over 4,094). Locking the loop period
from the pair timestamps gives 611,438 cycles, matching the period measured on
the `or` line to five figures — same physical loop, seen from a different cache
line.

## 4. Where the bit should be — and why it isn't measurable there

The natural place to look for the leak is the A2→A3 gap: it's the interval
*inside* `SELECT`, between its two `&` calls, closest to the mask arithmetic
that depends on `cond`. It comes back flat:

```
                        median 0 / median 1     delta      accuracy
A2->A3  inside SELECT   11,882 /  11,822         -60        0.526   (chance)
```

0.518–0.541 across ten independently-collected traces, with the sign of the
delta flipping run to run — this isn't a one-off unlucky sample, there is no
signal on this interval at all.

The reason is Prime+Scope's resolution, and the trace shows it directly. The
smallest gap between two consecutive detections in *any* trace collected for
this artifact — either cache line, any run — is 10,916 cycles. That floor is
Prime+Scope's own re-arm time: after a detection the probe thread has to
re-prime its eviction set before it is capable of detecting anything else. The
A2→A3 medians (~11,800) sit right on top of that floor, which is the tell:
`SELECT`'s two `&` calls are genuinely closer together than the probe can
resolve, so what lands in the trace on that interval is the probe's recovery
time, not the victim's work — and recovery time doesn't depend on `cond`.

Prime+Scope therefore cannot measure that interval. Two other instruments can,
and they show it is where most of the leak lives.

### 4.1 What is actually in the A2→A3 gap

`SELECT`'s expression evaluates left to right, so the gap between the two `&`
calls is not empty — it holds the *second* mask's arithmetic:

```
sub   mask - cond
&     -> A2
sub   mask - _1n      \
add   + cond          / between A2 and A3
&     -> A3
|     -> or
```

Per-bytecode-handler timing on an instrumented QuickJS
(`openpgp_patch/run_opcode_timing.sh`, 10 runs at the victim's real
`maxBitLength` of 4096) attributes the bit dependence almost entirely to that
`add`:

| handler | median cycles, `cond=1` minus `cond=0` |
|---|---|
| `add` (`mask - _1n + cond`) | **+1,431** (+1,422 … +1,440) |
| `sub` (`mask - cond`, `mask - _1n`) | +108 |
| `and` (both `&`) | +20 |
| `or` | −40 |
| **total** | **+1,523** |

Intel PT (`openpgp_patch/run_intel_pt.sh`) localizes the `add` to one branch,
`bf_add_internal+0x26a`, which `addr2line` maps to `libbf.c:908`:

```c
} else if (a->len == 0 || b->len == 0) {
    bf_set(r, a);      /* libbf.c:923 — copy, then done */
    goto renorm;
}                      /* else: bf_resize + 64-limb add loop */
```

`cond = 0n` is a BigInt of length 0, so the add takes the zero-operand
shortcut and finishes with a copy. `cond = 1n` has length 1, so it runs the
full path — and since the left operand is `2^4096 - 1`, the carry propagates
out of all 64 limbs and triggers a *second* `bf_resize` at `libbf.c:1017`. The
divergence is nine true-only and eight false-only instructions, all inside
`bf_add_internal`, byte-identical across captures at 2048, 4095 and 4096 bits
(`openpgp_patch/pt_results_4096/instruction_set_diff.txt`).

So the "branchless" patch is not branchless: `+ cond` turns the secret bit
into a zero-length test on a BigInt operand, and that test is a real branch in
`libbf`. The `&` and `|` operations the patch is built around contribute ~0.

Two caveats. The instrumented total (+1,523) is smaller than the ~+2,200 the
Prime+Scope traces show across a full iteration (§5), and that ~700-cycle
residual is unexplained — PT reports which instructions execute, not their
cost. What it does bound is where the residual *cannot* be: the two paths are
identical outside `bf_add_internal`, `bf_normalize_and_round`, `bf_resize` and
`bf_add_limb`, so it is not elsewhere in `SELECT`. The likely source is the
difference between the harness (fixed operands, alternating `cond`) and a real
`modExp` (random bits, output feeding the next multiply); that is not measured
here. Separately, an earlier version of this document quoted cycle counts from
an LD_PRELOAD interposer whose per-call overhead exceeded the effect it was
measuring; those numbers were withdrawn and underpin nothing above.

## 5. Where the bit shows up instead

The bit doesn't disappear from the trace — it's still ~2,000–2,400 cycles of
real timing difference, it just isn't isolated on its own gap. Any interval
that *contains* the A2→A3 gap inherits the delta, because that is where the
work is (§4.1); widening the window only adds jitter, not signal. The two
usable intervals both do that by also spanning a full modular multiplication:

```
                        median 0 / median 1     delta      accuracy
A2->A1' SELECT+square  307,598 / 308,916      +1,318        0.763
A1->A1' whole iteration 609,939 / 612,016     +2,077        0.787
```

(from `data/traces_and_line/r0.out`; across all ten traces A2→A1′ runs
0.756–0.809 and A1→A1′ runs 0.784–0.827.)

**Unlike the `or` line, repetition helps here.** A single trace tops out around
0.80 because ~2,100 cycles of signal sit under ~1,700 cycles of IQR, but those
errors are not shared across traces the way the `or` line's are — so a plain
per-bit majority vote over the ten traces recovers most of what a single trace
loses:

```
10-trace majority vote on A1->A1':  acc=0.964  coverage=1.000
                                    (best single trace 0.827)
```

This is the one place the `and` line behaves *better* than the `or` line, where
voting is flat-to-harmful (`verify.py` checks that a 5-trace vote does not beat
the best single trace — 0.9922 vs 0.9925). The plausible reading is that the
`or` line's residual errors are dominated by anchor/period mistakes that whole
traces share, while the `and` line's are dominated by per-iteration timing
jitter, which averages out; that explanation is inferred from the two voting
behaviours, not independently confirmed. Note also that anchors here are
resolved per trace against ground truth, so 0.964 is an upper bound, not an
attacker-achievable number.

Even so, a single trace is a much
weaker signal than the default attack gets. On the `or` line, the pair that
brackets `SELECT` end-to-end (`bf_rint(r*x%n)` → `or`) separates at
**96.7–99.2%** accuracy, because that pair's own gap already spans the
relevant multiplication *and* stays a comparatively tight ~29k–31k cycles
(IQR ~500), instead of ~300k–610k cycles (IQR ~1,100–1,650). Same underlying
~2,200-cycle signal, but riding on roughly three times more jitter because the
window it has to sit inside is roughly ten times longer.

## 6. Summary

Ten traces, one signature each, key 0:

| interval | what it spans | median delta | accuracy |
|---|---|---|---|
| A2→A3 | inside `SELECT`, between its two `&`s | −74 to +58 | 0.52 (chance)¹ |
| A2→A1′ | `SELECT`'s 2nd `&` through the next square | +1,214 to +1,532 | 0.76–0.81 |
| A1→A1′ | one full loop iteration | +2,016 to +2,378 | 0.78–0.83 |
| A1→A1′, 10-trace vote | as above, majority-voted per bit | — | 0.96 |
| *(for reference)* `or`-line wide pair, single trace | `SELECT` end-to-end | +2,146 to +2,334 | 0.97–0.99 |

¹ Chance *as seen by the probe*. The true bit-dependent cost in this interval
is ~+1,523 cycles — it is the largest single contribution in the iteration —
but it sits below the re-arm floor, so the trace records recovery time
instead. See §4.1.

Watching `bf_logic_and` is the more legible target on paper — one primitive,
one clean cache line, no co-tenant to explain away, and the trace literally
alternates one-hit/two-hit per iteration. But the interval that carries the
bit sits below Prime+Scope's re-arm floor (~10,900 cycles) and reads as
pure recovery time, so the bit can only be recovered by widening the
measurement window to include a full modular multiplication — which costs
roughly three times the jitter. That drops a single trace to ~0.80, and it
takes ten traces of voting to climb back to ~0.96, still short of what the
`or` line gets from one. The `or` line's `bf_rint` co-tenancy, confusing as it
is to explain, is what gives that attack its tight bracket around `SELECT`.

## 7. Reproducing this

```bash
PROBE_LINE=and VICTIM_RUNS=10 ./attack/run_select_rsa_ps.sh   # collect traces
cp "$BUILD"/output/quickjs_select_rsa_ps/*_key00000_r00010/*.out \
   data/traces_and_line/
cd analysis && python3 and_line.py             # prints the tables in §4-6
```

For §4.1 (run from `../../openpgp_patch`, needs Intel PT and a `perf` matching
the notes in `INTEL_PT_LOCALIZATION.md`):

```bash
RUNS=10 PIN_CPU=10 OUTPUT_PREFIX="$PWD/opcode_timing_4096" \
  ./run_opcode_timing.sh 10000 4096            # the handler table

PERF_BIN=/usr/lib/linux-tools/5.15.0-186-generic/perf PIN_CPU=5 \
  RESULTS_DIR="$PWD/pt_results_4096" ./run_intel_pt.sh 4096 1
cat pt_results_4096/instruction_set_diff.txt   # the bf_add_internal divergence
```

Both default to 4095 bits; pass 4096 to match the victim. Run them one at a
time — a concurrent PT capture perturbs the cycle measurements.

`and_line.py` groups the `PROBE_LINE=and` trace into (A1, A2, A3, A1′)
quadruples per iteration, locks the loop period, scans for the anchor that
best separates each candidate interval against the known key's exponent
bits, and reports median-threshold accuracy — the same methodology
`decoder.py` uses for the `or` line, applied to the `and` line's three
candidate intervals instead of one.
