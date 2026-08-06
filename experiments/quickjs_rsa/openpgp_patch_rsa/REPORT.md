## 5.2 QuickJS – OpenPGP.js RSA under the proposed constant-time patch

The leakage in §5.1 arises from a bytecode-level conditional branch. In response,
the OpenPGP.js maintainers proposed a branchless replacement for the ternary. We
show that this mitigation eliminates attack vector I2 but relocates the leakage to
vector I4 — an operand-dependent loop inside the handler implementation — and that
the resulting channel is still sufficient for key recovery, with a single trace
yielding the least-significant half of `d` at 99.2% accuracy.

### 5.2.1 The proposed mitigation

The patch replaces `r = lsb ? rx : r` with a masked select over BigInts:

```js
function SELECT(cond, a, b, maxBitLength) {
  const mask = 1n << maxBitLength;
  return (a & (mask - cond)) | (b & (mask - 1n + cond));
}
// r = SELECT(lsb, rx, r, bits);   bits = bitlength(n) = 4096
```

For `cond = 1` the operand pair is `(a & 2^k−1, b & 2^k) = (a, 0)`; for `cond = 0`
it is `(0, b)`. Two `&`, one `|`, two subtractions and one shift execute in the
same order for either value of `cond`, and no branch depends on the secret. Under a
source-level model of constant time the construction is correct.

Note that OpenPGP.js signing does not use CRT: `sign()` reaches `m.modExp(d, n)`
with the full 4096-bit `d`, so one signature exercises all 4094 exponent bits in a
single loop.

### 5.2.2 Analysis

The mitigation is effective against the vectors exploited in §5.1. The ternary is
gone, so BB2/BB3 no longer exist: there is no extra `goto8` dispatch and the
bytecode instruction sequence is identical for both key-bit values. I1 and I2 are
therefore unviable. I3 remains unviable for the same reason as before — the
operands are re-allocated per iteration and their addresses are unpredictable.

Vector I4, which was inapplicable in §5.1 because the `get_loc_check` handler
contains no operand-dependent branches, now becomes the leakage source. The
handler reached by SELECT's `|` is `OP_or` in `js_binary_arith_bigint`, which
calls `bf_logic_or` → `bf_logic_op` in QuickJS's arbitrary-precision library. That
function does not operate at fixed width:

```c
if (op == BF_LOGIC_AND && r_sign == 0)
    l = bf_min(a->expn, b->expn);      /* AND: min */
else
    l = bf_max(a->expn, b->expn);      /* OR : max */
l = (bf_max(l, 1) + LIMB_BITS - 1) / LIMB_BITS;
if (bf_resize(r, l)) goto fail;        /* allocation ∝ l */
for (i = 0; i < l; i++) { ... }        /* trip count = l */
bf_normalize_and_round(r, BF_PREC_INF, BF_RNDZ);
```

The trip count, the `bf_resize` allocation and the normalisation scan are all
derived from the operand exponents. By the table above, exactly one operand of the
OR is zero, and *which* one is the secret; symmetrically, one AND yields a
full-width 4096-bit value and the other yields zero, in an order set by `cond`. A
zero operand has `expn ≤ 0`, takes a different path through the sign handling,
contributes nothing to `bf_max`, and normalises at different cost. The mitigation
equalises the control flow of the *program* while leaving the data flow of the
*runtime* untouched.

The consequence for the adversary is that the observable changes character. In
§5.1 the signal was a *rate* — whether an extra `goto8` dispatch occurred in an
iteration. Here the instruction sequence is invariant and the signal is a
*duration* — how long one bitwise operation runs, observable as the interval
between two accesses to a single cache line. This distinction determines both the
required primitive (§5.2.3) and the trace segmentation (§5.2.4).

> **Insight.** Removing a bytecode branch does not remove the leak if the operands
> reaching the runtime's arbitrary-precision library remain secret-dependent.
> Constant-time reasoning at the source level of a managed language does not
> transfer to the engine, where a bitwise operator is a call whose cost scales with
> operand magnitude.

### 5.2.3 Attack primitive

We monitor the cache line of `bf_logic_or`, which has exactly one caller in the
engine (the `OP_or` case of `js_binary_arith_bigint`) and, in the patched modExp,
is reachable only from SELECT's own `|`. It is thus exclusive to the target
operation by construction. We monitor `bf_add_internal` concurrently as a control;
it is *not* exclusive, since its callers `__bf_add`/`__bf_sub` are invoked from
within `bf_mul` and `bf_divrem`, i.e. from the unconditional `(r·x) % n` and
`(x·x) % n` work of every iteration.

Flush+Reload is insufficient here, for a reason worth stating because the same
patch *is* FR-breakable in a batched microbenchmark. An FR probe detects only
accesses landing between its flush and its reload, so shortening the wait trades
detection sensitivity for temporal resolution at approximately 1:1. Sweeping the
wait from 2000 to 100 cycles raised the sample rate ~2× (probe period 3710 → 1778
cycles) while reducing observed hits ~3× (11,920 → 3,742). At its 1778-cycle floor
FR yields 1.9–3.0 events per SELECT call — enough to estimate a rate, not enough to
resolve an interval within the call.

Prime+Scope is event-driven rather than sampled and its loop period is a single
timed access. We measure a scope resolution of 154 cycles against FR's 1778-cycle
floor, which raises the observed `bf_logic_or` events to 4.10–4.13 per SELECT
call. The tradeoff is that P+S is set-granular where FR is line-granular, so
spatial exclusivity is weakened; this is acceptable only because the target is
exclusive at the call-graph level. Because both target addresses are known
(computed from the load bias of `libquickjs.so`), we build eviction sets directly
and omit the PSD-based cache set identification of §5.1.3; that procedure applies
unchanged if the addresses are unknown.

### 5.2.4 Trace structure and segmentation

Applying §5.1.3's decoder — segment into one cluster per exponent bit, classify on
event count — fails. Cluster count as a function of the merge threshold has no
stable region at 4094 (5×10³ → 16,809; 5×10⁴ → 8,310; 2×10⁵ → 8,143; 5×10⁵ → 19),
three of five traces admit no threshold producing 4094 clusters at all, and forcing
4094 gives correlations of +0.036 and +0.009 against SE ≈ 1/√4094 ≈ 0.0156.
Averaging ten rounds moved correlation from 0.021 to 0.027 where a noise-limited
signal would gain ≈√10, confirming the decoder measured the wrong quantity rather
than an attenuated one. The plateau at ≈8100 ≈ 2 × 4094 is the clue.

Inspecting consecutive inter-event gaps rather than aggregate counts reveals the
structure. `bf_logic_or` events occur in **pairs** separated by 25–32k cycles, with
≈278k cycles to the next pair; the gap histogram is empty between ≈35k and ≈270k,
so the pair split is data-determined rather than tuned. Consecutive pairs alternate
strictly between two populations, at a measured alternation rate of 0.975–0.982:

| population | intra-pair gap | std |
|---|---|---|
| WIDE | ≈30,050 cycles | ≈1400 |
| NARROW | ≈25,650 cycles | ≈600 |

Two pairs occur per modExp iteration (2 × ≈306k ≈ the ≈612k iteration period,
matching the least-squares period of 612,038–613,417 cycles recovered
independently per trace). The WIDE member carries 2–3× the variance of the NARROW
member, and that variance is the signal; the NARROW member serves as a built-in
control — same function, same call structure, roughly half the spread, no
correlation with the key.

The decoder therefore isolates the dense signing region, splits events into pairs
at 10⁵ cycles, retains pairs with exactly two events, classifies WIDE/NARROW by the
median gap, assigns each WIDE pair an exponent-bit index, and predicts bit = 1 iff
the WIDE gap exceeds the median. Square-and-multiply consumes `d` LSB-first, so
trace order maps to `d` reversed and forward-order scoring is a built-in negative
control.

**Alignment.** Roughly 100 of 4094 iterations yield no clean pair, so the WIDE
series (~3990 entries) cannot be sliced positionally. Indices come from a global
least-squares fit of `t = idx·P + c`. This is the accuracy-limiting step: any
scheme that accumulates index shift fails catastrophically, since one missed
iteration displaces every subsequent bit. Sequential step counting and
alternation counting both collapse to chance (corr ≈0.02); block-anchored
assignment over 640 blocks reaches 0.717; the anchored global fit is best. Its
residual jitter is ≈0.25·P, so points slip progressively and correlation decays
along the trace.

### 5.2.5 Results

RSA-4096, key with a 4094-bit exponent, five independent signing operations.

| trace | WIDE pairs | alternation | corr (LSB-first) | acc (4094 bits) | acc (first 2048) | corr (forward, control) |
|---|---|---|---|---|---|---|
| r0 | 4023 | 0.982 | **+0.4994** | 0.7766 | **0.9920** | −0.0182 (acc 0.4896) |
| r1 | 3988 | 0.979 | +0.4242 | 0.7373 | 0.9670 | −0.0171 (acc 0.4878) |
| r2 | 3987 | 0.975 | +0.0746 | 0.5566 | 0.6024 | −0.0192 (acc 0.4869) |
| r3 | 4008 | 0.977 | **+0.5151** | 0.7751 | **0.9894** | −0.0305 (acc 0.4895) |
| r4 | 4024 | 0.979 | +0.0417 | 0.5238 | 0.5409 | −0.0140 (acc 0.4902) |

Three controls behave as required: forward-order scoring returns 0.487–0.490 in
every trace; the NARROW population does not track the key; and the concurrently
monitored non-exclusive `bf_add_internal` yields correlation ≈0.036.

The whole-trace accuracy understates the channel, because per-bit accuracy is not
uniform along the trace. Correlating within ten contiguous regions:

```
r0:  +0.938 +0.685 +0.864 +0.897 +0.959 +0.478 +0.049 +0.118 +0.003 −0.025
r3:  +0.857 +0.875 +0.936 +0.901 +0.949 +0.461 +0.049 +0.082 −0.006 −0.002
```

Regional correlation reaches +0.94–0.96 until the least-squares index assignment
desynchronises, after which it falls to chance. Accordingly, accuracy over the
first *N* least-significant bits is far higher than over all 4094:

| N | 256 | 1024 | 2048 | 4094 |
|---|---|---|---|---|
| r0 | 0.979 | 0.993 | 0.992 | 0.777 |
| r1 | 0.980 | 0.992 | 0.967 | 0.737 |
| r3 | 0.972 | 0.985 | 0.989 | 0.775 |

A single trace (r0) recovers 1995 of the first 2048 LSBs of `d` with 16 errors.
Since partial key exposure attacks [BDF98] recover RSA keys from the
least-significant quarter of `d` for small `e`, single-trace recovery of half of
`d` at this accuracy is sufficient for full key recovery; we cite the bound rather
than execute the lattice step.

**Multi-round voting does not help.** Unlike §5.1, where repetition suppresses
dispatch-speculation noise, here it is flat-to-negative:

| rounds | 1 | 2 (best) | 3 (strong) | 4 | 5 |
|---|---|---|---|---|---|
| acc (4094 bits) | 0.7766 | 0.7786 | 0.7777 | 0.7596 | 0.7338 |

The reason is that the residual errors are common-mode rather than independent.
Comparing predictions between two traces per region shows agreement of 0.975–1.000
*even in regions where accuracy is 0.50*: all traces share nearly the same fitted
period and therefore mis-index identically. Voting suppresses independent noise and
cannot correct a systematic misalignment. Repetition becomes useful only once a
drop-aware aligner replaces the global fit — the information required is present in
the traces, since a dropped iteration appears as a gap of ≈2·P.

**Limitations.** Results are for a single key over five traces; two of the five
(r2, r4) score near chance, and while r2 shows +0.653 in its first region before
desynchronising, we have no explanation for r4. We have not mapped the ≈4.1
observed events per SELECT call onto its three `bf_logic_op` invocations; the
attack does not depend on that attribution, but resolving it (e.g. by Intel PT
instruction-path localisation) would sharpen the mechanism claim.
