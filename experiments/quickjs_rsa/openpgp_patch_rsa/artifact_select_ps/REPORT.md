## 5.2 QuickJS – OpenPGP.js RSA under the proposed constant-time patch

The leak in §5.1 comes from a conditional branch in the bytecode. The OpenPGP.js
maintainers proposed a branchless replacement for the ternary operation. We show
that this removes the branch, and therefore attack vectors I1 and I2, but that the
secret still controls how much work the runtime's big-integer library performs
inside a single bitwise operation. This is attack vector I4. One signature is
enough to recover the low half of the exponent with 16 errors in 1995 recovered
bits.

### 5.2.1 The proposed mitigation

The patch replaces `r = lsb ? rx : r` with a masked selection over BigInts:

```js
function SELECT(cond, a, b, maxBitLength) {
  const mask = 1n << maxBitLength;
  return (a & (mask - cond)) | (b & (mask - 1n + cond));
}
// called as: r = SELECT(lsb, rx, r, 4096n)
```

Here `mask` is 2^4096, `mask - 1n` is the 4096-bit value with every bit set, and
both `a` and `b` are smaller than the modulus `n`, hence smaller than 2^4096. So:

| `cond` | first operand `a & (mask − cond)` | second operand `b & (mask − 1n + cond)` | result |
|---|---|---|---|
| 1 | `a & (2^4096 − 1)` = `a` | `b & 2^4096` = 0 | `a` |
| 0 | `a & 2^4096` = 0 | `b & (2^4096 − 1)` = `b` | `b` |

Two AND operations, one OR, two subtractions and one shift execute in this order
for both values of `cond`, and no branch tests the secret. Judged only by the
JavaScript source, the selection is constant time.

OpenPGP.js signing does not use the Chinese Remainder Theorem: `sign()` calls
`m.modExp(d, n)` with the complete 4096-bit exponent, so one signature runs the
loop over all 4094 exponent bits.

### 5.2.2 Analysis

The mitigation defeats the attacks of §5.1. With the ternary gone, basic blocks
BB2 and BB3 no longer exist, no extra `goto8` dispatch occurs, and the sequence of
bytecode instructions is identical for both values of the key bit. I1 and I2 are
therefore unviable. I3 stays unviable for the reason given in §5.1: the operands
are re-allocated on every loop iteration, so the adversary cannot predict their
addresses.

I4 was inapplicable in §5.1 because the `get_loc_check` handler contains no
operand-dependent branches. That is not true of the handler reached here. SELECT's
`|` dispatches to `OP_or` in `js_binary_arith_bigint`, which calls `bf_logic_or`
and then `bf_logic_op` in QuickJS's big-integer library `libbf`. That function
chooses its work from the operands, not from a fixed width:

```c
if (op == BF_LOGIC_AND && r_sign == 0)
    l = bf_min(a->expn, b->expn);      /* AND: smaller operand */
else
    l = bf_max(a->expn, b->expn);      /* OR:  larger operand  */
l = (bf_max(l, 1) + LIMB_BITS - 1) / LIMB_BITS;   /* LIMB_BITS = 64 */
if (bf_resize(r, l)) goto fail;        /* allocation of l limbs */
for (i = 0; i < l; i++) { ... }        /* loop runs l times */
bf_normalize_and_round(r, BF_PREC_INF, BF_RNDZ);  /* scans for significant limbs */
```

For a non-negative integer, `expn` is the number of significant bits, so `l` is
that bit count divided by 64 and rounded up. Three costs therefore depend on the
operand values: the number of limbs allocated by `bf_resize`, the trip count of
the main loop, and the scan performed by `bf_normalize_and_round`.

Two consequences follow from the table in §5.2.1, and they differ in strength:

1. **The two AND operations run the same number of iterations either way.** For
   the AND case `l` is taken from the *smaller* operand, and the mask is at least
   as large as `a` or `b` in both columns, so `l` equals the bit length of `a` and
   of `b` regardless of `cond`. The trip count is not the leak.
2. **Which AND returns zero does depend on `cond`.** When `cond = 1` the first AND
   returns the full 4096-bit value `a` and the second returns 0; when `cond = 0`
   the order is reversed. A zero result has no significant limbs, so
   `bf_normalize_and_round` does different work in the two cases, and the OR that
   follows receives its `l` from `a` in one case and from `b` in the other.

So the secret bit does not change which instructions execute; it changes the
magnitude of the values those instructions are given, and `libbf` spends time in
proportion to magnitude. The mitigation makes the program's control flow
independent of the secret and leaves the library's work dependent on it.

This changes what the adversary must measure. In §5.1 the observable was a count:
whether an extra `goto8` dispatch occurred in a loop iteration. Here every
iteration executes the same instructions the same number of times, and the
observable is a length of time: how long one bitwise operation takes, seen as the
interval between two accesses to one cache line. That difference decides both the
attack primitive (§5.2.3) and how traces must be divided up (§5.2.4).

We establish points 1 and 2 from the source, and we measure a per-bit correlation
of up to +0.96 for the interval described in §5.2.4. We do not establish which of
the three `bf_logic_op` calls produces each observed cache access; that mapping
remains open and the attack does not depend on it.

> **Insight.** Removing a bytecode branch does not remove the leak if the values
> handed to the runtime's big-integer library still depend on the secret. In a
> managed language a bitwise operator is not an instruction but a call whose cost
> grows with the size of its operands.

### 5.2.3 Attack primitive

We monitor the cache line holding `bf_logic_or`. It has one caller in the engine,
the `OP_or` case of `js_binary_arith_bigint`, and in the patched `modExp` the only
OR between BigInts is SELECT's own, so every access to this line comes from the
operation we are attacking. We monitor `bf_add_internal` at the same time as a
control. It is not exclusive: its callers `__bf_add` and `__bf_sub` are reached
from inside `bf_mul` and `bf_divrem`, that is, from the `(r·x) mod n` and
`(x·x) mod n` computations that every iteration performs whatever the key bit.

Flush+Reload is not sufficient here, which is worth recording because the same
patch is breakable with Flush+Reload in a batched microbenchmark. A Flush+Reload
probe only detects an access that falls between its flush and its reload, so
shortening the wait shortens the window in almost the same proportion as it raises
the sampling rate. Measured over waits from 2000 down to 100 cycles, the probe
period fell from 3710 to 1778 cycles, a factor of 2.1, while detected accesses fell
from 11,920 to 3,742, a factor of 3.2. At its floor of 1778 cycles the probe
records 1.9 to 3.0 accesses per SELECT call. That is enough to estimate how often
the line is touched and not enough to measure an interval inside a single call.

Prime+Scope records a timestamp only when it detects an eviction, and its loop is
one timed access rather than a flush, a wait and a reload. We measure a loop period
of 154 cycles against Flush+Reload's floor of 1778, and this raises the record to
4.10 to 4.13 accesses per SELECT call. The cost is that Prime+Scope observes a
whole cache set rather than one line, so any other address in that set is also
counted; this is acceptable only because the target is exclusive at the level of
the call graph, as argued above. Both target addresses are known, computed from the
load address of `libquickjs.so`, so we build eviction sets for them directly and do
not need the power spectral density search of §5.1.3. That search applies unchanged
if the addresses are unknown.

### 5.2.4 Dividing the trace into loop iterations

The decoder of §5.1.3 divides the trace into one cluster per exponent bit and
classifies on the number of accesses in each cluster. Applied here it fails, and
the way it fails is informative. The number of clusters, as the threshold for
merging neighbouring accesses is raised, never settles at 4094:

| merge threshold (cycles) | 5,000 | 50,000 | 200,000 | 500,000 |
|---|---|---|---|---|
| clusters | 16,809 | 8,310 | 8,143 | 19 |

Three of the five traces have no threshold that yields exactly 4094 clusters, and
forcing that number gives correlations of +0.036 and +0.009 against a standard
error of 1/√4094 = 0.0156. Averaging ten repetitions raised the correlation only
from 0.021 to 0.027, whereas a signal buried in independent noise should improve by
about √10. The decoder was measuring the wrong quantity, not a weakened one. The
flat region near 8100, which is close to 2 × 4094, indicates two groups of accesses
per loop iteration.

Looking at the gaps between successive accesses rather than at cluster counts shows
the structure directly. Accesses to `bf_logic_or` arrive in **pairs**: two accesses
25,000 to 32,000 cycles apart, then about 278,000 cycles before the next pair. No
gap in any trace falls between 35,000 and 270,000 cycles, so the value that
separates pairs is read off the data rather than tuned. Classifying each pair by
its internal gap gives two groups, and consecutive pairs belong to different groups
in 97.5% to 98.2% of cases:

| group | internal gap | standard deviation |
|---|---|---|
| wide | 30,050 cycles | 1,400 |
| narrow | 25,650 cycles | 600 |

Two pairs occur per loop iteration: 2 × 306,000 cycles matches the loop period of
612,000 cycles, which we also recover independently as 612,038 to 613,417 cycles
per trace from the fit described below. The wide group's internal gap varies two to
three times as much as the narrow group's, and that variation is the signal. The
narrow group is a control: the same function, the same call structure, about half
the spread, and no relationship to the key.

The decoder therefore keeps the dense part of the trace where signing occurs,
splits accesses into pairs wherever the gap exceeds 100,000 cycles, keeps pairs
containing exactly two accesses, labels a pair wide if its internal gap exceeds the
median internal gap, gives each wide pair an exponent-bit index, and reports bit 1
when the wide pair's internal gap exceeds the median gap of the wide group. Square
and multiply consumes the exponent from its least significant bit upward, so the
trace runs in the reverse order of the written exponent; scoring in the forward
order is a control that should return chance.

**Assigning bit indices.** About 100 of the 4094 iterations produce no pair with
exactly two accesses, so the wide group holds roughly 3990 entries and cannot be
matched to the 4094 bits by position. We obtain indices by fitting
`t = index × P + c` by least squares over the whole trace, repeated three times,
and discarding indices claimed by more than one pair. This is the step that limits
accuracy. Any method that counts forward from the previous pair fails completely,
because one missed iteration shifts every later bit: counting steps and counting
alternations both fall to correlation 0.02. Anchoring the fit within each of 640
blocks reaches 0.717. The single global fit is the best of the four, and its
remaining error is that individual pairs sit up to a quarter of a loop period away
from the fitted line, so assignments slip progressively along the trace.

### 5.2.5 Results

One RSA-4096 key with a 4094-bit exponent, five separate signing operations.
Accuracy is the fraction of correctly recovered bits among those the decoder
assigned an index to; the count of those bits is given as *n*.

| trace | wide pairs | alternation | correlation | *n* | accuracy | forward-order control |
|---|---|---|---|---|---|---|
| r0 | 4023 | 0.982 | **+0.4994** | 3989 | 0.7766 | −0.0182 (accuracy 0.4896) |
| r1 | 3988 | 0.979 | +0.4242 | 3967 | 0.7373 | −0.0171 (accuracy 0.4878) |
| r2 | 3987 | 0.975 | +0.0746 | 3960 | 0.5566 | −0.0192 (accuracy 0.4869) |
| r3 | 4008 | 0.977 | **+0.5151** | 3967 | 0.7751 | −0.0305 (accuracy 0.4895) |
| r4 | 4024 | 0.979 | +0.0417 | 3988 | 0.5238 | −0.0140 (accuracy 0.4902) |

Correlations of +0.42 to +0.52 are 27 to 33 times the standard error of 0.0156.
Three controls behave as they should: scoring in the forward bit order gives
accuracy 0.487 to 0.490 in every trace; the narrow group does not track the key;
and the non-exclusive `bf_add_internal` line, recorded at the same time, gives
correlation 0.036.

Accuracy over the whole exponent understates the leak, because it is not uniform
along the trace. Correlations computed within ten equal, consecutive parts of a
trace are:

```
r0:  +0.938 +0.685 +0.864 +0.897 +0.959 +0.478 +0.049 +0.118 +0.003 −0.025
r3:  +0.857 +0.875 +0.936 +0.901 +0.949 +0.461 +0.049 +0.082 −0.006 −0.002
```

The correlation is +0.94 to +0.96 until the index assignment loses synchronisation,
after which it is indistinguishable from chance. Accuracy over the lowest *N* bits
of the exponent shows the same picture, with the number of assigned bits in
brackets:

| *N* | 256 | 1024 | 2048 | 4094 |
|---|---|---|---|---|
| r0 | 0.979 | 0.993 | 0.992 (1995) | 0.777 (3989) |
| r1 | 0.980 | 0.992 | 0.967 (1972) | 0.737 (3967) |
| r3 | 0.972 | 0.985 | 0.989 (1985) | 0.775 (3967) |

Trace r0 recovers 1995 of the lowest 2048 exponent bits with 16 errors; trace r3
recovers 1985 with 21 errors. Known partial key exposure results recover an RSA key
from the lowest quarter of the private exponent when the public exponent is small,
so recovering half the exponent at this error rate from one signature is enough for
full key recovery. We cite that bound and do not carry out the lattice computation.

**Repeating the attack does not improve it.** In §5.1 repetition removes noise
caused by speculative dispatch. Here it does not help and eventually hurts:

| traces combined | 1 | 2 (best pair) | 3 | 4 | 5 |
|---|---|---|---|---|---|
| accuracy over 4094 bits | 0.7766 | 0.7786 | 0.7777 | 0.7596 | 0.7338 |

The reason is that the remaining errors are the same errors in every trace, not
independent ones. Comparing the bits reported by two traces part by part, they
agree with each other on 97.5% to 100% of bits *including the parts where each is
only 50% accurate*. Every trace produces nearly the same fitted loop period and so
misassigns indices in nearly the same way. Combining traces removes independent
noise and cannot remove a shared misassignment. Repetition will only help once the
index assignment accounts for missing iterations, and the traces contain what is
needed to do this, because a missing iteration appears as a gap of about twice the
loop period.

**Limitations.** These results cover one key and five traces. Two of the five, r2
and r4, are close to chance overall; r2 reaches +0.653 in the first tenth of its
trace before losing synchronisation, but we have no explanation for r4. We have not
determined which of SELECT's three calls into `bf_logic_op` produces each of the
4.1 accesses we record per call.
