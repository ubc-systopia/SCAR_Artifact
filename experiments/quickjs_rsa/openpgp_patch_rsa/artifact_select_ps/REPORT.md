## 5.2 QuickJS – OpenPGP.js RSA under the proposed constant-time patch

OpenPGP.js's proposed branchless replacement for the ternary in `modExp`
(`SELECT`, using masked BigInt selection instead of `r = lsb ? rx : r`)
removes the bytecode-level branch, but the runtime's big-integer library
(`libbf`) still does secret-dependent work inside `SELECT`: the interval
spanning `SELECT` is reliably ~2,300 cycles longer for a 1 bit than a 0. The
mechanism is **not** the masking operations the patch is built around. It is
the `+ cond` that constructs the second mask. Per-handler timing on an
instrumented QuickJS (10 runs, `maxBitLength=4096`) attributes +1,422 cycles to
`add` against +16 for the two `&` and −36 for the `|`; Intel PT localizes the
divergence to one branch, `bf_add_internal+0x26a` (`libbf.c:908`), where
`cond = 0n` — a BigInt of length zero — takes a zero-operand shortcut while
`cond = 1n` runs a full 64-limb add whose carry out of the top forces a second
`bf_resize`. So the patch is branchless only above the runtime: `+ cond` turns
the secret into a zero-length test on a BigInt, and that test is a real branch
in `libbf`. Two earlier claims are withdrawn: it is *not* `bf_logic_and`'s trip
count (`bf_logic_op` takes `l = bf_min(a->expn, b->expn)` on the AND path
specifically to avoid that), nor the size of the value each `&` produces
(measured at +16 cycles). What remains unexplained is a ~700-cycle residual
between the instrumented total (≈ +1,450) and the ≈ +2,200 seen in the traces.
A
Prime+Scope attacker who monitors the `bf_logic_or` cache line can recover
the exponent bit-by-bit from the interval between paired accesses within one
loop iteration. See `artifact_select_ps/EXPLANATION.md` for the full
mechanism, calibration, and worked walkthrough with figures; this file is a
short status note on the pool-scale evaluation.

### Setup

100 random RSA-4096 keys (`rsa_key_pool/`), 128 Prime+Scope traces per key
(one signature each), **all 100 keys evaluated**.

Two keys needed a second collection pass. The first pass over the pool lost
key 88 entirely — the attacker failed to build its eviction set and the
driver moved on rather than hanging the run — and returned key 85 with all
128 traces degenerate (near-empty; see Data quality). Both were re-collected
individually afterwards and came back normal on the first retry (key 85: 0
of 128 degenerate, best single trace 0.9601; key 88: 3 of 128 degenerate,
0.9358). Both failure modes are transient and per-run, not properties of
those keys.

Per trace, the decoder (`artifact_select_ps/analysis/decoder.py`) takes the
loop period to be the median spacing between consecutive paired accesses and
assigns each pair an exponent-bit index from `t = index × P + t₀`. The
decoder is deliberately the simplest thing that works: four steps, each one
line of arithmetic, at a cost in accuracy that is quantified below and in
`artifact_select_ps/EXPLANATION.md`.

One integer — which loop iteration the first pair belongs to (the "anchor") —
is not fixed by the trace itself. It is resolved here against the known
exponent (`best_anchor`, a ±2 search), standing in for the check a real
attacker performs anyway: trying the handful of candidate keys against a
known signature. That is an oracle, so every number below is an upper bound
in that one specific respect.

Per-bit voting bins predictions into 0/1/unknown using the band [0.90, 0.95]
(REPORT §5.1's threshold), each band-thresholded across bits of that key.

### Results

**Best single trace per key is excellent and consistent.** Across all 100
keys, best-single-trace accuracy has median 98.32%, at or above 95% for 94
of 100 keys and above 90% for 99. The one exception is key 40 at 59.5% (see
Limitations).

That is the number to read, and it barely moved when the decoder was
simplified. A single trace is fragile here: the median-spacing period
estimate holds phase over part of a trace and slips somewhere in the middle
of the rest, so individual traces land anywhere from 0.5 to 0.99 (the
five-trace single-key study in §5.2.5 sees 0.76–0.92). At 128 traces per
key, some trace always holds phase throughout, and best-of-N recovers almost
all of what a much more elaborate period estimator would buy per trace —
median 98.3% against 99.8% for the phase-locking decoder this replaced. The
simplification costs about 1.5 points at pool scale and roughly 20 on a
single trace.

**Voting never beats the best single trace — 0/100 keys.** Naive per-bit
majority vote across all ~125–128 runs of a key gives median known-bit
accuracy of only 58.8% (range 49.2%–74.4%), against 98.3% from just keeping
the best trace. This is not new — the earlier 5-trace result already found
repetition doesn't help because errors are shared, not independent — but at
pool scale the effect is worse than "doesn't help": it actively destroys the
signal. The mechanism is that individual traces are not uniformly noisy, and
each one is wrong over a *different* stretch of the exponent; unweighted
voting lets the traces that are at chance over a given range outvote the one
that is tracking it. So the practical strategy is **best-of-N with external
verification**, not repetition: decode each trace independently, keep the one
that verifies against a known signature. That check also resolves the
anchor's one unknown integer for free.

| | min | median | max |
|---|---|---|---|
| best single trace, accuracy | 0.595 (key 40) | 0.9832 | 0.9970 |
| voted, known-bit accuracy | 0.4921 | 0.5883 | 0.7443 |
| voted, coverage | 0.2746 | 0.8901 | 0.9885 |

**"Runs required to reach 99% coverage" is a misleading headline in
isolation.** Read the way REPORT §5.1 reads it, this number looks great:
median 2 runs, i.e. two traces are "enough." But that's coverage, not
accuracy — the vote becomes confident fast while still being wrong on a large
share of what it's confident about (median accuracy 58.8%). One outlier is
real signal rather than noise: key 40 needed 111 of 111 available runs and
never reached the 99% target — consistent with it also being the worst
best-single-trace key and the largest single degenerate-trace count (17/128).

### Data quality

211 of 12,800 collected traces (1.6%) were dropped as degenerate (< 100
paired accesses recovered, against a normal ~3900–4000; `MIN_WIDE_PAIRS` in
`evaluate_pool.py`). These arrive in short bursts within a key rather than
uniformly — e.g. key 63 lost 27/128, keys 11 and 15 lost 22–23/128 — pointing
at a transient recording problem rather than steady-state noise. 52% of keys
had at least one dropped trace (median 2/128 among those). The extreme case
was key 85's first collection pass, which lost all 128; re-collecting it lost
none, which is the clearest evidence available that this is a property of the
run and not of the key.

### Limitations

- One key (40) is a genuine outlier — worst best-single-trace accuracy by a
  wide margin (0.595 against a 0.9832 median), one of the highest
  degenerate-trace counts (17/128), and the only key whose voted coverage
  never converged. Not averaged away above; flagged as-is. Unlike keys 85 and
  88 it was not re-collected, so it is not known whether a second pass would
  behave the same way.
- The bursty degenerate-trace pattern is unexplained — plausibly transient
  system noise during collection, not investigated further here. That it
  cleared completely on key 85's retry supports the "transient" reading but
  does not identify a cause.
- The per-trace anchor is resolved against ground truth (a ±2 search); a real
  attacker would resolve the same handful of candidates via signature
  verification, not run here.
- The decoder is deliberately simpler than the attack allows. Estimating the
  loop period as a median spacing, rather than locking it to ~10⁻⁸ relative,
  costs ~1.4 points of best-of-N accuracy at pool scale and ~20 on a single
  trace. The numbers here are a lower bound on what the channel yields,
  traded for a decoder that can be read end to end in a few minutes.
- The ~4.1 recorded accesses per `SELECT` call are now accounted for, but not
  the way the earlier text assumed: `bf_rint` shares the probed cache line with
  `bf_logic_or`, and one signature makes 4,094 `bf_logic_or` calls against
  13,305 `bf_rint` calls (sum 17,399, versus 17,074 records in `r0`). They are
  not `SELECT`'s three `bf_logic_op` calls — `SELECT`'s two `&` go to
  `bf_logic_and`, which is on a different line and a different LLC set.
  The pair structure is now attributed: the loop body is invariantly
  `and(exp&1n) rint(shift) rint(r*x%n) and and or rint(x*x%n)`, of which the
  three `bf_rint` and the `bf_logic_or` fall on the watched line. The wide pair
  is `rint(r*x%n)`->`or`, i.e. `SELECT` itself (29,608 cycles for a 0 vs 32,164
  for a 1, 99.3% separable by one threshold, measured against the victim's own
  record of `lsb`); the narrow pair is `rint(x*x%n)`->next `rint(shift)`, the
  exponent shift, which does not leak (25,282 vs 25,374, 58%). Prime+Scope cannot
  localize the dependence *within* the wide pair — the interval between `SELECT`'s
  two `&` calls is below the probe's ~10,900-cycle re-arm floor (see
  `EXPLANATION_AND.md` §4), and the LD_PRELOAD instrumentation that previously
  supplied a figure there adds per-call overhead comparable to the interval, so its
  absolute numbers are not relied on. The localization above comes instead from
  per-handler timing and Intel PT on an instrumented build. The lattice step
  that would turn a best-single-trace ~99.8%-accurate partial exponent into
  the exact key is cited (via known partial-key-exposure bounds), not run.
