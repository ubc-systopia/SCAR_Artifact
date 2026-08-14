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

100 random RSA-4096 keys (`rsa_key_pool/`), targeting 128 Prime+Scope traces
per key (one signature each). 99 keys collected successfully; one attacker
run failed to build its eviction set for key 88 mid-pool (an occasional,
expected failure mode — the driver detects it, releases the wedged victim,
and moves on rather than hanging the whole run). Of the 99 collected, key 85
came back with every trace degenerate (near-empty; see below), leaving **98
keys evaluated**.

Per trace, the decoder (`artifact_select_ps/analysis/decoder.py`) recovers a
loop period by locking onto it (Fourier-style phase scan) and assigns each
paired access an exponent-bit index from `t = index × P + offset`. One
integer — which loop iteration the first pair belongs to (the "anchor") — is
not fixed by the trace itself and must be resolved separately. Three tiers
are reported:

- **blind** — the anchor is resolved by cross-trace consensus alone
  (`blind_anchors`), no ground truth. This recovers every trace's anchor
  correctly *relative to the others*, but leaves one integer shared by the
  whole key unresolved (cross-trace agreement can't distinguish it — every
  candidate for that shared shift explains the other traces equally well).
- **blind + shift** — the one shared integer is additionally resolved per
  key (`resolve_group_shift`), standing in for what a real attacker would
  do with a cheap external check (e.g. trying the handful of candidate keys
  against a known signature).
- **oracle** — every trace's anchor resolved individually against the known
  key. Upper bound only, not attacker-achievable.

Per-bit voting bins predictions into 0/1/unknown using the band [0.90, 0.95]
(REPORT §5.1's threshold), each band-thresholded across bits of that key.

### Results

**Best single trace per key is excellent and consistent.** Across 98 keys,
best-single-trace accuracy has median 99.77%, ranging 97.7%–99.97% for 97 of
98 keys. The one exception is key 40 at 58.8% (see Limitations).

**Voting never beats the best single trace — 0/98 keys, at any tier.**
Naive per-bit majority vote across all ~125–128 runs of a key gives median
known-bit accuracy of only 62.7% (range 49.6%–98.3%, +shift tier), against
99.8% from just keeping the best trace. This is not new — REPORT's earlier
5-trace result already found repetition doesn't help because errors are
shared, not independent — but at pool scale the effect is worse than
"doesn't help": it actively destroys the signal. The mechanism is that
individual traces are not uniformly noisy; a meaningful fraction (roughly
15–25%, observed directly on a 32-trace sample of two keys) are close to
pure chance, and unweighted voting lets those traces poison bits a single
good trace would get right. No cheap, no-oracle signal (lock-fit magnitude,
cross-trace agreement) reliably separates good traces from bad ones in this
data, so the practical strategy is **best-of-N with external verification**,
not repetition: decode each trace independently, keep the one that verifies
against a known signature. That check also resolves the anchor's one
remaining unknown integer for free.

| | min | median | max |
|---|---|---|---|
| best single trace, accuracy | 0.588 (key 40) | 0.9977 | 0.9997 |
| voted (+shift), known-bit accuracy | 0.4959 | 0.6265 | 0.9832 |
| voted (oracle), known-bit accuracy | 0.4949 | 0.6137 | 0.9197 |
| voted (+shift), coverage | 0.2367 | 0.8588 | 0.9893 |

**"Runs required to reach 99% coverage" is a misleading headline in
isolation.** Read the way REPORT §5.1 reads it, this number looks great:
median 2 runs across every tier, i.e. two traces are "enough." But that's
coverage, not accuracy — the vote becomes confident fast while still being
wrong on a large share of what it's confident about (median accuracy 62.7%
at that same +shift tier). One outlier is real signal rather than noise:
key 40 needed 111 of 111 available runs and never reached the 99% target —
consistent with it also being the worst best-single-trace key and the
largest single degenerate-trace count (17/128).

### Data quality

336 of 12,672 collected traces (2.7%) were dropped as degenerate (< 100
paired accesses recovered, against a normal ~3900–4000; `MIN_WIDE_PAIRS` in
`evaluate_pool.py`). These arrive in short bursts within a key rather than
uniformly — e.g. key 63 lost 27/128, keys 11 and 15 lost 22–23/128 — pointing
at a transient recording problem rather than steady-state noise. 44% of keys
had at least one dropped trace (median 2/128). Key 85 lost all 128 traces
this way and contributes nothing to the results above.

### Limitations

- One key (40) is a genuine outlier across every metric — worst
  best-single-trace accuracy, most degenerate traces, and the only key whose
  voted coverage never converged. Not averaged away above; flagged as-is.
- Key 85's total loss and the bursty degenerate-trace pattern are unexplained
  — plausibly transient system noise during collection, not investigated
  further here.
- The blind anchor tier still needs one per-key oracle bit (the shared
  integer shift) that this evaluation resolves against ground truth; a real
  attacker would resolve it via signature verification, not run here.
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
