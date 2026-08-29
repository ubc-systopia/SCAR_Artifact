# Case Study 6: V8 — constant-time-js

Reproduces the results in **paper §5.4** (V8 — constant-time-js).

V8 version: `v13.9-lkgr`

## Description

Constant-time-js's branchless selectors still leak the secret condition bit,
because V8's bytecode handlers dispatch on a value's runtime representation
rather than its value. The target is Elliptic's Curve25519 ladder with its
secret-dependent branch replaced by two `select_ints` merges.

Two cache lines are monitored with Prime+Probe: one in the `BitwiseAnd` handler
that is touched only when the secret bit is 0, and one in the `Negate` handler
that is touched once per selector call and so marks off ladder iterations.

## Evaluation

```bash
experiments/v8_constant_time_js/e2e.sh
```

To print the per-key statistics:

```bash
python experiments/v8_constant_time_js/evaluation/extract_v8_ctjs_ecdh.py \
    --all_keys build/experiments/v8_constant_time_js/output
```

## Instruction trace of the handlers

```bash
experiments/v8_constant_time_js/trace/trace_ct_select.sh
```
