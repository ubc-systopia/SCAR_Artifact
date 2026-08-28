# Case Study 5: V8 — Elliptic

Reproduces the results in **paper §4.4** (V8 — Elliptic).

V8 version: `v13.9-lkgr`

Elliptic version: `v6.6.1`

## Description

Elliptic's ECDH scalar multiplication keeps its secret-dependent branch after V8
JIT-compiles it. The attack monitors two cache sets of the compiled `mul()` with
Prime+Scope: the ladder loop header, which is accessed once per iteration and
acts as a clock, and a line reached only when the secret bit is 1.

## Evaluation

```bash
experiments/v8_ecdh/e2e.sh
```

To prints the per-key statistics:

```bash
python experiments/v8_ecdh/evaluation/extract_ecdh.py --all_keys build/output/v8_ecdh_key_pool
```
