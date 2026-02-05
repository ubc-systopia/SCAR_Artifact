# Case Study 5: V8 — Elliptic

V8 version: `v13.9-lkgr`

Elliptic version: `v6.6.1`

## Description

Case Study 5: V8 — Elliptic evaluates the exploitability of Elliptic ECDH under JIT-compilation.

V8 JIT-compiled code of Elliptic's ECDH implementation contains secret-dependent control-flow which can be used to recover secret scalars.

## Evaluation

To run the evaluation execute the following command:

```bash
cd SCAR_Artifact/build
./experiments/v8_ecdh/v8_ecdh_key_pool ../experiments/v8_ecdh/js/elliptic_ecdh_eval.js ../experiments/v8_ecdh/js/elliptic_ecdh_repeat.js ../experiments/v8_ecdh/js/elliptic_ecdh_set_keypair_template.js --trace-opt --single-threaded
```

```bash
cd SCAR_Artifact
python experiments/v8_ecdh/evaluation/extract_ecdh.py --all_keys ./build/output
```
