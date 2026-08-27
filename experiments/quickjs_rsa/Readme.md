# Case Study 1: QuickJS — OpenPGP.js

Reproduces the results in **paper §4.2** (QuickJS — OpenPGP.js), including the
disclosure and patch analysis in §4.2's final subsection (see
[`openpgp_patch/`](./openpgp_patch/Readme.md) and
[`openpgp_patch_rsa/`](./openpgp_patch_rsa/Readme.md)).

QuickJS version: `3b45d15`

OpenPGP.js version: `v5.11.2`

## Description

Case Study 1: QuickJS — OpenPGP.js evaluates the exploitability of OpenPGP.js's implementation of RSA encryption and decryption.

While OpenPGP.js's implementation of RSA encryption and decryption is timing-balanced, the selection used in the modular exponentiation algorithm is not constant-time, and results in the execution of different bytecode instructions. An adversary can exploit the execution of instructions to reconstruct secret keys.

## Evaluation

To run the evaluation execute the following command:

```bash
cd SCAR_Artifact/build
taskset -c 1,3,5,7,9,11,13,15 ././src/runtime/quickjs/quickjs_rt ../experiments/quickjs_rsa/js/openpgp_rsa.js
```

```bash
cd SCAR_Artifact/build
taskset -c 1,3,5,7,9,11,13,15 ./experiments/quickjs_rsa/quickjs_rsa_key_pool
```

```bash
cd SCAR_Artifact
python experiments/quickjs_rsa/evaluation/extract_openpgp_rsa.py -p build/output/quickjs_rsa_key_pool --at PS
```

### Flush+Reload (single key)

`quickjs_rsa_fr` is a Flush+Reload attacker against the same `goto8`/`sar`
bytecode-handler cache lines, exploiting the fact that `libquickjs.so` is a
shared library mapped by both the victim and the attacker. Unlike the Prime+Scope
binaries above it only attacks the default key (`KEY_ID=0`) and needs no
eviction-set calibration:

```bash
cd SCAR_Artifact/build
taskset -c 1,3,5,7,9,11,13,15 ./src/runtime/quickjs/quickjs_rt ../experiments/quickjs_rsa/js/openpgp_rsa.js
```

```bash
cd SCAR_Artifact/build
taskset -c 1,3,5,7,9,11,13,15 ./experiments/quickjs_rsa/quickjs_rsa_fr
```

```bash
cd SCAR_Artifact
python experiments/quickjs_rsa/evaluation/extract_openpgp_rsa.py -f build/output/quickjs_openpgp_rsa_fr_r00001/r0.out --at FR
```

### Key Pool Generation

```bash
python3 gen_key_pool.py
```
