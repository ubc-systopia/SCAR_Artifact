# Case Study 1: QuickJS — OpenPGP.js

QuickJS version: `3b45d15`

OpenPGP.js version: `v5.11.2`

## Description

Case Study 1: QuickJS — OpenPGP.js evaluates the exploitability of OpenPGP.js's implementation of RSA encryption and decryption.

While OpenPGP.js's implementation of RSA encryption and decryption is timing-balanced, the selection used in the modular exponentiation algorithm is not constant-time, and results in the execution of different bytecode instructions. An adversary can exploit the execution of instructions to reconstruct secret keys.

## Evaluation

To run the evaluation execute the following command:

```bash
cd SCAR_Artifact/build
./src/runtime/quickjs/quickjs_rt ../experiments/quickjs_rsa/js/openpgp_rsa.js
```

```bash
cd SCAR_Artifact/build
./experiments/quickjs_rsa/quickjs_rsa_key_pool
```

```bash
cd SCAR_Artifact
python experiments/quickjs_rsa/evaluation/extract_openpgp_rsa.py -p build/output/ --at PS
```
