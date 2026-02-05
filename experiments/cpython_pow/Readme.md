# Case Study 4: CPython — `pow`

CPython version: `v3.13.1`

Python-RSA version: `v4.9.1`

## Description

Case Study 4: CPython — `pow` evaluates the exploitability of Python's modular exponentiation function `pow`.

CPython's internal implementation [`long_pow`](https://github.com/anonymous-sc-language-runtimes/cpython/blob/anonymous-sc-language-runtimes/Objects/longobject.c#L4915) of its modular exponentiation function  `pow` contains secret-dependent control flow that can be used to reconstruct the exponent used in computations. [Python-RSA](https://github.com/sybrenstuvel/python-rsa) is a commonly-used library for RSA encryption and decryption, which internally uses CPython's `pow` function and therefore leaks information about private RSA keys.

## Evaluation

To run the evaluation execute the following command:

```bash
cd experiments/cpython_pow/evaluation
python3 e2e.py
```
