#!/usr/bin/env python3
"""Rewrite the private exponent d of an RSA key.

Reads a PKCS#1 PEM (from `openssl genrsa` or `openssl rsa -traditional`),
replaces d with the integer described by --pattern, and writes a new PEM.
CRT params are left as-is and will no longer match d; cpython's pow(c, d, n)
ignores them.

--pattern uses regex-style `+` meaning "repeat the preceding atom to fill":
  1+         -> 1111...1                    (all ones)
  10+        -> 1 followed by all zeros     (= 2**(bits-1))
  (10000)+   -> 10000 10000 10000 ...       (5-bit group tiled MSB-first)

The atom before `+` is either a single bit or a parenthesized binary group.
Any binary chars before that atom are taken literally as the MSB prefix.
A pattern with no `+` is taken literally and zero-padded.
"""
import argparse
import re
import rsa


_RE = re.compile(r"^([01]*)(?:\(([01]+)\)|([01]))\+$")


def expand(pattern: str, bits: int) -> str:
    m = _RE.match(pattern)
    if m:
        prefix = m.group(1)
        atom = m.group(2) or m.group(3)
        if len(prefix) >= bits:
            return prefix[:bits]
        need = bits - len(prefix)
        reps = (need + len(atom) - 1) // len(atom)
        return prefix + (atom * reps)[:need]
    if set(pattern) <= {"0", "1"} and pattern:
        return (pattern + "0" * bits)[:bits]
    raise ValueError(f"unrecognized pattern: {pattern!r}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True,
                    help="base PEM (PKCS#1, e.g. from openssl genrsa)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--pattern", required=True,
                    help="e.g. '1+', '10+', '(10000)+'")
    ap.add_argument("--bits", type=int, default=4096)
    args = ap.parse_args()

    with open(args.inp, "rb") as f:
        priv = rsa.PrivateKey.load_pkcs1(f.read())

    bitstr = expand(args.pattern, args.bits)
    priv.d = int(bitstr, 2)

    with open(args.out, "wb") as f:
        f.write(priv.save_pkcs1(format="PEM"))
    print(f"wrote {args.out}: pattern={args.pattern!r} -> {args.bits} bits")


if __name__ == "__main__":
    main()
