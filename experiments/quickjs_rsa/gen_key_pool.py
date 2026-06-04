#!/usr/bin/env python3

import json
import os
import subprocess
import sys
from argparse import ArgumentParser

import rsa


def hx(value):
    """Render an integer as a lowercase, 0x-prefixed hex string (no padding)."""
    return "0x" + format(value, "x")


def gen_key_json(bits):
    """Generate one RSA key with openssl and return it as an ordered dict."""
    pem = subprocess.run(
        ["openssl", "genrsa", "-traditional", str(bits)],
        check=True,
        capture_output=True,
    ).stdout
    key = rsa.PrivateKey.load_pkcs1(pem)

    # openssl emits prime1 > prime2, so python-rsa's (p, q) already satisfy p > q.
    p, q = key.p, key.q
    u = rsa.common.inverse(q, p)  # q^-1 mod p

    return {
        "n": hx(key.n),
        "e": hx(key.e),
        "d": hx(key.d),
        "p": hx(p),
        "q": hx(q),
        "u": hx(u),
    }


def main():
    parser = ArgumentParser(
        prog="gen_key_pool_json",
        description="Generate an RSA key pool in the quickjs_rsa/rsa_key_pool JSON format",
    )
    parser.add_argument(
        "--count", type=int, default=128, help="Number of keys to generate (default: 128)"
    )
    parser.add_argument(
        "--bits", type=int, default=4096, help="RSA modulus size in bits (default: 4096)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "rsa_key_pool"),
        help="Output directory for the key pool",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing keys instead of skipping them",
    )
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    print(f"Generating {args.count} x {args.bits}-bit RSA keys (JSON) into {args.output}")

    for i in range(args.count):
        path = os.path.join(args.output, f"rsa_key_{i}.json")
        if os.path.exists(path) and not args.force:
            print(f"[{i + 1}/{args.count}] skip existing {path}")
            continue
        print(f"[{i + 1}/{args.count}] generating {path}")
        key = gen_key_json(args.bits)
        with open(path, "w") as f:
            json.dump(key, f, indent=4)

    print("Done")


if __name__ == "__main__":
    sys.exit(main())
