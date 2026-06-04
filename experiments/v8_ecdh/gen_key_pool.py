#!/usr/bin/env python3
"""Generate a pool of EC private-key pairs in the exact JSON format used by
`experiments/v8_ecdh/ec_key_pool/`.

Each key file (`ec_key_<i>.json`) holds two random curve25519 private scalars
as hex strings (no `0x` prefix), in the order `key1, key2`:

    key1 = party 1 private scalar (the secret recovered by the attack)
    key2 = party 2 private scalar

The values are byte-aligned hex (32 bytes -> 64 hex chars), with leading
zero bytes dropped, matching the existing pool and `elliptic`'s
`ec.keyFromPrivate(<hex>, 'hex')` in `js/elliptic_ecdh_set_keypair_template.js`.

Existing key files are never overwritten unless `--force` is given, so this can
be used to top up an existing pool (e.g. extend 100 -> 128 keys).

Usage:
    python3 gen_key_pool.py                 # ensure 128 keys exist in ./ec_key_pool
    python3 gen_key_pool.py --count 256
    python3 gen_key_pool.py --output /tmp/pool
"""

import json
import os
import secrets
import sys
from argparse import ArgumentParser

# curve25519 private keys are 32 bytes.
KEY_BYTES = 32


def gen_scalar():
    """Random 32-byte scalar as byte-aligned hex with leading zero bytes stripped."""
    raw = secrets.token_bytes(KEY_BYTES)
    # Strip leading zero bytes (keep byte alignment) but never produce an empty string.
    stripped = raw.lstrip(b"\x00") or b"\x00"
    return stripped.hex()


def main():
    parser = ArgumentParser(
        prog="gen_key_pool",
        description="Generate an EC key pool in the v8_ecdh/ec_key_pool JSON format",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=128,
        help="Total number of keys the pool should contain (default: 128)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "ec_key_pool"),
        help="Output directory for the key pool",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing keys instead of skipping them",
    )
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    print(f"Ensuring {args.count} EC keys exist in {args.output}")

    generated = 0
    for i in range(args.count):
        path = os.path.join(args.output, f"ec_key_{i}.json")
        if os.path.exists(path) and not args.force:
            print(f"[{i + 1}/{args.count}] skip existing {path}")
            continue
        print(f"[{i + 1}/{args.count}] generating {path}")
        key = {"key1": gen_scalar(), "key2": gen_scalar()}
        with open(path, "w") as f:
            json.dump(key, f, indent=4)
        generated += 1

    print(f"Done ({generated} new key(s) generated)")


if __name__ == "__main__":
    sys.exit(main())
